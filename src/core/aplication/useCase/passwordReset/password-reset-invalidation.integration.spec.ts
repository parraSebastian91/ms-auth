import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { LoginError } from 'src/core/domain/errors/LoginError.error';
import { makeConfig, makeFakeCache, makeUsuario, PKCE, SECRETS } from 'src/test-support/fixtures';
import { AuthAplicationService } from '../../service/auth.service';
import { AuthorizationUseCase } from '../authorization/authorization.usecase';
import { SessionUseCase } from '../session/session.usecase';
import { PasswordResetUseCase } from './passwordReset.usecase';

/**
 * Reset de contraseña con componentes REALES (servicio de aplicación + 3 casos de uso) y repositorios en
 * memoria: comprueba que tras el reset dejan de servir tanto el access token cacheado como el refresh token.
 */
function buildWorld() {
  const cache = makeFakeCache();
  const jwt = new JwtService({ secret: SECRETS.access });
  const config = makeConfig();

  // --- usuarios ---
  const users = new Map<number, any>();
  const addUser = async (id: number, userName: string, password: string, correo: string) => {
    const u = makeUsuario({ id, uuid: `uuid-${id}`, userName, password: await bcrypt.hash(password, 4), correo });
    users.set(id, u);
    return u;
  };
  const usuarioRepo: any = {
    getUsuarioByUsername: async (name: string) => [...users.values()].find(u => u.userName === name) ?? null,
    getUsuarioById: async (id: number) => users.get(id) ?? null,
    getSystemsByUsername: async () => [{}],
    updatePassword: async (id: number, hash: string) => { users.get(id).password = hash; },
  };
  const contactoRepo: any = {
    findByCorreo: async (correo: string) => {
      const u = [...users.values()].find(x => x.contacto?.correo === correo);
      return u ? { nombres: 'Ana', usuario: { id: u.id.getValue(), activo: true, userName: u.userName } } : null;
    },
  };

  // --- sesiones de refresh en memoria ---
  let seq = 0;
  const rows: any[] = [];
  const refreshRepo: any = {
    create: async (s: any) => { const r = { ...s, id: ++seq, sessionUuid: `su-${seq}`, revokedAt: null }; rows.push(r); return r; },
    findById: async (uuid: string) => rows.find(r => r.sessionUuid === uuid) ?? null,
    revokeById: async (uuid: string) => { const r = rows.find(x => x.sessionUuid === uuid); if (r) r.revokedAt = new Date(); },
    rotate: async (old: any, n: any) => { const o = rows.find(x => x.sessionUuid === old.sessionUuid); if (o) o.revokedAt = new Date(); const r = { ...n, id: ++seq, sessionUuid: `su-${seq}`, revokedAt: null }; rows.push(r); return r; },
    getSessionsByUserId: async (userId: string) => rows.filter(r => String(r.userId) === userId && !r.revokedAt),
    revokeAllUserSessions: async (userId: string) => { const mine = rows.filter(r => String(r.userId) === userId && !r.revokedAt); mine.forEach(r => (r.revokedAt = new Date())); return mine.length; },
    revokeUserSessions: async () => 0,
    hasRotationChild: async (id: number) => rows.some(r => r.rotationParentId === id),
    revokeFamily: async () => 0,
  };

  // --- reset tokens y correo ---
  const resetTokens: any[] = [];
  const resetRepo: any = {
    deleteUserTokens: async (userId: number) => { for (let i = resetTokens.length - 1; i >= 0; i--) if (resetTokens[i].userId === userId) resetTokens.splice(i, 1); },
    createResetToken: async (userId: number, email: string, tokenHash: string) => { const t = { id: resetTokens.length + 1, userId, email, tokenHash, uuid: `tok-${resetTokens.length + 1}`, usedAt: null }; resetTokens.push(t); return { tokenUuid: t.uuid }; },
    findValidToken: async (uuid: string) => resetTokens.find(t => t.uuid === uuid && !t.usedAt) ?? null,
    markTokenAsUsed: async (id: number) => { resetTokens.find(t => t.id === id).usedAt = new Date(); },
  };
  const sentLinks: string[] = [];
  const emailService: any = { sendPasswordResetLink: async (_to: string, url: string) => { sentLinks.push(url); }, sendPasswordChangedNotice: jest.fn().mockResolvedValue(undefined) };

  const authService = new AuthAplicationService(cache as any, refreshRepo, jwt, config);
  const authorization = new AuthorizationUseCase(usuarioRepo, authService, cache as any);
  const sessions = new SessionUseCase(usuarioRepo, refreshRepo, authService, jwt, cache as any, config);
  const reset = new PasswordResetUseCase(usuarioRepo, contactoRepo, resetRepo, authService, emailService, { frontendUrl: 'https://app.test' });

  /** Login completo (authorize + token) con PKCE; devuelve el sessionId y los tokens. */
  const login = async (username: string, password: string, sessionId: string, typeDevice = 'WEB') => {
    const [{ code }] = await authorization.ExecuteAuthorize({ username, password, typeDevice, code_challenge: PKCE.challenge, CorrelationId: 'cid' });
    const tokens = await authorization.ExecuteToken({ code: decodeURIComponent(code), codeVerifier: PKCE.verifier, typeDevice, sessionId, CorrelationId: 'cid' });
    return { sessionId, ...tokens };
  };
  return { addUser, login, sessions, reset, authorization, sentLinks, cache };
}

describe('Restablecer contraseña cierra las sesiones de punta a punta', () => {
  it('tras el reset dejan de servir el access token cacheado y el refresh token; otros usuarios no se ven afectados', async () => {
    const w = buildWorld();
    await w.addUser(1, 'ana', 'Vieja#1234', 'ana@test.cl');
    await w.addUser(2, 'beto', 'Beto#1234', 'beto@test.cl');

    const ana1 = await w.login('ana', 'Vieja#1234', 'sid-ana-web', 'WEB');
    const ana2 = await w.login('ana', 'Vieja#1234', 'sid-ana-mobile', 'MOBILE');
    const beto = await w.login('beto', 'Beto#1234', 'sid-beto');

    // antes del reset: las tres sesiones son válidas
    for (const s of [ana1, ana2, beto]) await expect(w.sessions.ExecuteValidateSession({ sessionId: s.sessionId })).resolves.toBe(true);

    // solicitar y ejecutar el reset con el token que llegó por correo
    await w.reset.ExecuteRequestReset({ correo: 'ana@test.cl', ip: '1.1.1.1', userAgent: 'jest' });
    await w.reset.whenIdle();
    const link = new URL(w.sentLinks[0]);
    await w.reset.ExecuteResetPassword({ token: link.searchParams.get('token')!, uuid: link.searchParams.get('uuid')!, newPassword: 'Nueva#1234', confirmPassword: 'Nueva#1234' });

    // access tokens cacheados de Ana: ya no pasan el guard
    await expect(w.sessions.ExecuteValidateSession({ sessionId: ana1.sessionId })).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(w.sessions.ExecuteValidateSession({ sessionId: ana2.sessionId })).rejects.toBeInstanceOf(UnauthorizedException);
    expect(w.cache.tokens.has('sid-ana-web')).toBe(false);
    expect(w.cache.tokens.has('sid-ana-mobile')).toBe(false);

    // refresh tokens de Ana: revocados en BD
    await expect(w.sessions.ExecuteRefreshSession({ tokens: { 'auth.refresh': ana1.refreshToken }, typeDevice: 'WEB' })).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(w.sessions.ExecuteRefreshSession({ tokens: { 'auth.refresh': ana2.refreshToken }, typeDevice: 'MOBILE' })).rejects.toBeInstanceOf(UnauthorizedException);

    // la sesión de otro usuario sigue intacta
    await expect(w.sessions.ExecuteValidateSession({ sessionId: beto.sessionId })).resolves.toBe(true);
  });

  it('la contraseña vieja deja de funcionar, la nueva sí, y el token de reset es de un solo uso', async () => {
    const w = buildWorld();
    await w.addUser(1, 'ana', 'Vieja#1234', 'ana@test.cl');

    await w.reset.ExecuteRequestReset({ correo: 'ana@test.cl', ip: '1.1.1.1', userAgent: 'jest' });
    await w.reset.whenIdle();
    const link = new URL(w.sentLinks[0]);
    const cmd = { token: link.searchParams.get('token')!, uuid: link.searchParams.get('uuid')!, newPassword: 'Nueva#1234', confirmPassword: 'Nueva#1234' };
    await w.reset.ExecuteResetPassword(cmd);

    await expect(w.login('ana', 'Vieja#1234', 'sid-x')).rejects.toBeInstanceOf(LoginError);
    await expect(w.login('ana', 'Nueva#1234', 'sid-y')).resolves.toMatchObject({ sessionId: 'sid-y' });
    await expect(w.reset.ExecuteResetPassword(cmd)).rejects.toBeInstanceOf(BadRequestException);
  });
});
