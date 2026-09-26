import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { makeConfig, makeFakeCache, makeUsuario, PKCE, SECRETS } from 'src/test-support/fixtures';
import { AuthAplicationService } from '../../service/auth.service';
import { AuthorizationUseCase } from '../authorization/authorization.usecase';
import { SessionUseCase } from './session.usecase';

/**
 * Detección de reutilización de refresh tokens con componentes REALES (servicio de aplicación, autorización y
 * sesión) y repositorios en memoria que respetan el contrato de la BD (ids, rotation_parent_id, revocación).
 */
function buildWorld(graceMs = 30_000) {
  const cache = makeFakeCache();
  const jwt = new JwtService({ secret: SECRETS.access });
  const config = makeConfig({ 'app.refreshReuseGraceMs': graceMs });

  const usuario = makeUsuario({ id: 1, uuid: 'uuid-1', userName: 'ana', password: '$2b$04$hashqueNoImporta' });
  const usuarioRepo: any = {
    getUsuarioByUsername: async () => usuario,
    getUsuarioById: async () => usuario,
    getSystemsByUsername: async () => [{}],
  };

  let seq = 0;
  const rows: any[] = [];
  const refreshRepo: any = {
    create: async (s: any) => { const r = { ...s, id: ++seq, sessionUuid: `su-${seq}`, revokedAt: null, rotationParentId: s.rotationParentId ?? null }; rows.push(r); return r; },
    findById: async (uuid: string) => rows.find(r => r.sessionUuid === uuid) ?? null,
    revokeById: async (uuid: string) => { const r = rows.find(x => x.sessionUuid === uuid); if (r) r.revokedAt = new Date(); },
    rotate: async (old: any, n: any) => {
      const o = rows.find(x => x.sessionUuid === old.sessionUuid); if (o) o.revokedAt = o.revokedAt ?? new Date();
      const r = { ...n, id: ++seq, sessionUuid: `su-${seq}`, revokedAt: null }; rows.push(r); return r;
    },
    hasRotationChild: async (id: number) => rows.some(r => r.rotationParentId === id),
    revokeFamily: async (sessionId: string, userId: number) => {
      const fam = rows.filter(r => r.sessionId === sessionId && r.userId === userId && !r.revokedAt);
      fam.forEach(r => (r.revokedAt = new Date())); return fam.length;
    },
    getSessionsByUserId: async () => [], revokeAllUserSessions: async () => 0, revokeUserSessions: async () => 0,
  };

  const authService = new AuthAplicationService(cache as any, refreshRepo, jwt, config);
  const sessions = new SessionUseCase(usuarioRepo, refreshRepo, authService, jwt, cache as any, config);

  /** Inicia sesión sin pasar por bcrypt: emite el código directamente y lo canjea con PKCE. */
  const authorization = new AuthorizationUseCase(usuarioRepo, authService, cache as any);
  const login = async (sessionId: string) => {
    const code = await authService.createAuthorizationCode(usuario, PKCE.challenge, 'WEB', 'cid');
    return authorization.ExecuteToken({ code, codeVerifier: PKCE.verifier, typeDevice: 'WEB', sessionId, CorrelationId: 'cid' });
  };
  const refresh = (cookie: string) => sessions.ExecuteRefreshSession({ tokens: { 'auth.refresh': cookie }, typeDevice: 'WEB' });
  /** Envejece la revocación de las filas rotadas para simular que pasó el margen de gracia. */
  const ageRotations = (ms: number) => rows.filter(r => r.revokedAt).forEach(r => (r.revokedAt = new Date(Date.now() - ms)));
  return { login, refresh, sessions, rows, cache, ageRotations };
}

const denied = (p: Promise<unknown>) => expect(p).rejects.toBeInstanceOf(UnauthorizedException);

describe('Reutilización de refresh tokens (rotación con detección de robo)', () => {
  it('cada refresh crea una sesión hija enlazada a la anterior (la cadena queda registrada)', async () => {
    const w = buildWorld();
    const t0 = await w.login('sid-a');
    await w.refresh(t0.refreshToken);

    const [first, second] = w.rows;
    expect(first.rotationParentId).toBeNull();
    expect(second.rotationParentId).toBe(first.id);
    expect(first.revokedAt).toBeTruthy();
    expect(second.revokedAt).toBeNull();
  });

  it('usar un token ya rotado, pasado el margen, cierra TODA la cadena: el token más nuevo también deja de servir', async () => {
    const w = buildWorld();
    const t0 = await w.login('sid-a');
    const t1 = await w.refresh(t0.refreshToken);
    const t2 = await w.refresh(t1.refreshToken);
    await expect(w.sessions.ExecuteValidateSession({ sessionId: 'sid-a' })).resolves.toBe(true);

    w.ageRotations(5 * 60_000);
    await denied(w.refresh(t0.refreshToken)); // el atacante reproduce el token original

    // el usuario legítimo, con el token más reciente, también queda fuera (debe volver a iniciar sesión)
    await denied(w.refresh(t2.refreshToken));
    expect(w.rows.every(r => r.revokedAt)).toBe(true);
    // y el access token cacheado ya no pasa el guard
    await denied(w.sessions.ExecuteValidateSession({ sessionId: 'sid-a' }));
    expect(w.cache.tokens.has('sid-a')).toBe(false);
  });

  it('dentro del margen de gracia el token viejo da 401 pero el legítimo sigue funcionando', async () => {
    const w = buildWorld();
    const t0 = await w.login('sid-a');
    const t1 = await w.refresh(t0.refreshToken);

    await denied(w.refresh(t0.refreshToken)); // segunda pestaña con la cookie anterior, al instante
    await expect(w.refresh(t1.refreshToken)).resolves.toBeDefined();
  });

  it('un token cerrado por logout y reintentado no cierra ninguna otra cosa', async () => {
    const w = buildWorld();
    const t0 = await w.login('sid-a');
    w.rows[0].revokedAt = new Date(Date.now() - 5 * 60_000); // revocada por logout: sin hija
    const other = await w.login('sid-b');

    await denied(w.refresh(t0.refreshToken));
    await expect(w.refresh(other.refreshToken)).resolves.toBeDefined();
  });

  it('el robo en una sesión no afecta a las demás sesiones del mismo usuario', async () => {
    const w = buildWorld();
    const a0 = await w.login('sid-a');
    const b0 = await w.login('sid-b');
    await w.refresh(a0.refreshToken);

    w.ageRotations(5 * 60_000);
    await denied(w.refresh(a0.refreshToken));

    await expect(w.sessions.ExecuteValidateSession({ sessionId: 'sid-b' })).resolves.toBe(true);
    await expect(w.refresh(b0.refreshToken)).resolves.toBeDefined();
  });
});
