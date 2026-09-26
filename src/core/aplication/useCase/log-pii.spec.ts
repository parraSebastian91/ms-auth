import { Logger } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { makeUsuario } from 'src/test-support/fixtures';
import { AuthorizationUseCase } from './authorization/authorization.usecase';
import { PasswordResetUseCase } from './passwordReset/passwordReset.usecase';

/** Los logs se recolectan: ni el correo ni el username completos deben aparecer en ninguna línea. */
describe('Los casos de uso no registran datos personales completos', () => {
  const lines: string[] = [];
  beforeEach(() => {
    lines.length = 0;
    for (const level of ['log', 'warn', 'error', 'debug', 'verbose'] as const) {
      jest.spyOn(Logger.prototype, level).mockImplementation((m: any) => { lines.push(String(m)); });
    }
  });
  afterEach(() => jest.restoreAllMocks());

  const EMAIL = 'ana.perez@correo.cl';
  const USER = 'anaperez';

  it('authorize (usuario inexistente, contraseña errónea, correo sin verificar y éxito)', async () => {
    const hash = await bcrypt.hash('ok', 4);
    const build = (usuario: any) => {
      const usuarioRepo: any = { getUsuarioByUsername: async () => usuario, getSystemsByUsername: async () => [{}] };
      const authService: any = { createAuthorizationCode: async () => 'code' };
      return new AuthorizationUseCase(usuarioRepo, authService, {} as any);
    };
    const cmd = (o: any = {}) => ({ username: USER, password: 'ok', typeDevice: 'WEB', code_challenge: 'c', CorrelationId: 'x', ...o });

    await build(null).ExecuteAuthorize(cmd()).catch(() => undefined);
    await build(makeUsuario({ password: hash })).ExecuteAuthorize(cmd({ password: 'mala' })).catch(() => undefined);
    await build(makeUsuario({ password: hash, emailVerificado: false })).ExecuteAuthorize(cmd({ username: EMAIL })).catch(() => undefined);
    await build(makeUsuario({ password: hash })).ExecuteAuthorize(cmd());

    expect(lines.length).toBeGreaterThan(8);
    for (const l of lines) { expect(l).not.toContain(USER); expect(l).not.toContain(EMAIL); }
  });

  it('password-reset (correo inexistente, inactivo y activo; y reset)', async () => {
    const build = (contacto: any) => new PasswordResetUseCase(
      { getUsuarioById: async () => ({ id: { getValue: () => 7 }, uuid: 'u', userName: USER }), updatePassword: async () => undefined } as any,
      { findByCorreo: async () => contacto } as any,
      { deleteUserTokens: async () => undefined, createResetToken: async () => ({ tokenUuid: 't' }), findValidToken: async () => null } as any,
      { revokeAllUserSessions: async () => ({}) } as any,
      { sendPasswordResetLink: async () => undefined, sendPasswordChangedNotice: async () => undefined } as any,
      { frontendUrl: 'https://app.test' },
    );
    const cmd = { correo: EMAIL, ip: '1.1.1.1', userAgent: 'jest' };
    await build(null).ExecuteRequestReset(cmd);
    await build({ usuario: { id: 7, activo: false } }).ExecuteRequestReset(cmd);
    await build({ nombres: 'Ana', usuario: { id: 7, activo: true, userName: USER } }).ExecuteRequestReset(cmd);

    expect(lines.length).toBeGreaterThan(5);
    for (const l of lines) { expect(l).not.toContain(EMAIL); expect(l).not.toContain(USER); }
  });
});
