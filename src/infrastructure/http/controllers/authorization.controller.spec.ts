import { EmailNotVerifiedError } from 'src/core/domain/errors/EmailNotVerified.error';
import { InvalidcodeToken } from 'src/core/domain/errors/InvalidCodeToken.error';
import { LoginError } from 'src/core/domain/errors/LoginError.error';
import { AUTHORIZATION_USE_CASE } from 'src/core/domain/puertos/inbound/IAuthorizationUseCase.interface';
import { createHttpApp } from 'src/test-support/http-app';
import { AuthorizationController } from './authorization.controller';

const authorizeBody = { username: 'ana', password: 'x', code_challenge: 'ch', typeDevice: 'WEB', CorrelationId: 'cid-1' };
const tokenBody = { code: 'abc', codeVerifier: 'ver', typeDevice: 'WEB', cid: 'cid-1' };

async function setup() {
  const useCase = { ExecuteAuthorize: jest.fn(), ExecuteToken: jest.fn() };
  const ctx = await createHttpApp({ controllers: [AuthorizationController], providers: [{ provide: AUTHORIZATION_USE_CASE, useValue: useCase }] });
  return { ...ctx, useCase };
}

describe('AuthorizationController', () => {
  describe('POST /security/authorize', () => {
    it('200 con las redirecciones y cuenta el intento como exitoso', async () => {
      const { http, useCase, metrics } = await setup();
      useCase.ExecuteAuthorize.mockResolvedValue([{ code: 'c', url: '/validate?code=c&cid=cid-1' }]);

      const res = await http().post('/security/authorize').set('x-request-id', 'req-9').send(authorizeBody);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: 200, message: 'Login exitoso', data: [{ code: 'c', url: '/validate?code=c&cid=cid-1' }] });
      expect(useCase.ExecuteAuthorize).toHaveBeenCalledWith(expect.objectContaining({ username: 'ana', code_challenge: 'ch', requestId: 'req-9' }));
      expect(metrics.loginAttempt).toHaveBeenCalledWith('success');
    });

    it.each([
      ['password', 'La contraseña es obligatoria'],
      ['code_challenge', 'El código de desafío es obligatorio'],
      ['CorrelationId', 'El CorrelationId es obligatorio'],
    ])('400 si falta %s, sin invocar el caso de uso', async (field, message) => {
      const { http, useCase } = await setup();
      const res = await http().post('/security/authorize').send({ ...authorizeBody, [field]: undefined });
      expect(res.status).toBe(400);
      expect(res.body.message).toBe(message);
      expect(useCase.ExecuteAuthorize).not.toHaveBeenCalled();
    });

    it('400 si typeDevice no es uno de los permitidos', async () => {
      const { http } = await setup();
      expect((await http().post('/security/authorize').send({ ...authorizeBody, typeDevice: 'TOSTADORA' })).status).toBe(400);
    });

    it('credenciales inválidas → 401 (lo que el login del SPA interpreta como "usuario o contraseña incorrectos") y cuenta el intento fallido', async () => {
      const { http, useCase, metrics } = await setup();
      useCase.ExecuteAuthorize.mockRejectedValue(new LoginError('Usuario o contraseña incorrectos'));
      const res = await http().post('/security/authorize').send(authorizeBody);
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Usuario o contraseña incorrectos');
      expect(metrics.loginAttempt).toHaveBeenCalledWith('failure');
    });

    it('403 con code EMAIL_NOT_VERIFIED y el correo cuando falta verificar', async () => {
      const { http, useCase } = await setup();
      useCase.ExecuteAuthorize.mockRejectedValue(new EmailNotVerifiedError('ana@test.cl'));
      const res = await http().post('/security/authorize').send(authorizeBody);
      expect(res.status).toBe(403);
      expect(res.body).toEqual({ code: 'EMAIL_NOT_VERIFIED', email: 'ana@test.cl' });
    });
  });

  describe('POST /security/token', () => {
    const okTokens = { accessToken: 'AT', refreshToken: 'RT' };

    it('200: marca la sesión como autenticada, la guarda y fija la cookie de refresh HttpOnly', async () => {
      const { http, useCase, session } = await setup();
      useCase.ExecuteToken.mockResolvedValue(okTokens);

      const res = await http().post('/security/token').send(tokenBody);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: 200, message: 'Callback exitoso', data: { message: 'Autenticación exitosa' } });
      expect(session.authenticated).toBe(true);
      expect(session.accessToken).toBe('AT');
      expect(session.save).toHaveBeenCalledTimes(1);
      const cookie = (res.headers['set-cookie'] as unknown as string[]).find(c => c.startsWith('auth.refresh='))!;
      expect(cookie).toContain('RT');
      expect(cookie).toMatch(/HttpOnly/i);
      expect(cookie).toMatch(/SameSite=Lax/i);
      expect(cookie).not.toMatch(/Secure/i);
    });

    it('la cookie de refresh es Secure cuando el proxy indica HTTPS', async () => {
      const { http, useCase } = await setup();
      useCase.ExecuteToken.mockResolvedValue(okTokens);
      const res = await http().post('/security/token').set('x-forwarded-proto', 'https').send(tokenBody);
      expect((res.headers['set-cookie'] as unknown as string[]).find(c => c.startsWith('auth.refresh='))).toMatch(/Secure/i);
    });

    it('pasa al caso de uso el id de la sesión actual y el cid como CorrelationId', async () => {
      const { http, useCase } = await setup();
      useCase.ExecuteToken.mockResolvedValue(okTokens);
      await http().post('/security/token').send(tokenBody);
      expect(useCase.ExecuteToken).toHaveBeenCalledWith(expect.objectContaining({ code: 'abc', codeVerifier: 'ver', sessionId: 'sess-1', CorrelationId: 'cid-1' }));
    });

    it('ignora el id que trae la cookie auth.session: usa siempre el id de la sesión verificada', async () => {
      const { http, useCase } = await setup();
      useCase.ExecuteToken.mockResolvedValue(okTokens);
      await http().post('/security/token').set('Cookie', 'auth.session=s:id-elegido-por-el-cliente.firma').send(tokenBody);
      expect(useCase.ExecuteToken).toHaveBeenCalledWith(expect.objectContaining({ sessionId: 'sess-1' }));
    });

    it.each(['mal-formada', 's:', ''])('una cookie auth.session mal formada (%p) no provoca 500: se usa la sesión actual', async (value) => {
      const { http, useCase } = await setup();
      useCase.ExecuteToken.mockResolvedValue(okTokens);
      const res = await http().post('/security/token').set('Cookie', `auth.session=${value}`).send(tokenBody);
      expect(res.status).toBe(200);
      expect(useCase.ExecuteToken).toHaveBeenCalledWith(expect.objectContaining({ sessionId: 'sess-1' }));
    });

    it('400 si el código o el verifier son inválidos, sin tocar la sesión ni fijar cookies', async () => {
      const { http, useCase, session } = await setup();
      useCase.ExecuteToken.mockRejectedValue(new InvalidcodeToken('Code verifier inválido (PKCE)'));
      const res = await http().post('/security/token').send(tokenBody);
      expect(res.status).toBe(400);
      expect(session.save).not.toHaveBeenCalled();
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('400 si falta el codeVerifier', async () => {
      const { http, useCase } = await setup();
      expect((await http().post('/security/token').send({ ...tokenBody, codeVerifier: undefined })).status).toBe(400);
      expect(useCase.ExecuteToken).not.toHaveBeenCalled();
    });

    it('si no se puede guardar la sesión no se emite la cookie de refresh', async () => {
      const { http, useCase, session } = await setup();
      useCase.ExecuteToken.mockResolvedValue(okTokens);
      session.save.mockImplementation((cb: any) => cb(new Error('redis caído')));
      const res = await http().post('/security/token').send(tokenBody);
      expect(res.status).toBe(500);
      expect(res.headers['set-cookie']).toBeUndefined();
    });
  });

  it('los nombres anteriores (authenticate, callback) ya no existen', async () => {
    const { http } = await setup();
    expect((await http().post('/security/authenticate').send(authorizeBody)).status).toBe(404);
    expect((await http().post('/security/callback').send(tokenBody)).status).toBe(404);
  });
});
