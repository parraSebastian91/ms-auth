import { UnauthorizedException } from '@nestjs/common';
import { SESSION_USE_CASE } from 'src/core/domain/puertos/inbound/ISessionUseCase.interface';
import { createHttpApp } from 'src/test-support/http-app';
import { SessionController } from './session.controller';

async function setup() {
  const useCase = { ExecuteRefreshSession: jest.fn(), ExecuteLogout: jest.fn().mockResolvedValue(undefined), ExecuteValidateSession: jest.fn() };
  const ctx = await createHttpApp({ controllers: [SessionController], providers: [{ provide: SESSION_USE_CASE, useValue: useCase }] });
  return { ...ctx, useCase };
}

describe('SessionController', () => {
  describe('POST /security/session/refresh', () => {
    it('200: pasa las cookies al caso de uso, guarda el access token y renueva la cookie de refresh', async () => {
      const { http, useCase, session, metrics } = await setup();
      useCase.ExecuteRefreshSession.mockResolvedValue({ accessToken: 'AT2', refreshToken: 'RT2' });

      const res = await http().post('/security/session/refresh').set('Cookie', 'auth.refresh=RT1').send({ typeDevice: 'WEB' });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ message: 'Sesión renovada' });
      expect(useCase.ExecuteRefreshSession).toHaveBeenCalledWith(expect.objectContaining({ tokens: { 'auth.refresh': 'RT1' }, typeDevice: 'WEB' }));
      expect(session).toMatchObject({ authenticated: true, accessToken: 'AT2' });
      expect(session.save).toHaveBeenCalled();
      expect((res.headers['set-cookie'] as unknown as string[]).find(c => c.startsWith('auth.refresh='))).toContain('RT2');
      expect(metrics.sessionRefreshed).toHaveBeenCalledTimes(1);
    });

    it('acepta el cuerpo vacío (typeDevice es opcional)', async () => {
      const { http, useCase } = await setup();
      useCase.ExecuteRefreshSession.mockResolvedValue({ accessToken: 'a', refreshToken: 'r' });
      expect((await http().post('/security/session/refresh').send({})).status).toBe(200);
    });

    it('401 si el caso de uso rechaza el refresh token, sin tocar la sesión ni cuenta el refresco', async () => {
      const { http, useCase, session, metrics } = await setup();
      useCase.ExecuteRefreshSession.mockRejectedValue(new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo'));
      const res = await http().post('/security/session/refresh').send({});
      expect(res.status).toBe(401);
      expect(session.save).not.toHaveBeenCalled();
      expect(metrics.sessionRefreshed).not.toHaveBeenCalled();
    });
  });

  describe('POST /security/logout', () => {
    it('200: revoca la sesión, la destruye y borra las cookies de refresh y de sesión', async () => {
      const { http, useCase, session } = await setup();
      const res = await http().post('/security/logout');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: 200, message: 'Logout exitoso', data: null });
      expect(useCase.ExecuteLogout).toHaveBeenCalledWith('sess-1');
      expect(session.destroy).toHaveBeenCalledTimes(1);
      const cleared = (res.headers['set-cookie'] as unknown as string[]).join('|');
      expect(cleared).toMatch(/auth\.refresh=;/);
      expect(cleared).toMatch(/auth\.session=;/);
    });

    it('500 y sin borrar cookies si falla el destroy de la sesión (no responde dos veces)', async () => {
      const { http, session } = await setup();
      session.destroy.mockImplementation((cb: any) => cb(new Error('redis caído')));
      const res = await http().post('/security/logout');
      expect(res.status).toBe(500);
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('si revocar en el caso de uso falla no se destruye la sesión', async () => {
      const { http, useCase, session } = await setup();
      useCase.ExecuteLogout.mockRejectedValue(new Error('bd caída'));
      expect((await http().post('/security/logout')).status).toBe(500);
      expect(session.destroy).not.toHaveBeenCalled();
    });
  });

  it('logout ya no acepta GET (cambia estado: un enlace o imagen de otro sitio podría cerrar la sesión)', async () => {
    const { http, useCase, session } = await setup();
    expect((await http().get('/security/logout')).status).toBe(404);
    expect(useCase.ExecuteLogout).not.toHaveBeenCalled();
    expect(session.destroy).not.toHaveBeenCalled();
  });

  it('el endpoint de depuración session/test fue retirado', async () => {
    const { http } = await setup();
    for (const m of ['get', 'post'] as const) expect((await http()[m]('/security/session/test')).status).toBe(404);
  });
});
