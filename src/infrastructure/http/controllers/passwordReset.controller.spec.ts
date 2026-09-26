import { BadRequestException } from '@nestjs/common';
import { PASSWORD_RESET_USE_CASE } from 'src/core/domain/puertos/inbound/IPasswordResetUseCase.interface';
import { createHttpApp } from 'src/test-support/http-app';
import { PasswordResetController } from './passwordReset.controller';

async function setup() {
  const useCase = { ExecuteRequestReset: jest.fn(), ExecuteValidateResetToken: jest.fn(), ExecuteResetPassword: jest.fn() };
  const ctx = await createHttpApp({ controllers: [PasswordResetController], providers: [{ provide: PASSWORD_RESET_USE_CASE, useValue: useCase }] });
  return { ...ctx, useCase };
}

describe('PasswordResetController', () => {
  describe('POST /security/password-reset/request', () => {
    it('devuelve tal cual el resultado del caso de uso, con ip y user-agent, y cuenta la solicitud', async () => {
      const { http, useCase, metrics } = await setup();
      useCase.ExecuteRequestReset.mockResolvedValue({ message: 'ok' });
      const res = await http().post('/security/password-reset/request').set('User-Agent', 'jest-agent').send({ correo: 'ana@test.cl' });
      expect(res.status).toBe(201);
      expect(res.body).toEqual({ message: 'ok' });
      expect(useCase.ExecuteRequestReset).toHaveBeenCalledWith(expect.objectContaining({ correo: 'ana@test.cl', userAgent: 'jest-agent', ip: expect.any(String) }));
      expect(metrics.passwordResetRequested).toHaveBeenCalledTimes(1);
    });

    it('400 con un correo inválido, sin invocar el caso de uso', async () => {
      const { http, useCase } = await setup();
      expect((await http().post('/security/password-reset/request').send({ correo: 'no-es-correo' })).status).toBe(400);
      expect(useCase.ExecuteRequestReset).not.toHaveBeenCalled();
    });
  });

  describe('GET /security/password-reset/validate', () => {
    it('devuelve { valid, email } del caso de uso', async () => {
      const { http, useCase } = await setup();
      useCase.ExecuteValidateResetToken.mockResolvedValue({ valid: true, email: 'ana@test.cl' });
      const res = await http().get('/security/password-reset/validate').query({ token: 't', uuid: 'u' });
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ valid: true, email: 'ana@test.cl' });
      expect(useCase.ExecuteValidateResetToken).toHaveBeenCalledWith(expect.objectContaining({ token: 't', uuid: 'u' }));
    });

    it('400 si falta el token', async () => {
      const { http } = await setup();
      expect((await http().get('/security/password-reset/validate').query({ uuid: 'u' })).status).toBe(400);
    });
  });

  describe('POST /security/password-reset/reset', () => {
    const body = { token: 't', uuid: 'u', newPassword: 'Nueva#1234', confirmPassword: 'Nueva#1234' };

    it('restablece con el cuerpo válido', async () => {
      const { http, useCase } = await setup();
      useCase.ExecuteResetPassword.mockResolvedValue({ message: 'Contraseña restablecida exitosamente' });
      const res = await http().post('/security/password-reset/reset').send(body);
      expect(res.body).toEqual({ message: 'Contraseña restablecida exitosamente' });
      expect(useCase.ExecuteResetPassword).toHaveBeenCalledWith(expect.objectContaining({ newPassword: 'Nueva#1234', confirmPassword: 'Nueva#1234' }));
    });

    it('400 con una contraseña de menos de 8 caracteres', async () => {
      const { http, useCase } = await setup();
      const res = await http().post('/security/password-reset/reset').send({ ...body, newPassword: 'corta', confirmPassword: 'corta' });
      expect(res.status).toBe(400);
      expect(useCase.ExecuteResetPassword).not.toHaveBeenCalled();
    });

    it('propaga como 500 los errores no HTTP del caso de uso y como 400 los BadRequest', async () => {
      const { http, useCase } = await setup();
      useCase.ExecuteResetPassword.mockRejectedValue(new BadRequestException('Token inválido o expirado'));
      const res = await http().post('/security/password-reset/reset').send(body);
      expect(res.status).toBe(400);
      expect(res.body.message).toBe('Token inválido o expirado');
    });
  });
});
