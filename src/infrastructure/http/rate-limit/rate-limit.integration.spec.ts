import { AUTHORIZATION_USE_CASE } from 'src/core/domain/puertos/inbound/IAuthorizationUseCase.interface';
import { PASSWORD_RESET_USE_CASE } from 'src/core/domain/puertos/inbound/IPasswordResetUseCase.interface';
import { createHttpApp } from 'src/test-support/http-app';
import { AuthorizationController } from '../controllers/authorization.controller';
import { PasswordResetController } from '../controllers/passwordReset.controller';
import { RegistroController } from '../controllers/registro.controller';
import { getToken } from '@willsoto/nestjs-prometheus';

/** Rate limit con el ThrottlerGuard REAL sobre los controladores reales (casos de uso simulados). */
async function setup() {
  const authorization = { ExecuteAuthorize: jest.fn().mockResolvedValue([]), ExecuteToken: jest.fn() };
  const passwordReset = { ExecuteRequestReset: jest.fn().mockResolvedValue({ message: 'ok' }), ExecuteValidateResetToken: jest.fn(), ExecuteResetPassword: jest.fn() };
  const registro = {
    ExecuteValidateField: jest.fn().mockResolvedValue({ available: true }),
    executeCreateRegistro: jest.fn(),
    executeVerificarEmail: jest.fn().mockResolvedValue({ success: false, message: 'Código incorrecto.' }),
    executeResendOtp: jest.fn().mockResolvedValue({ success: true }),
  };
  const ctx = await createHttpApp({
    controllers: [AuthorizationController, PasswordResetController, RegistroController],
    providers: [
      { provide: AUTHORIZATION_USE_CASE, useValue: authorization },
      { provide: PASSWORD_RESET_USE_CASE, useValue: passwordReset },
      { provide: 'REGISTRO_USE_CASE', useValue: registro },
      { provide: getToken('auth_register_attempts_total'), useValue: { inc: jest.fn() } },
    ],
  });
  return { ...ctx, authorization, passwordReset, registro };
}

const login = (username: string) => ({ username, password: 'x', code_challenge: 'c', typeDevice: 'WEB', CorrelationId: 'cid' });

describe('Rate limit de los endpoints sensibles', () => {
  afterEach(() => { delete process.env.RATE_LIMIT_ENABLED; });

  describe('POST /security/authorize', () => {
    it('limita por USUARIO (10 cada 15 min): el 11.º intento sobre la misma cuenta da 429 sin llegar al caso de uso', async () => {
      const { http, authorization } = await setup();
      for (let i = 0; i < 10; i++) expect((await http().post('/security/authorize').send(login('ana'))).status).toBe(200);

      const blocked = await http().post('/security/authorize').send(login('ana'));
      expect(blocked.status).toBe(429);
      expect(blocked.body.message).toMatch(/Demasiados intentos/);
      expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0); // cabecera estándar
      expect(Number(blocked.headers['retry-after'])).toBeLessThanOrEqual(15 * 60);
      expect(authorization.ExecuteAuthorize).toHaveBeenCalledTimes(10);
    });

    it('el bloqueo de una cuenta no afecta a otra', async () => {
      const { http } = await setup();
      for (let i = 0; i < 11; i++) await http().post('/security/authorize').send(login('ana'));
      expect((await http().post('/security/authorize').send(login('beto'))).status).toBe(200);
    });

    it('mayúsculas y espacios en el username no permiten evadir el límite de la cuenta', async () => {
      const { http } = await setup();
      for (let i = 0; i < 10; i++) await http().post('/security/authorize').send(login(i % 2 ? ' ANA ' : 'ana'));
      expect((await http().post('/security/authorize').send(login('Ana'))).status).toBe(429);
    });

    it('limita por IP (20 por minuto) aunque cada intento use un usuario distinto', async () => {
      const { http } = await setup();
      for (let i = 0; i < 20; i++) expect((await http().post('/security/authorize').send(login(`user${i}`))).status).toBe(200);
      expect((await http().post('/security/authorize').send(login('user-21'))).status).toBe(429);
    });

    it('un cuerpo inválido también consume cupo (no se puede sondear gratis)', async () => {
      const { http } = await setup();
      for (let i = 0; i < 10; i++) await http().post('/security/authorize').send({ username: 'ana' });
      expect((await http().post('/security/authorize').send(login('ana'))).status).toBe(429);
    });
  });

  describe('recuperación de contraseña', () => {
    it('solo 3 solicitudes por hora por correo (anti-bombardeo): la 4.ª da 429 y no envía nada', async () => {
      const { http, passwordReset } = await setup();
      for (let i = 0; i < 3; i++) expect((await http().post('/security/password-reset/request').send({ correo: 'ana@test.cl' })).status).toBe(201);
      expect((await http().post('/security/password-reset/request').send({ correo: 'ANA@test.cl' })).status).toBe(429);
      expect(passwordReset.ExecuteRequestReset).toHaveBeenCalledTimes(3);
      expect((await http().post('/security/password-reset/request').send({ correo: 'otra@test.cl' })).status).toBe(201);
    });

    it('validate y reset tienen tope por IP', async () => {
      const { http, passwordReset } = await setup();
      passwordReset.ExecuteResetPassword.mockResolvedValue({ message: 'ok' });
      const body = { token: 't', uuid: 'u', newPassword: 'Nueva#1234', confirmPassword: 'Nueva#1234' };
      for (let i = 0; i < 10; i++) expect((await http().post('/security/password-reset/reset').send(body)).status).toBe(201);
      expect((await http().post('/security/password-reset/reset').send(body)).status).toBe(429);
    });
  });

  describe('registro y OTP', () => {
    it('resend-otp: 3 por correo cada 15 min', async () => {
      const { http, registro } = await setup();
      for (let i = 0; i < 3; i++) expect((await http().post('/registro/resend-otp').send({ email: 'ana@test.cl' })).status).toBe(200);
      expect((await http().post('/registro/resend-otp').send({ email: 'ana@test.cl' })).status).toBe(429);
      expect(registro.executeResendOtp).toHaveBeenCalledTimes(3);
    });

    it('verificar-email: 10 intentos por correo cada 15 min (además del tope de 5 por código)', async () => {
      const { http } = await setup();
      const send = () => http().post('/registro/verificar-email').send({ email: 'ana@test.cl', otp: '000000' });
      for (let i = 0; i < 10; i++) expect((await send()).status).toBe(400);
      expect((await send()).status).toBe(429);
    });

    it('registro: 10 altas por hora desde la misma IP', async () => {
      const { http, registro } = await setup();
      registro.executeCreateRegistro.mockResolvedValue({ success: false, message: 'x' });
      const bad = {}; // el 400 por validación también cuenta
      for (let i = 0; i < 10; i++) await http().post('/registro').send(bad);
      expect((await http().post('/registro').send(bad)).status).toBe(429);
    });

    it('check de disponibilidad: 30 por minuto por IP (frena el barrido de usernames/correos)', async () => {
      const { http } = await setup();
      for (let i = 0; i < 30; i++) expect((await http().get('/registro/check/username').query({ value: `u${i}` })).status).toBe(200);
      expect((await http().get('/registro/check/username').query({ value: 'u31' })).status).toBe(429);
    });
  });

  it('RATE_LIMIT_ENABLED=false desactiva los límites (p. ej. pruebas de carga)', async () => {
    process.env.RATE_LIMIT_ENABLED = 'false';
    const { http } = await setup();
    for (let i = 0; i < 25; i++) expect((await http().post('/security/authorize').send(login('ana'))).status).toBe(200);
  });
});
