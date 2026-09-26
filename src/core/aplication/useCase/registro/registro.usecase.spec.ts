import * as bcrypt from 'bcrypt';
import { makeFakeCache } from 'src/test-support/fixtures';
import { MAX_OTP_ATTEMPTS, RegistroUseCaseImpl } from './registro.usecase.impl';

const UUID = 'uuid-1';
const vo = <T>(v: T) => ({ getValue: () => v });

function setup(o: { usuario?: any } = {}) {
  const cache = makeFakeCache();
  const usuarioRepo: any = {
    getUsuarioByEmail: jest.fn().mockResolvedValue(o.usuario === undefined ? { id: 7, uuid: UUID, emailVerificado: false, nombres: 'Ana' } : o.usuario),
    createUsuario: jest.fn().mockResolvedValue({ usuarioUuid: UUID }),
    marcarEmailVerificado: jest.fn().mockResolvedValue(undefined),
    validateField: jest.fn(),
  };
  const contactoRepo: any = { create: jest.fn().mockResolvedValue(55), delete: jest.fn().mockResolvedValue(undefined) };
  const emailService: any = { sendVerificationCode: jest.fn().mockResolvedValue(undefined) };
  const rolRepo: any = { setRolInicial: jest.fn().mockResolvedValue(undefined) };
  const uc = new RegistroUseCaseImpl(usuarioRepo, contactoRepo, cache as any, emailService, rolRepo);
  return { uc, cache, usuarioRepo, contactoRepo, emailService, rolRepo };
}

const formData = (): any => ({
  rol: 'CEDENTE', email: vo('ana@test.cl'), username: 'ana', nombres: 'Ana', apellidoPaterno: 'P', apellidoMaterno: 'M',
  telefono: vo('+56912345678'), tipoDocumento: vo('RUT'), numeroDocumento: vo('12345678-9'), pais: 'CL',
  fechaNacimiento: new Date('1990-01-01'), direccion: 'Calle 123', password: vo('Secreta#123'),
});

/** Deja un código válido almacenado y devuelve el código en claro. */
async function withCode(s: ReturnType<typeof setup>, code = '123456') {
  s.cache.emailCodes.set(UUID, await bcrypt.hash(code, 4));
  return code;
}

describe('RegistroUseCaseImpl', () => {
  describe('executeCreateRegistro', () => {
    it('crea contacto y usuario, guarda el hash del OTP (no el código) y lo envía por correo', async () => {
      const { uc, cache, emailService, contactoRepo, usuarioRepo } = setup();
      await expect(uc.executeCreateRegistro(formData())).resolves.toEqual({ success: true });

      expect(contactoRepo.create).toHaveBeenCalledWith(expect.objectContaining({ correo: 'ana@test.cl', numeroDocumento: '12345678-9' }));
      expect(usuarioRepo.createUsuario).toHaveBeenCalledWith(expect.objectContaining({ username: 'ana', contactoid: 55 }));
      const sent = emailService.sendVerificationCode.mock.calls[0];
      expect(sent[0]).toBe('ana@test.cl');
      expect(sent[1]).toMatch(/^\d{6}$/);
      const stored = cache.emailCodes.get(UUID)!;
      expect(stored).not.toBe(sent[1]);
      expect(await bcrypt.compare(sent[1], stored)).toBe(true);
    });

    it('guarda la contraseña hasheada con bcrypt, nunca en claro', async () => {
      const { uc, usuarioRepo } = setup();
      await uc.executeCreateRegistro(formData());
      const { passwordHash } = usuarioRepo.createUsuario.mock.calls[0][0];
      expect(passwordHash).not.toBe('Secreta#123');
      expect(await bcrypt.compare('Secreta#123', passwordHash)).toBe(true);
    });

    it.each([
      ['createUsuario falla', (s: any) => s.usuarioRepo.createUsuario.mockRejectedValue(new Error('duplicado'))],
      ['createUsuario no devuelve uuid', (s: any) => s.usuarioRepo.createUsuario.mockResolvedValue({})],
      ['el envío del correo falla', (s: any) => s.emailService.sendVerificationCode.mockRejectedValue(new Error('SMTP'))],
    ])('rollback del contacto y mensaje genérico cuando %s', async (_n, arrange) => {
      const s = setup();
      arrange(s);
      await expect(s.uc.executeCreateRegistro(formData())).resolves.toEqual({ success: false, message: 'Error al crear el registro' });
      expect(s.contactoRepo.delete).toHaveBeenCalledWith(55);
    });

    it('si falla el propio alta del contacto no hay nada que revertir', async () => {
      const s = setup();
      s.contactoRepo.create.mockRejectedValue(new Error('correo repetido'));
      await expect(s.uc.executeCreateRegistro(formData())).resolves.toMatchObject({ success: false });
      expect(s.contactoRepo.delete).not.toHaveBeenCalled();
    });
  });

  describe('executeVerificarEmail', () => {
    it('correo desconocido → mismo mensaje que código vencido (no revela si existe)', async () => {
      const r = await setup({ usuario: null }).uc.executeVerificarEmail('x@test.cl', '123456');
      expect(r).toEqual({ success: false, message: 'Código expirado o inexistente. Solicita uno nuevo.' });
    });

    it('sin código almacenado → expirado', async () => {
      const r = await setup().uc.executeVerificarEmail('ana@test.cl', '123456');
      expect(r).toEqual({ success: false, message: 'Código expirado o inexistente. Solicita uno nuevo.' });
    });

    it('con el código correcto verifica el correo, asigna el rol inicial y consume el código', async () => {
      const s = setup();
      const code = await withCode(s);
      await expect(s.uc.executeVerificarEmail('ana@test.cl', code)).resolves.toEqual({ success: true });
      expect(s.usuarioRepo.marcarEmailVerificado).toHaveBeenCalledWith(UUID);
      expect(s.rolRepo.setRolInicial).toHaveBeenCalledWith(7, 'CEDENTE');
      expect(s.cache.emailCodes.has(UUID)).toBe(false);
    });

    it('un código incorrecto no verifica y cuenta el intento', async () => {
      const s = setup();
      await withCode(s);
      await expect(s.uc.executeVerificarEmail('ana@test.cl', '000000')).resolves.toEqual({ success: false, message: 'Código incorrecto.' });
      expect(s.usuarioRepo.marcarEmailVerificado).not.toHaveBeenCalled();
      expect(s.cache.attempts.get(UUID)).toBe(1);
    });

    it(`tras ${MAX_OTP_ATTEMPTS} intentos fallidos el código se invalida: ni el correcto sirve hasta pedir otro`, async () => {
      const s = setup();
      const code = await withCode(s);
      for (let i = 1; i < MAX_OTP_ATTEMPTS; i++) {
        await expect(s.uc.executeVerificarEmail('ana@test.cl', '000000')).resolves.toMatchObject({ message: 'Código incorrecto.' });
      }
      const last = await s.uc.executeVerificarEmail('ana@test.cl', '000000');
      expect(last).toEqual({ success: false, message: 'Demasiados intentos incorrectos. Solicita un código nuevo.' });
      expect(s.cache.emailCodes.has(UUID)).toBe(false);

      const afterwards = await s.uc.executeVerificarEmail('ana@test.cl', code);
      expect(afterwards.success).toBe(false);
      expect(s.usuarioRepo.marcarEmailVerificado).not.toHaveBeenCalled();
    });

    it('acertar antes del tope verifica y reinicia el contador', async () => {
      const s = setup();
      const code = await withCode(s);
      await s.uc.executeVerificarEmail('ana@test.cl', '000000');
      await s.uc.executeVerificarEmail('ana@test.cl', '000000');
      await expect(s.uc.executeVerificarEmail('ana@test.cl', code)).resolves.toEqual({ success: true });
      expect(s.cache.attempts.has(UUID)).toBe(false);
    });

    it('un correo ya verificado responde éxito sin volver a asignar rol', async () => {
      const s = setup({ usuario: { id: 7, uuid: UUID, emailVerificado: true, nombres: 'Ana' } });
      await expect(s.uc.executeVerificarEmail('ana@test.cl', '123456')).resolves.toEqual({ success: true });
      expect(s.rolRepo.setRolInicial).not.toHaveBeenCalled();
    });
  });

  describe('executeResendOtp (anti-enumeración)', () => {
    const verificado = { id: 7, uuid: UUID, emailVerificado: true, nombres: 'Ana' };

    it('correo desconocido → éxito uniforme, sin enviar nada', async () => {
      const s = setup({ usuario: null });
      await expect(s.uc.executeResendOtp('x@test.cl')).resolves.toEqual({ success: true });
      await s.uc.whenIdle();
      expect(s.emailService.sendVerificationCode).not.toHaveBeenCalled();
    });

    it('correo ya verificado → MISMA respuesta que el resto (no revela el estado) y sin envío', async () => {
      const s = setup({ usuario: verificado });
      await expect(s.uc.executeResendOtp('ana@test.cl')).resolves.toEqual({ success: true });
      await s.uc.whenIdle();
      expect(s.emailService.sendVerificationCode).not.toHaveBeenCalled();
    });

    it('la respuesta es idéntica para desconocido, verificado y pendiente', async () => {
      const respuestas = [];
      for (const usuario of [null, verificado, undefined]) {
        const s = setup({ usuario });
        respuestas.push(await s.uc.executeResendOtp('ana@test.cl'));
        await s.uc.whenIdle();
      }
      expect(new Set(respuestas.map(r => JSON.stringify(r))).size).toBe(1);
    });

    it('al responder solo se hizo la búsqueda: bcrypt, caché y envío ocurren en segundo plano', async () => {
      const s = setup();
      await s.uc.executeResendOtp('ana@test.cl');
      expect(s.emailService.sendVerificationCode).not.toHaveBeenCalled();
      expect(s.cache.emailCodes.has(UUID)).toBe(false);
      await s.uc.whenIdle();
      expect(s.emailService.sendVerificationCode).toHaveBeenCalledTimes(1);
    });

    it('emite un código NUEVO (reemplaza el anterior) y reinicia el contador de intentos', async () => {
      const s = setup();
      const old = await withCode(s, '111111');
      s.cache.attempts.set(UUID, 4);
      await expect(s.uc.executeResendOtp('ana@test.cl')).resolves.toEqual({ success: true });
      await s.uc.whenIdle();

      const newCode = s.emailService.sendVerificationCode.mock.calls[0][1];
      expect(await bcrypt.compare(newCode, s.cache.emailCodes.get(UUID)!)).toBe(true);
      expect(old).not.toBe(newCode);
      expect(s.cache.attempts.has(UUID)).toBe(false);
    });

    it('si falla el envío no se propaga: la respuesta sigue siendo la genérica', async () => {
      const s = setup();
      s.emailService.sendVerificationCode.mockRejectedValue(new Error('smtp caído'));
      jest.spyOn(require('@nestjs/common').Logger.prototype, 'error').mockImplementation(() => undefined);
      await expect(s.uc.executeResendOtp('ana@test.cl')).resolves.toEqual({ success: true });
      await expect(s.uc.whenIdle()).resolves.toBeUndefined();
    });

    it('onModuleDestroy espera a los envíos pendientes', async () => {
      const s = setup();
      await s.uc.executeResendOtp('ana@test.cl');
      await s.uc.onModuleDestroy();
      expect(s.emailService.sendVerificationCode).toHaveBeenCalledTimes(1);
    });
  });
});
