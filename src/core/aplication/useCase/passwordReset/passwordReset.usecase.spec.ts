import { BadRequestException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PasswordResetUseCase } from './passwordReset.usecase';

const GENERIC = 'Si el correo existe, recibirás un enlace de restablecimiento';
const TOKEN = 'token-plano-de-prueba';

function setup(o: { contacto?: any; resetToken?: any; usuario?: any } = {}) {
  const usuarioRepo: any = {
    getUsuarioById: jest.fn().mockResolvedValue(o.usuario === undefined ? { id: { getValue: () => 7 }, uuid: 'u-1' } : o.usuario),
    updatePassword: jest.fn().mockResolvedValue(undefined),
  };
  const contactoRepo: any = { findByCorreo: jest.fn().mockResolvedValue(o.contacto ?? null) };
  const resetRepo: any = {
    deleteUserTokens: jest.fn().mockResolvedValue(undefined),
    createResetToken: jest.fn().mockResolvedValue({ tokenUuid: 'tok-uuid' }),
    findValidToken: jest.fn().mockResolvedValue(o.resetToken ?? null),
    markTokenAsUsed: jest.fn().mockResolvedValue(undefined),
  };
  const sessionsRepo: any = { revokeAllUserSessions: jest.fn().mockResolvedValue(3) };
  return { uc: new PasswordResetUseCase(usuarioRepo, contactoRepo, resetRepo, sessionsRepo), usuarioRepo, contactoRepo, resetRepo, sessionsRepo };
}

describe('PasswordResetUseCase', () => {
  let tokenHash: string;
  beforeAll(async () => { tokenHash = await bcrypt.hash(TOKEN, 4); });
  const validRecord = () => ({ id: 5, userId: 7, uuid: 'tok-uuid', tokenHash, email: 'ana@test.cl', expiresAt: new Date(Date.now() + 60_000), usedAt: null });

  describe('ExecuteRequestReset', () => {
    const cmd = { correo: 'ana@test.cl', ip: '1.1.1.1', userAgent: 'jest' };

    it('con un correo inexistente responde el mensaje genérico y no crea token', async () => {
      const { uc, resetRepo } = setup();
      await expect(uc.ExecuteRequestReset(cmd)).resolves.toEqual({ message: GENERIC });
      expect(resetRepo.createResetToken).not.toHaveBeenCalled();
    });

    it('DOCUMENTA (filtración): un usuario inactivo recibe error distinto al genérico, lo que revela que el correo existe', async () => {
      const { uc } = setup({ contacto: { usuario: { id: 7, activo: false } } });
      await expect(uc.ExecuteRequestReset(cmd)).rejects.toBeInstanceOf(BadRequestException);
    });

    it('con un usuario activo borra tokens previos y guarda uno nuevo hasheado que expira en ~1 hora', async () => {
      const { uc, resetRepo } = setup({ contacto: { usuario: { id: 7, activo: true } } });
      const before = Date.now();
      await expect(uc.ExecuteRequestReset(cmd)).resolves.toEqual({ message: GENERIC });

      expect(resetRepo.deleteUserTokens).toHaveBeenCalledWith(7);
      const [userId, correo, hash, expiresAt, ip, ua] = resetRepo.createResetToken.mock.calls[0];
      expect([userId, correo, ip, ua]).toEqual([7, 'ana@test.cl', '1.1.1.1', 'jest']);
      expect(hash).toMatch(/^\$2[aby]\$/);
      expect(expiresAt.getTime() - before).toBeGreaterThan(59 * 60_000);
      expect(expiresAt.getTime() - before).toBeLessThanOrEqual(61 * 60_000);
    });

    it('la misma respuesta para correo existente e inexistente (anti-enumeración por cuerpo)', async () => {
      const a = await setup().uc.ExecuteRequestReset(cmd);
      const b = await setup({ contacto: { usuario: { id: 7, activo: true } } }).uc.ExecuteRequestReset(cmd);
      expect(a).toEqual(b);
    });
  });

  describe('ExecuteValidateResetToken', () => {
    const cmd = (token = TOKEN) => ({ token, uuid: 'tok-uuid' });

    it('token no encontrado o vencido → valid:false', async () => {
      await expect(setup().uc.ExecuteValidateResetToken(cmd())).resolves.toEqual({ valid: false });
    });

    it('token que no coincide con el hash → valid:false', async () => {
      const { uc } = setup({ resetToken: validRecord() });
      await expect(uc.ExecuteValidateResetToken(cmd('otro-token'))).resolves.toEqual({ valid: false });
    });

    it('token correcto → valid:true con el correo asociado', async () => {
      const { uc } = setup({ resetToken: validRecord() });
      await expect(uc.ExecuteValidateResetToken(cmd())).resolves.toEqual({ valid: true, email: 'ana@test.cl' });
    });
  });

  describe('ExecuteResetPassword', () => {
    const cmd = (o: any = {}) => ({ token: TOKEN, uuid: 'tok-uuid', newPassword: 'Nueva#1234', confirmPassword: 'Nueva#1234', ...o });

    it('rechaza si las contraseñas no coinciden, sin consultar el token', async () => {
      const { uc, resetRepo } = setup({ resetToken: validRecord() });
      await expect(uc.ExecuteResetPassword(cmd({ confirmPassword: 'distinta' }))).rejects.toThrow(/no coinciden/);
      expect(resetRepo.findValidToken).not.toHaveBeenCalled();
    });

    it('rechaza un token inexistente/vencido', async () => {
      await expect(setup().uc.ExecuteResetPassword(cmd())).rejects.toThrow(/inválido o expirado/);
    });

    it('rechaza un token que no coincide con el hash y no cambia la contraseña', async () => {
      const { uc, usuarioRepo } = setup({ resetToken: validRecord() });
      await expect(uc.ExecuteResetPassword(cmd({ token: 'otro' }))).rejects.toBeInstanceOf(BadRequestException);
      expect(usuarioRepo.updatePassword).not.toHaveBeenCalled();
    });

    it('rechaza si el usuario del token ya no existe', async () => {
      const { uc, usuarioRepo } = setup({ resetToken: validRecord(), usuario: null });
      await expect(uc.ExecuteResetPassword(cmd())).rejects.toThrow(/Usuario no encontrado/);
      expect(usuarioRepo.updatePassword).not.toHaveBeenCalled();
    });

    it('con token válido guarda el hash bcrypt de la nueva contraseña, marca el token usado y revoca las sesiones', async () => {
      const { uc, usuarioRepo, resetRepo, sessionsRepo } = setup({ resetToken: validRecord() });
      await expect(uc.ExecuteResetPassword(cmd())).resolves.toEqual({ message: 'Contraseña restablecida exitosamente' });

      const [userId, hash] = usuarioRepo.updatePassword.mock.calls[0];
      expect(userId).toBe(7);
      expect(hash).not.toBe('Nueva#1234');
      expect(await bcrypt.compare('Nueva#1234', hash)).toBe(true);
      expect(resetRepo.markTokenAsUsed).toHaveBeenCalledWith(5);
      expect(sessionsRepo.revokeAllUserSessions).toHaveBeenCalledWith('7');
    });
  });
});
