import { BadRequestException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PasswordResetUseCase } from './passwordReset.usecase';

const GENERIC = 'Si el correo existe, recibirás un enlace de restablecimiento';
const activeContacto = { nombres: 'Ana', usuario: { id: 7, activo: true, userName: 'ana' } };
const TOKEN = 'token-plano-de-prueba';

function setup(o: { contacto?: any; resetToken?: any; usuario?: any } = {}) {
  const usuarioRepo: any = {
    getUsuarioById: jest.fn().mockResolvedValue(o.usuario === undefined ? { id: { getValue: () => 7 }, uuid: 'u-1', userName: 'ana' } : o.usuario),
    updatePassword: jest.fn().mockResolvedValue(undefined),
  };
  const contactoRepo: any = { findByCorreo: jest.fn().mockResolvedValue(o.contacto ?? null) };
  const resetRepo: any = {
    deleteUserTokens: jest.fn().mockResolvedValue(undefined),
    createResetToken: jest.fn().mockResolvedValue({ tokenUuid: 'tok-uuid' }),
    findValidToken: jest.fn().mockResolvedValue(o.resetToken ?? null),
    markTokenAsUsed: jest.fn().mockResolvedValue(undefined),
  };
  const authService: any = { revokeAllUserSessions: jest.fn().mockResolvedValue({ revoked: 2, cacheCleared: 2, cacheFailed: 0 }) };
  const emailService: any = {
    sendPasswordResetLink: jest.fn().mockResolvedValue(undefined),
    sendPasswordChangedNotice: jest.fn().mockResolvedValue(undefined),
  };
  const uc = new PasswordResetUseCase(usuarioRepo, contactoRepo, resetRepo, authService, emailService, { frontendUrl: 'https://app.test' });
  return { uc, usuarioRepo, contactoRepo, resetRepo, authService, emailService };
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

    it('un usuario inactivo recibe el mismo mensaje genérico y no se crea token (no revela el estado de la cuenta)', async () => {
      const { uc, resetRepo } = setup({ contacto: { usuario: { id: 7, activo: false } } });
      await expect(uc.ExecuteRequestReset(cmd)).resolves.toEqual({ message: GENERIC });
      expect(resetRepo.createResetToken).not.toHaveBeenCalled();
      expect(resetRepo.deleteUserTokens).not.toHaveBeenCalled();
    });

    it('con un usuario activo borra tokens previos y guarda uno nuevo hasheado que expira en ~1 hora', async () => {
      const { uc, resetRepo } = setup({ contacto: activeContacto });
      const before = Date.now();
      await expect(uc.ExecuteRequestReset(cmd)).resolves.toEqual({ message: GENERIC });

      expect(resetRepo.deleteUserTokens).toHaveBeenCalledWith(7);
      const [userId, correo, hash, expiresAt, ip, ua] = resetRepo.createResetToken.mock.calls[0];
      expect([userId, correo, ip, ua]).toEqual([7, 'ana@test.cl', '1.1.1.1', 'jest']);
      expect(hash).toMatch(/^\$2[aby]\$/);
      expect(expiresAt.getTime() - before).toBeGreaterThan(59 * 60_000);
      expect(expiresAt.getTime() - before).toBeLessThanOrEqual(61 * 60_000);
    });

    it('envía por correo un enlace cuyo token corresponde al hash guardado', async () => {
      const { uc, resetRepo, emailService } = setup({ contacto: activeContacto });
      await uc.ExecuteRequestReset(cmd);

      expect(emailService.sendPasswordResetLink).toHaveBeenCalledTimes(1);
      const [to, url, nombre] = emailService.sendPasswordResetLink.mock.calls[0];
      expect(to).toBe('ana@test.cl');
      expect(nombre).toBe('Ana');
      const link = new URL(url);
      expect(link.origin + link.pathname).toBe('https://app.test/pages/restablecer-password');
      expect(link.searchParams.get('uuid')).toBe('tok-uuid');
      const storedHash = resetRepo.createResetToken.mock.calls[0][2];
      expect(await bcrypt.compare(link.searchParams.get('token')!, storedHash)).toBe(true);
    });

    it('no envía correo si el correo no existe o la cuenta está inactiva', async () => {
      const a = setup();
      await a.uc.ExecuteRequestReset(cmd);
      const b = setup({ contacto: { usuario: { id: 7, activo: false } } });
      await b.uc.ExecuteRequestReset(cmd);
      expect(a.emailService.sendPasswordResetLink).not.toHaveBeenCalled();
      expect(b.emailService.sendPasswordResetLink).not.toHaveBeenCalled();
    });

    it('si el envío falla no cambia la respuesta (no revelar que el correo existe) ni lanza', async () => {
      const { uc, emailService } = setup({ contacto: activeContacto });
      emailService.sendPasswordResetLink.mockRejectedValue(new Error('SMTP caído'));
      await expect(uc.ExecuteRequestReset(cmd)).resolves.toEqual({ message: GENERIC });
    });

    it('la misma respuesta para correo inexistente, inactivo y activo (anti-enumeración por cuerpo)', async () => {
      const a = await setup().uc.ExecuteRequestReset(cmd);
      const b = await setup({ contacto: activeContacto }).uc.ExecuteRequestReset(cmd);
      const c = await setup({ contacto: { usuario: { id: 7, activo: false } } }).uc.ExecuteRequestReset(cmd);
      expect(a).toEqual(b);
      expect(a).toEqual(c);
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
      const { uc, usuarioRepo, resetRepo, authService } = setup({ resetToken: validRecord() });
      await expect(uc.ExecuteResetPassword(cmd())).resolves.toEqual({ message: 'Contraseña restablecida exitosamente' });

      const [userId, hash] = usuarioRepo.updatePassword.mock.calls[0];
      expect(userId).toBe(7);
      expect(hash).not.toBe('Nueva#1234');
      expect(await bcrypt.compare('Nueva#1234', hash)).toBe(true);
      expect(resetRepo.markTokenAsUsed).toHaveBeenCalledWith(5);
      expect(authService.revokeAllUserSessions).toHaveBeenCalledWith(7);
    });

    it('cierra las sesiones DESPUÉS de cambiar la contraseña y marcar el token', async () => {
      const { uc, usuarioRepo, resetRepo, authService } = setup({ resetToken: validRecord() });
      await uc.ExecuteResetPassword(cmd());
      const order = (m: jest.Mock) => m.mock.invocationCallOrder[0];
      expect(order(usuarioRepo.updatePassword)).toBeLessThan(order(authService.revokeAllUserSessions));
      expect(order(resetRepo.markTokenAsUsed)).toBeLessThan(order(authService.revokeAllUserSessions));
    });

    it('avisa al usuario del cambio, pero un fallo del correo no deshace el restablecimiento', async () => {
      const { uc, emailService } = setup({ resetToken: validRecord() });
      emailService.sendPasswordChangedNotice.mockRejectedValue(new Error('SMTP caído'));
      await expect(uc.ExecuteResetPassword(cmd())).resolves.toEqual({ message: 'Contraseña restablecida exitosamente' });
      expect(emailService.sendPasswordChangedNotice).toHaveBeenCalledWith('ana@test.cl', 'ana');
    });

    it('si no se pueden cerrar las sesiones en BD el error se propaga (no se da por bueno el reset)', async () => {
      const { uc, authService } = setup({ resetToken: validRecord() });
      authService.revokeAllUserSessions.mockRejectedValue(new Error('bd caída'));
      await expect(uc.ExecuteResetPassword(cmd())).rejects.toThrow('bd caída');
    });

    it('con token inválido no cierra sesiones ni envía avisos', async () => {
      const { uc, authService, emailService } = setup({ resetToken: validRecord() });
      await uc.ExecuteResetPassword(cmd({ token: 'otro' })).catch(() => undefined);
      expect(authService.revokeAllUserSessions).not.toHaveBeenCalled();
      expect(emailService.sendPasswordChangedNotice).not.toHaveBeenCalled();
    });
  });
});
