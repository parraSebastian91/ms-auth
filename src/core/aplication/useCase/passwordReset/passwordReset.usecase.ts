import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { IPasswordResetUseCase } from 'src/core/domain/puertos/inbound/IPasswordResetUseCase.interface';
import { IContactoRepository } from 'src/core/domain/puertos/outbound/iContactoRepository.interface';
import { IPasswordResetRepository } from 'src/core/domain/puertos/outbound/IPasswordResetRepository.interface';
import { IRefreshSessionRepository } from 'src/core/domain/puertos/outbound/iRefreshSessionRepository.interface';
import { IUsuarioRepository } from './../../../domain/puertos/outbound/iUsuarioRepository.interface';
import {
  RequestPasswordResetCommand,
  ResetPasswordCommand,
  validateResetTokenCommand,
} from './../auth/command/AuthCommand.interface';

/** Recuperación de contraseña: solicitar enlace, validar token y restablecer. */
@Injectable()
export class PasswordResetUseCase implements IPasswordResetUseCase {
  private readonly logger = new Logger(PasswordResetUseCase.name);

  constructor(
    private usuarioRepository: IUsuarioRepository,
    private contactoRepository: IContactoRepository,
    private passwordResetRepo: IPasswordResetRepository,
    private refreshSessionRepo: IRefreshSessionRepository,
  ) {}

  async ExecuteRequestReset(
    command: RequestPasswordResetCommand,
  ): Promise<{ message: string }> {
    const requestId = command.requestId || 'N/A';
    this.logger.log(
      `[PASSWORD_RESET_REQUEST] INIT requestId=${requestId} email=${command.correo}`,
    );
    const contacto = await this.contactoRepository.findByCorreo(command.correo);

    if (!contacto) {
      // Por seguridad, no revelar si el email existe o no
      this.logger.warn(
        `[PASSWORD_RESET_REQUEST] NON_EXISTENT_EMAIL requestId=${requestId} email=${command.correo}`,
      );
      return {
        message: 'Si el correo existe, recibirás un enlace de restablecimiento',
      };
    }

    if (!contacto.usuario.activo) {
      this.logger.warn(
        `[PASSWORD_RESET_REQUEST] INACTIVE_USER requestId=${requestId} email=${command.correo}`,
      );
      throw new BadRequestException('Usuario inactivo');
    }

    // Eliminar tokens anteriores del usuario
    await this.passwordResetRepo.deleteUserTokens(contacto.usuario.id);

    // Generar token único
    const token = randomBytes(48).toString('hex');
    const tokenHash = await bcrypt.hash(token, 10);

    // Token válido por 1 hora
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

    // Guardar token en BD
    const { tokenUuid } = await this.passwordResetRepo.createResetToken(
      contacto.usuario.id,
      command.correo,
      tokenHash,
      expiresAt,
      command.ip,
      command.userAgent,
    );

    // Construir URL de restablecimiento
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:8000'}/pages/restablecer-password?token=${token}&uuid=${tokenUuid}`;

    // TODO: Enviar email con el enlace
    // await this.emailService.sendPasswordResetEmail(email, resetUrl, contacto.usuario.username);

    this.logger.log(
      `[PASSWORD_RESET_REQUEST] TOKEN_CREATED requestId=${requestId} email=${command.correo} tokenUuid=${tokenUuid} expiresAt=${expiresAt.toISOString()}`,
    );

    return {
      message: 'Si el correo existe, recibirás un enlace de restablecimiento',
    };
  }

  async ExecuteValidateResetToken(
    command: validateResetTokenCommand,
  ): Promise<{ valid: boolean; email?: string }> {
    const requestId = command.requestId || 'N/A';
    this.logger.log(
      `[PASSWORD_RESET_VALIDATE] INIT requestId=${requestId} tokenUuid=${command.uuid}`,
    );
    const resetToken = await this.passwordResetRepo.findValidToken(
      command.uuid,
    );
    if (!resetToken) {
      this.logger.warn(
        `[PASSWORD_RESET_VALIDATE] TOKEN_NOT_FOUND requestId=${requestId} tokenUuid=${command.uuid}`,
      );
      return { valid: false };
    }

    const ok = await bcrypt.compare(command.token, resetToken.tokenHash);
    if (!ok) {
      this.logger.warn(
        `[PASSWORD_RESET_VALIDATE] TOKEN_MISMATCH requestId=${requestId} tokenUuid=${command.uuid}`,
      );
      return { valid: false };
    }

    this.logger.log(
      `[PASSWORD_RESET_VALIDATE] SUCCESS requestId=${requestId} tokenUuid=${command.uuid}`,
    );
    return { valid: true, email: resetToken.email };
  }

  async ExecuteResetPassword(
    command: ResetPasswordCommand,
  ): Promise<{ message: string }> {
    const requestId = command.requestId || 'N/A';
    this.logger.log(
      `[RESET_PASSWORD] INIT requestId=${requestId} tokenUuid=${command.uuid}`,
    );
    if (command.newPassword !== command.confirmPassword) {
      this.logger.warn(
        `[RESET_PASSWORD] PASSWORD_MISMATCH requestId=${requestId} tokenUuid=${command.uuid}`,
      );
      throw new BadRequestException('Las contraseñas no coinciden');
    }

    // Validar token
    const resetToken = await this.passwordResetRepo.findValidToken(
      command.uuid,
    );
    if (!resetToken) {
      this.logger.warn(
        `[RESET_PASSWORD] TOKEN_NOT_FOUND requestId=${requestId} tokenUuid=${command.uuid}`,
      );
      throw new BadRequestException('Token inválido o expirado');
    }

    const ok = await bcrypt.compare(command.token, resetToken.tokenHash);
    if (!ok) {
      this.logger.warn(
        `[RESET_PASSWORD] INVALID_TOKEN requestId=${requestId} tokenUuid=${command.uuid}`,
      );

      throw new BadRequestException('Token inválido o expirado');
    }

    // Hash de la nueva contraseña
    const passwordHash = await bcrypt.hash(command.newPassword, 10);

    const usuario = await this.usuarioRepository.getUsuarioById(
      resetToken.userId,
    );

    if (!usuario) {
      this.logger.error(
        `[RESET_PASSWORD] USER_NOT_FOUND requestId=${requestId} userId=${resetToken.userId}`,
      );
      throw new BadRequestException('Usuario no encontrado');
    }

    // Actualizar solo el password sin afectar las relaciones
    await this.usuarioRepository.updatePassword(
      resetToken.userId,
      passwordHash,
    );

    // Marcar token como usado
    await this.passwordResetRepo.markTokenAsUsed(resetToken.id);

    // TODO: Enviar email de confirmación
    // await this.emailService.sendPasswordChangedConfirmation(resetToken.email);

    // Invalidar todas las sesiones del usuario (opcional pero recomendado)
    await this.refreshSessionRepo.revokeAllUserSessions(
      usuario.id.getValue().toString(),
    );
    this.logger.log(
      `[RESET_PASSWORD] SUCCESS requestId=${requestId} userUuid=${usuario.uuid}`,
    );

    return {
      message: 'Contraseña restablecida exitosamente',
    };
  }
}
