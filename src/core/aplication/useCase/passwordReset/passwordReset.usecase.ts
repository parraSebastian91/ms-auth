import { BadRequestException, Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { IPasswordResetUseCase } from 'src/core/domain/puertos/inbound/IPasswordResetUseCase.interface';
import { IContactoRepository } from 'src/core/domain/puertos/outbound/iContactoRepository.interface';
import { IEmailService } from 'src/core/domain/puertos/outbound/IEmailService.interface';
import { IPasswordResetRepository } from 'src/core/domain/puertos/outbound/IPasswordResetRepository.interface';
import { maskEmail } from 'src/core/share/log-sanitizer';
import { IUsuarioRepository } from './../../../domain/puertos/outbound/iUsuarioRepository.interface';
import { AuthAplicationService } from './../../service/auth.service';
import {
  RequestPasswordResetCommand,
  ResetPasswordCommand,
  validateResetTokenCommand,
} from './../auth/command/AuthCommand.interface';

/** Recuperación de contraseña: solicitar enlace, validar token y restablecer. */
@Injectable()
export class PasswordResetUseCase implements IPasswordResetUseCase, OnModuleDestroy {
  private readonly logger = new Logger(PasswordResetUseCase.name);
  private readonly pending = new Set<Promise<void>>();

  constructor(
    private usuarioRepository: IUsuarioRepository,
    private contactoRepository: IContactoRepository,
    private passwordResetRepo: IPasswordResetRepository,
    private authService: AuthAplicationService,
    private emailService: IEmailService,
    private options: { frontendUrl: string },
  ) {}

  /**
   * Responde SIEMPRE lo mismo y en el mismo tiempo, exista o no el correo. Lo único que se hace antes de responder
   * es la búsqueda del contacto (igual en ambos casos); el trabajo costoso —borrar tokens, bcrypt, guardar el token
   * y enviar el correo— corre en segundo plano solo para cuentas activas. Así ni el cuerpo ni la duración de la
   * respuesta revelan si el correo está registrado. Errores del segundo plano se registran, no llegan al cliente.
   */
  async ExecuteRequestReset(
    command: RequestPasswordResetCommand,
  ): Promise<{ message: string }> {
    const requestId = command.requestId || 'N/A';
    this.logger.log(
      `[PASSWORD_RESET_REQUEST] INIT requestId=${requestId} email=${maskEmail(command.correo)}`,
    );
    const contacto = await this.contactoRepository.findByCorreo(command.correo);
    const genericResponse = {
      message: 'Si el correo existe, recibirás un enlace de restablecimiento',
    };

    if (!contacto) {
      this.logger.warn(
        `[PASSWORD_RESET_REQUEST] NON_EXISTENT_EMAIL requestId=${requestId} email=${maskEmail(command.correo)}`,
      );
      return genericResponse;
    }

    if (!contacto.usuario.activo) {
      this.logger.warn(
        `[PASSWORD_RESET_REQUEST] INACTIVE_USER requestId=${requestId} email=${maskEmail(command.correo)}`,
      );
      return genericResponse;
    }

    this.runInBackground(`PASSWORD_RESET_REQUEST requestId=${requestId}`, () =>
      this.issueResetToken(command, contacto, requestId),
    );
    return genericResponse;
  }

  /** Espera a que termine el trabajo en segundo plano (pruebas y apagado ordenado). */
  async whenIdle(): Promise<void> {
    while (this.pending.size > 0) await Promise.allSettled([...this.pending]);
  }

  /** Al apagar, no perder correos de restablecimiento que aún se estén emitiendo. */
  async onModuleDestroy(): Promise<void> {
    await this.whenIdle();
  }

  private runInBackground(label: string, task: () => Promise<void>): void {
    const promise: Promise<void> = task()
      .catch((error: any) => this.logger.error(`[${label}] BACKGROUND_FAILED: ${error?.message ?? error}`))
      .finally(() => this.pending.delete(promise));
    this.pending.add(promise);
  }

  private async issueResetToken(command: RequestPasswordResetCommand, contacto: any, requestId: string): Promise<void> {
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
    const resetUrl = `${this.options.frontendUrl}/pages/restablecer-password?token=${token}&uuid=${tokenUuid}`;

    // El envío es "mejor esfuerzo": el adaptador concreto (SMTP, SES, ...) se conecta por el puerto IEmailService.
    try {
      await this.emailService.sendPasswordResetLink(command.correo, resetUrl, contacto.nombres ?? contacto.usuario.userName);
    } catch (error: any) {
      this.logger.error(
        `[PASSWORD_RESET_REQUEST] EMAIL_SEND_FAILED requestId=${requestId} tokenUuid=${tokenUuid}: ${error?.message ?? error}`,
      );
    }

    this.logger.log(
      `[PASSWORD_RESET_REQUEST] TOKEN_CREATED requestId=${requestId} email=${maskEmail(command.correo)} tokenUuid=${tokenUuid} expiresAt=${expiresAt.toISOString()}`,
    );
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

    // Cerrar TODAS las sesiones: refresh tokens en BD y access tokens en caché, para que una cuenta
    // comprometida no siga entrando con un JWT ya emitido hasta que expire.
    await this.authService.revokeAllUserSessions(resetToken.userId);

    // Aviso al usuario (mejor esfuerzo): la contraseña ya cambió, un fallo de correo no debe deshacerlo.
    try {
      await this.emailService.sendPasswordChangedNotice(resetToken.email, usuario.userName);
    } catch (error: any) {
      this.logger.error(`[RESET_PASSWORD] NOTICE_SEND_FAILED requestId=${requestId}: ${error?.message ?? error}`);
    }
    this.logger.log(
      `[RESET_PASSWORD] SUCCESS requestId=${requestId} userUuid=${usuario.uuid}`,
    );

    return {
      message: 'Contraseña restablecida exitosamente',
    };
  }
}
