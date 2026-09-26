import { Injectable, Logger } from '@nestjs/common';
import { IEmailService } from '../../core/domain/puertos/outbound/IEmailService.interface';
import { maskEmail } from '../../core/share/log-sanitizer';

/**
 * ConsoleEmailAdapter — adaptador temporal sin servidor de correo.
 *
 * Imprime el código en los logs del servicio (visible en `docker compose logs ms-identity`).
 * Cuando el servidor de correo esté disponible, crear SmtpEmailAdapter / SendGridEmailAdapter
 * e intercambiarlo en el módulo sin modificar ningún use case.
 *
 * Para desarrollo local, también puede leerse desde:
 *   GET /auth/dev/ultimo-codigo?email=... (solo si NODE_ENV !== 'production')
 */
@Injectable()
export class ConsoleEmailAdapter implements IEmailService {
    private readonly logger = new Logger('📧 EmailService');

    /** En producción no hay servidor de correo: avisar sin volcar secretos al log. */
    private get isProduction(): boolean {
        return process.env.NODE_ENV === 'production';
    }

    async sendPasswordResetLink(email: string, resetUrl: string, nombre: string): Promise<void> {
        if (this.isProduction) {
            this.logger.warn(`Correo de restablecimiento NO enviado a ${maskEmail(email)}: no hay adaptador de correo real configurado.`);
            return;
        }
        this.logger.log('═══════════════════════════════════════════════');
        this.logger.log(`  RESTABLECER CONTRASEÑA (modo consola)`);
        this.logger.log(`  Para:    ${email}`);
        this.logger.log(`  Nombre:  ${nombre}`);
        this.logger.log(`  Enlace:  ${resetUrl}`);
        this.logger.log(`  Expira:  1 hora`);
        this.logger.log('═══════════════════════════════════════════════');
    }

    async sendPasswordChangedNotice(email: string, nombre: string): Promise<void> {
        this.logger.log(`Aviso de cambio de contraseña (modo consola) para ${email} (${nombre}).`);
    }

    async sendVerificationCode(email: string, code: string, nombre: string): Promise<void> {
        if (this.isProduction) {
            this.logger.warn(`Código de verificación NO enviado a ${maskEmail(email)}: no hay adaptador de correo real configurado.`);
            return;
        }
        this.logger.log('═══════════════════════════════════════════════');
        this.logger.log(`  VERIFICACIÓN DE CORREO (modo consola)`);
        this.logger.log(`  Para:    ${email}`);
        this.logger.log(`  Nombre:  ${nombre}`);
        this.logger.log(`  Código:  ${code}`);
        this.logger.log(`  Expira:  10 minutos`);
        this.logger.log('═══════════════════════════════════════════════');
    }
}
