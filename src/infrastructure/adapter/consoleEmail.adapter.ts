import { Injectable, Logger } from '@nestjs/common';
import { IEmailService } from '../../core/domain/puertos/outbound/IEmailService.interface';

/**
 * ConsoleEmailAdapter — adaptador temporal sin servidor de correo.
 *
 * Imprime el código en los logs del servicio (visible en `docker compose logs ms-auth`).
 * Cuando el servidor de correo esté disponible, crear SmtpEmailAdapter / SendGridEmailAdapter
 * e intercambiarlo en el módulo sin modificar ningún use case.
 *
 * Para desarrollo local, también puede leerse desde:
 *   GET /auth/dev/ultimo-codigo?email=... (solo si NODE_ENV !== 'production')
 */
@Injectable()
export class ConsoleEmailAdapter implements IEmailService {
    private readonly logger = new Logger('📧 EmailService');

    async sendVerificationCode(email: string, code: string, nombre: string): Promise<void> {
        this.logger.log('═══════════════════════════════════════════════');
        this.logger.log(`  VERIFICACIÓN DE CORREO (modo consola)`);
        this.logger.log(`  Para:    ${email}`);
        this.logger.log(`  Nombre:  ${nombre}`);
        this.logger.log(`  Código:  ${code}`);
        this.logger.log(`  Expira:  10 minutos`);
        this.logger.log('═══════════════════════════════════════════════');
    }
}
