import { formRegistroData } from "src/core/domain/model/dataRegistro.model";
import { RegistroContactoModel } from "src/core/domain/model/registroContacto.model";
import { IRegistroUseCase } from "src/core/domain/puertos/inbound/IRegistro.usecase.interface";
import { IContactoRepository } from "src/core/domain/puertos/outbound/iContactoRepository.interface";
import { IUsuarioRepository } from "src/core/domain/puertos/outbound/iUsuarioRepository.interface";
import { ICacheRepository } from "src/core/domain/puertos/outbound/CacheRepository.interface";
import { IEmailService } from "src/core/domain/puertos/outbound/IEmailService.interface";
import { RegistroUsuarioModel } from "src/core/domain/model/registroUsuario.model";
import { Logger, OnModuleDestroy } from "@nestjs/common";
import { BackgroundTasks } from "src/core/share/background-tasks";
import { maskEmail } from "src/core/share/log-sanitizer";
import * as bcrypt from 'bcrypt';
import { IRolRepository } from "src/core/domain/puertos/outbound/iRolRepository.interface";
import { rolEnum } from "src/core/domain/model/constantes.model";

const BCRYPT_ROUNDS = 10;
const VERIFICATION_CODE_TTL_MIN = 10;
/** Intentos fallidos permitidos por código: con 6 dígitos, sin tope se adivina por fuerza bruta. */
export const MAX_OTP_ATTEMPTS = 5;

export class RegistroUseCaseImpl implements IRegistroUseCase, OnModuleDestroy {
    private readonly logger = new Logger(RegistroUseCaseImpl.name);
    private readonly background = new BackgroundTasks(this.logger);

    constructor(
        private readonly usuarioRepository: IUsuarioRepository,
        private readonly contactoRepository: IContactoRepository,
        private readonly cacheRepository: ICacheRepository,
        private readonly emailService: IEmailService,
        private readonly rolRepository: IRolRepository
    ) { }

    async executeCreateRegistro(data: formRegistroData): Promise<{ success: boolean; message?: string; }> {
        let idContacto: number | null = null;

        try {
            const contactoModel: RegistroContactoModel = {
                nombres: data.nombres,
                apellidoPaterno: data.apellidoPaterno,
                apellidoMaterno: data.apellidoMaterno,
                direccion: data.direccion,
                celular: data.telefono.getValue(),
                correo: data.email.getValue(),
                tipoDocumento: data.tipoDocumento.getValue(),
                numeroDocumento: data.numeroDocumento.getValue(),
                pais_emision: data.pais,
                fechaNacimiento: data.fechaNacimiento,
                tipoContacto: 1
            };

            idContacto = await this.contactoRepository.create(contactoModel);
            const passwordHash = await bcrypt.hash(data.password.getValue(), BCRYPT_ROUNDS);

            const registroUsuarioModel: RegistroUsuarioModel = {
                username: data.username,
                passwordHash,
                contactoid: idContacto
            };

            const { usuarioUuid } = await this.usuarioRepository.createUsuario(registroUsuarioModel);
            if (!usuarioUuid) throw new Error('No se pudo crear el usuario');

            // Generar el código de 6 dígitos, guardarlo hasheado y enviarlo (consola ahora, SMTP/SendGrid después).
            // Aquí se espera: si falla, el alta entera se revierte (rollback del contacto).
            await this.storeAndSendVerificationCode(usuarioUuid, data.email.getValue(), data.nombres);

            this.logger.log(`[REGISTRO] Código de verificación generado | userUuid=${usuarioUuid} | TTL=${VERIFICATION_CODE_TTL_MIN}min`);
            return { success: true };

        } catch (error: any) {
            if (idContacto) {
                try {
                    await this.contactoRepository.delete(idContacto);
                    this.logger.warn(`Rollback aplicado: contacto eliminado | contactoId=${idContacto}`);
                } catch (rollbackError: any) {
                    this.logger.error(`Fallo rollback de contacto | contactoId=${idContacto} | reason=${rollbackError?.message ?? rollbackError}`);
                }
            }
            this.logger.error(`Error en executeCreateRegistro | reason=${error?.message ?? error}`);
            return { success: false, message: 'Error al crear el registro' };
        }
    }

    async executeVerificarEmail(email: string, code: string): Promise<{ success: boolean; message?: string }> {
        const usuario = await this.usuarioRepository.getUsuarioByEmail(email);
        if (!usuario) {
            return { success: false, message: 'Código expirado o inexistente. Solicita uno nuevo.' };
        }
        if (usuario.emailVerificado) {
            return { success: true };
        }

        const storedHash = await this.cacheRepository.getEmailVerificationCode(usuario.uuid);
        if (!storedHash) {
            return { success: false, message: 'Código expirado o inexistente. Solicita uno nuevo.' };
        }

        const isValid = await bcrypt.compare(code, storedHash);
        if (!isValid) {
            const attempts = await this.cacheRepository.incrementEmailVerificationAttempts(usuario.uuid);
            if (attempts >= MAX_OTP_ATTEMPTS) {
                // Invalidar el código: el atacante debe pedir uno nuevo (y eso también está limitado por petición).
                await this.cacheRepository.deleteEmailVerificationCode(usuario.uuid);
                await this.cacheRepository.clearEmailVerificationAttempts(usuario.uuid);
                this.logger.warn(`[VERIFICACION_EMAIL] CODIGO_INVALIDADO_POR_INTENTOS userUuid=${usuario.uuid}`);
                return { success: false, message: 'Demasiados intentos incorrectos. Solicita un código nuevo.' };
            }
            return { success: false, message: 'Código incorrecto.' };
        }

        await this.usuarioRepository.marcarEmailVerificado(usuario.uuid);
        await this.cacheRepository.deleteEmailVerificationCode(usuario.uuid);
        await this.cacheRepository.clearEmailVerificationAttempts(usuario.uuid);
        await this.rolRepository.setRolInicial(usuario.id, rolEnum.CEDENTE); // Asignar rol inicial (ajustar según tipo de usuario)
        this.logger.log(`[VERIFICACION_EMAIL] SUCCESS userUuid=${usuario.uuid}`);
        return { success: true };
    }

    async ExecuteValidateField(field: string, value: string): Promise<{ available: boolean; message?: string }> {
        return await this.usuarioRepository.validateField(field, value);
    }

    /**
     * Anti-enumeración (mismo criterio que password-reset/request): responde SIEMPRE éxito y en el mismo tiempo,
     * sea el correo desconocido, ya verificado o pendiente. Antes de responder solo se hace la búsqueda del usuario;
     * el bcrypt, la caché y el envío corren en segundo plano y solo para cuentas pendientes de verificar.
     */
    async executeResendOtp(email: string): Promise<{ success: boolean; message?: string }> {
        const usuario = await this.usuarioRepository.getUsuarioByEmail(email);
        if (!usuario || usuario.emailVerificado) {
            this.logger.warn(`[RESEND_OTP] SIN_ENVIO email=${maskEmail(email)} motivo=${usuario ? 'YA_VERIFICADO' : 'DESCONOCIDO'}`);
            return { success: true };
        }

        this.background.run(`RESEND_OTP userUuid=${usuario.uuid}`, async () => {
            await this.storeAndSendVerificationCode(usuario.uuid, email, usuario.nombres);
            this.logger.log(`[RESEND_OTP] Código reenviado | userUuid=${usuario.uuid}`);
        });
        return { success: true };
    }

    /** Espera al trabajo en segundo plano (pruebas y apagado ordenado). */
    whenIdle(): Promise<void> {
        return this.background.whenIdle();
    }

    /** Al apagar, no perder códigos que aún se estén enviando. */
    async onModuleDestroy(): Promise<void> {
        await this.whenIdle();
    }

    /** Código nuevo: se guarda hasheado, se reinicia el contador de intentos y se envía por correo. */
    private async storeAndSendVerificationCode(userUuid: string, email: string, nombres: string): Promise<void> {
        const code = this.generateVerificationCode();
        const codeHash = await bcrypt.hash(code, BCRYPT_ROUNDS);
        await this.cacheRepository.setEmailVerificationCode(userUuid, codeHash);
        await this.cacheRepository.clearEmailVerificationAttempts(userUuid);
        await this.emailService.sendVerificationCode(email, code, nombres);
    }

    private generateVerificationCode(): string {
        // Código de 6 dígitos criptográficamente seguro
        const buffer = require('crypto').randomBytes(3);
        const code = (parseInt(buffer.toString('hex'), 16) % 1_000_000).toString().padStart(6, '0');
        return code;
    }
}