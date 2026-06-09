import { formRegistroData } from "src/core/domain/model/dataRegistro.model";
import { RegistroContactoModel } from "src/core/domain/model/registroContacto.model";
import { IRegistroUseCase } from "src/core/domain/puertos/inbound/IRegistro.usecase.interface";
import { IContactoRepository } from "src/core/domain/puertos/outbound/iContactoRepository.interface";
import { IUsuarioRepository } from "src/core/domain/puertos/outbound/iUsuarioRepository.interface";
import { ICacheRepository } from "src/core/domain/puertos/outbound/CacheRepository.interface";
import { IEmailService } from "src/core/domain/puertos/outbound/IEmailService.interface";
import { RegistroUsuarioModel } from "src/core/domain/model/registroUsuario.model";
import { Logger } from "@nestjs/common";
import * as bcrypt from 'bcrypt';
import { IRolRepository } from "src/core/domain/puertos/outbound/iRolRepository.interface";
import { rolEnum } from "src/core/domain/model/constantes.model";

const BCRYPT_ROUNDS = 10;
const VERIFICATION_CODE_TTL_MIN = 10;

export class RegistroUseCaseImpl implements IRegistroUseCase {
    private readonly logger = new Logger(RegistroUseCaseImpl.name);

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

            // Generar código de 6 dígitos y almacenarlo hasheado en Redis
            const code = this.generateVerificationCode();
            const codeHash = await bcrypt.hash(code, BCRYPT_ROUNDS);
            await this.cacheRepository.setEmailVerificationCode(usuarioUuid, codeHash);

            // Enviar código (consola ahora, SMTP/SendGrid en producción)
            await this.emailService.sendVerificationCode(
                data.email.getValue(),
                code,
                data.nombres
            );

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
            return { success: false, message: 'Código incorrecto.' };
        }

        await this.usuarioRepository.marcarEmailVerificado(usuario.uuid);
        await this.cacheRepository.deleteEmailVerificationCode(usuario.uuid);
        await this.rolRepository.setRolInicial(usuario.id, rolEnum.CEDENTE); // Asignar rol inicial (ajustar según tipo de usuario)
        this.logger.log(`[VERIFICACION_EMAIL] SUCCESS userUuid=${usuario.uuid}`);
        return { success: true };
    }

    async ExecuteValidateField(field: string, value: string): Promise<{ available: boolean; message?: string }> {
        return await this.usuarioRepository.validateField(field, value);
    }

    async executeResendOtp(email: string): Promise<{ success: boolean; message?: string }> {
        const usuario = await this.usuarioRepository.getUsuarioByEmail(email);
        if (!usuario) {
            // No revelar si el email existe o no (evita enumeración)
            return { success: true };
        }
        if (usuario.emailVerificado) {
            return { success: false, message: 'Este correo ya fue verificado.' };
        }

        const code = this.generateVerificationCode();
        const codeHash = await bcrypt.hash(code, BCRYPT_ROUNDS);
        await this.cacheRepository.setEmailVerificationCode(usuario.uuid, codeHash);
        await this.emailService.sendVerificationCode(email, code, usuario.nombres);

        this.logger.log(`[RESEND_OTP] Código reenviado | userUuid=${usuario.uuid}`);
        return { success: true };
    }

    private generateVerificationCode(): string {
        // Código de 6 dígitos criptográficamente seguro
        const buffer = require('crypto').randomBytes(3);
        const code = (parseInt(buffer.toString('hex'), 16) % 1_000_000).toString().padStart(6, '0');
        return code;
    }
}