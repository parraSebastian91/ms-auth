import { IAuthUseCase } from "./../../../domain/puertos/inbound/IAuthUseCase.interface";
import { authorizationCommand, refreshSessionCommand, RequestPasswordResetCommand, ResetPasswordCommand, validateResetTokenCommand } from "./command/AuthCommand.interface";
import { IUsuarioRepository } from "./../../../domain/puertos/outbound/iUsuarioRepository.interface";

import * as bcrypt from 'bcrypt';
import { AuthAplicationService } from "./../../service/auth.service";
import { BadRequestException, Injectable, Logger, UnauthorizedException } from "@nestjs/common";
import { ICacheRepository } from "src/core/domain/puertos/outbound/CacheRepository.interface";
import { createHash, randomBytes } from "crypto";
import { validateQuery } from "./query/validate.query";
import { JwtService, JwtSignOptions } from "@nestjs/jwt";
import { IContactoRepository } from "src/core/domain/puertos/outbound/iContactoRepository.interface";
import { IPasswordResetRepository } from "src/core/domain/puertos/outbound/IPasswordResetRepository.interface";
import { IRefreshSessionRepository } from "src/core/domain/puertos/outbound/iRefreshSessionRepository.interface";

import { AuthenticationCommand } from "./command/AuthCommand.interface";
import { sessionHandler } from "../../model/application.model";
import { ConfigService } from "@nestjs/config";
import { AccessTokenPayload } from "src/core/domain/model/jwt.model";
import { UserNotFoundError } from "src/core/domain/errors/UserNotFound.error";
import { LoginError } from "src/core/domain/errors/LoginError.error";
import { InvalidcodeToken } from "src/core/domain/errors/InvalidCodeToken.error";

const COOKIES = {
    REFRESH: 'auth.refresh',
    SESSION: 'auth.session',
}

@Injectable()
export class AuthUseCase implements IAuthUseCase {
    private readonly logger = new Logger(AuthUseCase.name);
    constructor(
        private usuarioRepository: IUsuarioRepository,
        private contactoRepository: IContactoRepository,
        private passwordResetRepo: IPasswordResetRepository,
        private refreshSessionRepo: IRefreshSessionRepository,
        private authService: AuthAplicationService,
        private jwtService: JwtService,
        private cacheRepository: ICacheRepository,
        private configService: ConfigService
    ) { }

    async ExcuteAuthentication(command: AuthenticationCommand): Promise<{ code: string, url: string }[] | null> {
        const usuario = await this.usuarioRepository.getUsuarioByUsername(command.username);
        if (!usuario) {
            throw new UserNotFoundError("Usuario no encontrado");
        }
        if (!await bcrypt.compare(command.password, usuario.password)) {
            throw new LoginError("Usuario no encontrado o contraseña incorrecta");
        }
        const code = await this.authService.createAuthorizationCode(
            usuario,
            command.code_challenge,
            command.typeDevice,
            command.sessionId
        );

        const uris = await this.usuarioRepository
            .getSystemsByUsername(command.username)
            .then(data => {
                return data.map(item => {
                    return {
                        code: encodeURIComponent(code),
                        url: `${item.path}/validate?code=${encodeURIComponent(code)}`
                    }
                });
            });
        return uris;
    }

    async ExecuteAuthorization(command: authorizationCommand): Promise<{ accessToken: string, refreshToken: string } | null> {
        this.logger.log("INIT - EXCHANGE CODE FOR TOKEN");
        if (!command.code || command.code === '') throw new InvalidcodeToken("Código de autorización inválido");

        const stored = await this.cacheRepository.getAuthCode(command.code);
        if (!stored) throw new InvalidcodeToken("Código de autorización inválido");

        let hash = createHash('sha256').update(command.codeVerifier).digest();
        const computedChallenge = hash.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

        if (computedChallenge !== stored.codeChallenge) {
            throw new InvalidcodeToken("Code verifier inválido (PKCE)");
        }

        if (stored.typeDevice !== command.typeDevice) {
            throw new InvalidcodeToken("Tipo de dispositivo no coincide");
        }
        stored.sessionId = command.sessionId;

        this.cacheRepository.deleteAuthCode(command.sessionId);
        return await this.authService.createRefreshSession(stored);
    }

    async ExecuteValidateSession(command: validateQuery): Promise<boolean> {
        const session = await this.cacheRepository.getAccessToken(command.sessionId);
        if (!session) {
            this.logger.error('No se encontró sesión en la solicitud');
            throw new UnauthorizedException('Por favor inicia sesión.');
        }
        if (!this.jwtService.verify(session)) {
            this.logger.error('JWT expirado o inválido');
            throw new UnauthorizedException('Por favor inicia sesión.');
        }

        const payload = this.jwtService.decode(session);
        if (!payload) {
            this.logger.error('Session existe pero accessToken CORRUPTO');
            throw new UnauthorizedException('Por favor inicia sesión.');
        }
        // const ahora = Math.floor(Date.now() / 1000); // timestamp actual en segundos
        // const iat = payload.iat || ahora; // issued at
        // const exp = payload.exp; // expiration time

        // const tiempoLogeado = ahora - iat; // segundos desde que se emitió
        // const tiempoRestante = exp - ahora; // segundos hasta expiración

        // this.logger.log(`⏱️ Token - Logeado: ${tiempoLogeado}s | Expira en: ${tiempoRestante}s`);
        // this.logger.log(`✅ Usuario autenticado: ${request['user'].username} (ID: ${request['user'].userId})`);

        return true;
    }

    async ExecuteRefreshSession(command: refreshSessionCommand): Promise<{ accessToken: string, refreshToken: string } | null> {
        this.logger.log("INIT - REFRESH SESSION");

        if (this.jwtService.verify(command.tokens[COOKIES.REFRESH], { secret: this.configService.get<string>('JWT_REFRESH') })) {
            this.logger.error('INVALID REFRESH TOKEN FORMAT');
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }

        const decodedRefresh = this.jwtService.decode(command.tokens[COOKIES.REFRESH]) as { refreshToken: string } | null;
        const [sessionId, sessionUuid, secret] = decodedRefresh.refreshToken.split('.');

        let sessionHandler: sessionHandler = {} as sessionHandler;

        if (!sessionId || !sessionUuid || !secret) {
            this.logger.error('INVALID REFRESH TOKEN');
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }
        let sessionCache = await this.cacheRepository.getAccessToken(sessionId)

        if (!sessionCache) {
            this.logger.error('NO CACHED SESSION - GET DB refreshSession');
        }
        const refreshSession = await this.refreshSessionRepo.findById(sessionUuid);
        if (!refreshSession || refreshSession.revokedAt || new Date(refreshSession.expiresAt) < new Date()) {
            this.logger.error('NO SESSION FOUND FROM DB');
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }

        const ok = await bcrypt.compare(secret, refreshSession.refreshTokenHash);

        if (!ok) {
            this.logger.error('INVALID REFRESH TOKEN SECRET');
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }
        this.logger.log(`SESSION VALIDATED - ROTATING`);
        const tokenDecode = await this.jwtService.decode(sessionCache) as AccessTokenPayload;

        sessionHandler = await this.authService.rotateSession(tokenDecode, { ip: refreshSession.ip, ua: refreshSession.userAgent, fingerprint: refreshSession.deviceFingerprint });

        const payload: AccessTokenPayload = {
            userId: sessionHandler.session.userId,
            username: tokenDecode.username,
            userUuid: sessionHandler.session.userUuid,
            sessionUuid: sessionHandler.session.sessionUuid,
            sessionId: sessionHandler.session.sessionId,
            roles: tokenDecode.roles,
            permissions: tokenDecode.permissions,
            typeDevice: sessionHandler.session.deviceType
        }
        const accessToken = this.jwtService.sign(
            payload,
            {
                expiresIn: (payload.permissions.includes("SUPER_ADMIN") || payload.roles.includes("ADMIN")) ? this.configService.get<string>('admin_expires_in') : this.configService.get<string>('access_expires_in'),
                secret: this.configService.get<string>('access_secret')
            } as JwtSignOptions);
        await this.cacheRepository.setAccessToken(
            payload.sessionId,
            accessToken
        ).then(() => {
            this.logger.log(`Sesión cacheada para usuario ${payload.userUuid} con clave session:${payload.sessionId}`);
        });

        const refreshToken = this.jwtService.sign(
            { refreshToken: sessionHandler.plainToken },
            {
                expiresIn: this.configService.get<string>('refresh_expires_in'),
                secret: this.configService.get<string>('refresh_secret')
            } as JwtSignOptions
        );
        return { accessToken, refreshToken };
    }

    async ExecuteLogout(sessionId: string): Promise<void> {
        await this.authService.revokeUserSessions(sessionId);
    }

    async ExecuteRequestPasswordRequest(command: RequestPasswordResetCommand): Promise<{ message: string }> {
        const contacto = await this.contactoRepository.findByCorreo(command.correo);

        if (!contacto) {
            // Por seguridad, no revelar si el email existe o no
            this.logger.warn(`Password reset requested for non-existent email: ${command.correo}`);
            return {
                message: 'Si el correo existe, recibirás un enlace de restablecimiento',
            };
        }

        if (!contacto.usuario.activo) {
            this.logger.warn("Usuario inactivo intenta solicitar restablecimiento de contraseña:", command.correo);
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

        console.log('🔐 Password Reset URL:', resetUrl);

        return {
            message: 'Si el correo existe, recibirás un enlace de restablecimiento',
        };
    }

    async ExecuteRequestPasswordValidation(command: validateResetTokenCommand): Promise<{ valid: boolean; email?: string }> {
        const resetToken = await this.passwordResetRepo.findValidToken(command.uuid);
        if (!resetToken) return { valid: false };

        const ok = await bcrypt.compare(command.token, resetToken.tokenHash);
        if (!ok) return { valid: false };

        return { valid: true, email: resetToken.email };
    }

    async ExecuteResetPassword(command: ResetPasswordCommand): Promise<{ message: string }> {
        if (command.newPassword !== command.confirmPassword) {
            throw new BadRequestException('Las contraseñas no coinciden');
        }

        // Validar token
        const resetToken = await this.passwordResetRepo.findValidToken(command.uuid);
        if (!resetToken) {
            throw new BadRequestException('Token inválido o expirado');
        }

        const ok = await bcrypt.compare(command.token, resetToken.tokenHash);
        if (!ok) {
            console.log('🔐 Reset Password - Token no encontrado o expirado');

            throw new BadRequestException('Token inválido o expirado');
        }

        // Hash de la nueva contraseña
        const passwordHash = await bcrypt.hash(command.newPassword, 10);

        const usuario = await this.usuarioRepository.getUsuarioById(resetToken.userId);

        if (!usuario) {
            console.log('🔐 Reset Password - Usuario no encontrado');
            throw new BadRequestException('Usuario no encontrado');
        }

        // Actualizar solo el password sin afectar las relaciones
        await this.usuarioRepository.updatePassword(resetToken.userId, passwordHash);

        // Marcar token como usado
        await this.passwordResetRepo.markTokenAsUsed(resetToken.id);

        // TODO: Enviar email de confirmación
        // await this.emailService.sendPasswordChangedConfirmation(resetToken.email);

        // Invalidar todas las sesiones del usuario (opcional pero recomendado)
        await this.refreshSessionRepo.revokeAllUserSessions(usuario.id.getValue().toString());

        return {
            message: 'Contraseña restablecida exitosamente',
        };
    }

}