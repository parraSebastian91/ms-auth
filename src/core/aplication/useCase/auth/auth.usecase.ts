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
        const requestId = command.requestId || 'N/A';
        this.logger.log(`[AUTHENTICATE] INIT requestId=${requestId} username=${command.username} device=${command.typeDevice} sessionId=${command.sessionId}`);
        const usuario = await this.usuarioRepository.getUsuarioByUsername(command.username);
        if (!usuario) {
            this.logger.warn(`[AUTHENTICATE] USER_NOT_FOUND requestId=${requestId} username=${command.username}`);
            throw new UserNotFoundError("Usuario no encontrado");
        }
        if (!await bcrypt.compare(command.password, usuario.password)) {
            this.logger.warn(`[AUTHENTICATE] INVALID_CREDENTIALS requestId=${requestId} username=${command.username}`);
            throw new LoginError("Usuario no encontrado o contraseña incorrecta");
        }
        this.logger.log(`[AUTHENTICATE] CREDENTIALS_VALID requestId=${requestId} userUuid=${usuario.uuid} sessionId=${command.sessionId}`);
        const code = await this.authService.createAuthorizationCode(
            usuario,
            // this.authService.hashingCodeChallenge(command.code_challenge),
            command.code_challenge,
            command.typeDevice,
            command.sessionId
        );
        this.logger.log(`[AUTHENTICATE] AUTH_CODE_CREATED requestId=${requestId} userUuid=${usuario.uuid} sessionId=${command.sessionId}`);

        const uris = await this.usuarioRepository
            .getSystemsByUsername(command.username)
            .then(data => {
                return data.map(item => {
                    return {
                        code: encodeURIComponent(code),
                        url: `/validate?code=${encodeURIComponent(code)}`
                    }
                });
            });
        this.logger.log(`[AUTHENTICATE] SUCCESS requestId=${requestId} username=${command.username} systems=${uris.length}`);
        return uris;
    }

    async ExecuteAuthorization(command: authorizationCommand): Promise<{ accessToken: string, refreshToken: string } | null> {
        const requestId = command.requestId || 'N/A';
        this.logger.log(`[AUTHORIZATION] INIT requestId=${requestId} sessionId=${command.sessionId} device=${command.typeDevice}`);
        if (!command.code || command.code === '') throw new InvalidcodeToken("Código de autorización inválido");

        const stored = await this.cacheRepository.getAuthCode(command.code);
        if (!stored) throw new InvalidcodeToken("Código de autorización inválido");
        this.logger.log(`[AUTHORIZATION] AUTH_CODE_FOUND requestId=${requestId} sessionId=${stored.sessionId} userUuid=${stored.userUuid}`);

        const incomingChallenge = this.authService.hashingCodeChallenge(command.codeVerifier);
        if (incomingChallenge!== stored.codeChallenge) {
            this.logger.warn(`[AUTHORIZATION] INVALID_PKCE requestId=${requestId} sessionId=${command.sessionId}`);
            throw new InvalidcodeToken("Code verifier inválido (PKCE)");
        }

        const storedDevice = (stored.typeDevice || '').trim().toUpperCase();
        const commandDevice = (command.typeDevice || '').trim().toUpperCase();

        if (storedDevice !== commandDevice) {
            this.logger.warn(`[AUTHORIZATION] DEVICE_MISMATCH requestId=${requestId} stored=${storedDevice} incoming=${commandDevice} sessionId=${command.sessionId}`);
            throw new InvalidcodeToken("Tipo de dispositivo no coincide");
        }

        stored.sessionId = command.sessionId;

        await this.cacheRepository.deleteAuthCode(command.code);
        this.logger.log(`[AUTHORIZATION] AUTH_CODE_DELETED requestId=${requestId} sessionId=${command.sessionId}`);
        const tokens = await this.authService.createRefreshSession(stored);
        this.logger.log(`[AUTHORIZATION] SUCCESS requestId=${requestId} sessionId=${command.sessionId} userUuid=${stored.userUuid}`);
        return tokens;
    }



    async ExecuteValidateSession(command: validateQuery): Promise<boolean> {
        this.logger.log(`[VALIDATE_SESSION] INIT sessionId=${command.sessionId}`);
        const session = await this.cacheRepository.getAccessToken(command.sessionId);
        if (!session) {
            this.logger.error(`[VALIDATE_SESSION] SESSION_NOT_FOUND sessionId=${command.sessionId}`);
            throw new UnauthorizedException('Por favor inicia sesión.');
        }
        if (!this.jwtService.verify(session)) {
            this.logger.error(`[VALIDATE_SESSION] INVALID_OR_EXPIRED_JWT sessionId=${command.sessionId}`);
            throw new UnauthorizedException('Por favor inicia sesión.');
        }

        const payload = this.jwtService.decode(session);
        if (!payload) {
            this.logger.error(`[VALIDATE_SESSION] CORRUPTED_TOKEN sessionId=${command.sessionId}`);
            throw new UnauthorizedException('Por favor inicia sesión.');
        }
        // const ahora = Math.floor(Date.now() / 1000); // timestamp actual en segundos
        // const iat = payload.iat || ahora; // issued at
        // const exp = payload.exp; // expiration time

        // const tiempoLogeado = ahora - iat; // segundos desde que se emitió
        // const tiempoRestante = exp - ahora; // segundos hasta expiración

        // this.logger.log(`⏱️ Token - Logeado: ${tiempoLogeado}s | Expira en: ${tiempoRestante}s`);
        // this.logger.log(`✅ Usuario autenticado: ${request['user'].username} (ID: ${request['user'].userId})`);

        this.logger.log(`[VALIDATE_SESSION] SUCCESS sessionId=${command.sessionId}`);
        return true;
    }

    async ExecuteRefreshSession(command: refreshSessionCommand): Promise<{ accessToken: string, refreshToken: string } | null> {
        const requestId = command.requestId || 'N/A';
        this.logger.log(`[REFRESH_SESSION] INIT requestId=${requestId} device=${command.typeDevice}`);

        const refreshCookie = command.tokens?.[COOKIES.REFRESH];
        if (!refreshCookie) {
            this.logger.error(`[REFRESH_SESSION] MISSING_REFRESH_TOKEN requestId=${requestId} device=${command.typeDevice}`);
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }

        try {
            this.jwtService.verify(refreshCookie, { secret: this.configService.get<string>('JWT_REFRESH') });
        } catch (_error) {
            this.logger.error(`[REFRESH_SESSION] INVALID_REFRESH_TOKEN_FORMAT requestId=${requestId} device=${command.typeDevice}`);
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }

        const decodedRefresh = this.jwtService.decode(refreshCookie) as { refreshToken: string } | null;
        if (!decodedRefresh?.refreshToken) {
            this.logger.error(`[REFRESH_SESSION] INVALID_REFRESH_TOKEN_PAYLOAD requestId=${requestId} device=${command.typeDevice}`);
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }
        const [sessionId, sessionUuid, secret] = decodedRefresh.refreshToken.split('.');

        let sessionHandler: sessionHandler = {} as sessionHandler;

        if (!sessionId || !sessionUuid || !secret) {
            this.logger.error(`[REFRESH_SESSION] INVALID_REFRESH_TOKEN_PARTS requestId=${requestId} device=${command.typeDevice}`);
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }
        this.logger.log(`[REFRESH_SESSION] TOKEN_PARSED requestId=${requestId} cacheSessionId=${sessionId} sessionUuid=${sessionUuid}`);
        let sessionCache = await this.cacheRepository.getAccessToken(sessionId)

        if (!sessionCache) {
            this.logger.warn(`[REFRESH_SESSION] NO_CACHED_SESSION requestId=${requestId} cacheSessionId=${sessionId} sessionUuid=${sessionUuid}`);
        }
        const refreshSession = await this.refreshSessionRepo.findById(sessionUuid);
        if (!refreshSession || refreshSession.revokedAt || new Date(refreshSession.expiresAt) < new Date()) {
            this.logger.error(`[REFRESH_SESSION] SESSION_NOT_FOUND_OR_EXPIRED requestId=${requestId} sessionUuid=${sessionUuid}`);
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }

        const ok = await bcrypt.compare(secret, refreshSession.refreshTokenHash);

        if (!ok) {
            this.logger.error(`[REFRESH_SESSION] INVALID_REFRESH_TOKEN_SECRET requestId=${requestId} sessionUuid=${sessionUuid}`);
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }
        this.logger.log(`[REFRESH_SESSION] SESSION_VALIDATED requestId=${requestId} rotating sessionUuid=${sessionUuid}`);
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
            this.logger.log(`[REFRESH_SESSION] ACCESS_TOKEN_CACHED requestId=${requestId} userUuid=${payload.userUuid} sessionId=${payload.sessionId}`);
        });

        const refreshToken = this.jwtService.sign(
            { refreshToken: sessionHandler.plainToken },
            {
                expiresIn: this.configService.get<string>('refresh_expires_in'),
                secret: this.configService.get<string>('refresh_secret')
            } as JwtSignOptions
        );
        this.logger.log(`[REFRESH_SESSION] SUCCESS requestId=${requestId} userUuid=${payload.userUuid} sessionId=${payload.sessionId} sessionUuid=${payload.sessionUuid}`);
        return { accessToken, refreshToken };
    }

    async ExecuteLogout(sessionId: string): Promise<void> {
        this.logger.log(`[LOGOUT] INIT sessionId=${sessionId}`);
        await this.authService.revokeUserSessions(sessionId);
        this.logger.log(`[LOGOUT] SUCCESS sessionId=${sessionId}`);
    }

    async ExecuteRequestPasswordRequest(command: RequestPasswordResetCommand): Promise<{ message: string }> {
        const requestId = command.requestId || 'N/A';
        this.logger.log(`[PASSWORD_RESET_REQUEST] INIT requestId=${requestId} email=${command.correo}`);
        const contacto = await this.contactoRepository.findByCorreo(command.correo);

        if (!contacto) {
            // Por seguridad, no revelar si el email existe o no
            this.logger.warn(`[PASSWORD_RESET_REQUEST] NON_EXISTENT_EMAIL requestId=${requestId} email=${command.correo}`);
            return {
                message: 'Si el correo existe, recibirás un enlace de restablecimiento',
            };
        }

        if (!contacto.usuario.activo) {
            this.logger.warn(`[PASSWORD_RESET_REQUEST] INACTIVE_USER requestId=${requestId} email=${command.correo}`);
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

        this.logger.log(`[PASSWORD_RESET_REQUEST] TOKEN_CREATED requestId=${requestId} email=${command.correo} tokenUuid=${tokenUuid} expiresAt=${expiresAt.toISOString()}`);

        return {
            message: 'Si el correo existe, recibirás un enlace de restablecimiento',
        };
    }

    async ExecuteRequestPasswordValidation(command: validateResetTokenCommand): Promise<{ valid: boolean; email?: string }> {
        const requestId = command.requestId || 'N/A';
        this.logger.log(`[PASSWORD_RESET_VALIDATE] INIT requestId=${requestId} tokenUuid=${command.uuid}`);
        const resetToken = await this.passwordResetRepo.findValidToken(command.uuid);
        if (!resetToken) {
            this.logger.warn(`[PASSWORD_RESET_VALIDATE] TOKEN_NOT_FOUND requestId=${requestId} tokenUuid=${command.uuid}`);
            return { valid: false };
        }

        const ok = await bcrypt.compare(command.token, resetToken.tokenHash);
        if (!ok) {
            this.logger.warn(`[PASSWORD_RESET_VALIDATE] TOKEN_MISMATCH requestId=${requestId} tokenUuid=${command.uuid}`);
            return { valid: false };
        }

        this.logger.log(`[PASSWORD_RESET_VALIDATE] SUCCESS requestId=${requestId} tokenUuid=${command.uuid}`);
        return { valid: true, email: resetToken.email };
    }

    async ExecuteResetPassword(command: ResetPasswordCommand): Promise<{ message: string }> {
        const requestId = command.requestId || 'N/A';
        this.logger.log(`[RESET_PASSWORD] INIT requestId=${requestId} tokenUuid=${command.uuid}`);
        if (command.newPassword !== command.confirmPassword) {
            this.logger.warn(`[RESET_PASSWORD] PASSWORD_MISMATCH requestId=${requestId} tokenUuid=${command.uuid}`);
            throw new BadRequestException('Las contraseñas no coinciden');
        }

        // Validar token
        const resetToken = await this.passwordResetRepo.findValidToken(command.uuid);
        if (!resetToken) {
            this.logger.warn(`[RESET_PASSWORD] TOKEN_NOT_FOUND requestId=${requestId} tokenUuid=${command.uuid}`);
            throw new BadRequestException('Token inválido o expirado');
        }

        const ok = await bcrypt.compare(command.token, resetToken.tokenHash);
        if (!ok) {
            this.logger.warn(`[RESET_PASSWORD] INVALID_TOKEN requestId=${requestId} tokenUuid=${command.uuid}`);

            throw new BadRequestException('Token inválido o expirado');
        }

        // Hash de la nueva contraseña
        const passwordHash = await bcrypt.hash(command.newPassword, 10);

        const usuario = await this.usuarioRepository.getUsuarioById(resetToken.userId);

        if (!usuario) {
            this.logger.error(`[RESET_PASSWORD] USER_NOT_FOUND requestId=${requestId} userId=${resetToken.userId}`);
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
        this.logger.log(`[RESET_PASSWORD] SUCCESS requestId=${requestId} userUuid=${usuario.uuid}`);

        return {
            message: 'Contraseña restablecida exitosamente',
        };
    }

}