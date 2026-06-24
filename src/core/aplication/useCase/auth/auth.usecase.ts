import { IAuthUseCase } from "./../../../domain/puertos/inbound/IAuthUseCase.interface";
import { authorizationCommand, refreshSessionCommand, RequestPasswordResetCommand, ResetPasswordCommand, validateResetTokenCommand } from "./command/AuthCommand.interface";
import { IUsuarioRepository } from "./../../../domain/puertos/outbound/iUsuarioRepository.interface";
import { performance } from "perf_hooks";

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
import { EmailNotVerifiedError } from "src/core/domain/errors/EmailNotVerified.error";

const COOKIES = {
    REFRESH: 'auth.refresh',
    SESSION: 'auth.session',
}

@Injectable()
export class AuthUseCase implements IAuthUseCase {
    private readonly logger = new Logger(AuthUseCase.name);
    private readonly accessSecret: string;
    private readonly refreshSecret: string;
    private readonly accessExpiresIn: string;
    private readonly adminExpiresIn: string;
    private readonly refreshExpiresIn: string;

    constructor(
        private usuarioRepository: IUsuarioRepository,
        private contactoRepository: IContactoRepository,
        private passwordResetRepo: IPasswordResetRepository,
        private refreshSessionRepo: IRefreshSessionRepository,
        private authService: AuthAplicationService,
        private jwtService: JwtService,
        private cacheRepository: ICacheRepository,
        private configService: ConfigService
    ) {
        this.accessSecret = this.configService.get<string>('jwtConfig.access_secret');
        this.refreshSecret = this.configService.get<string>('jwtConfig.refresh_secret');
        this.accessExpiresIn = this.configService.get<string>('jwtConfig.access_expires_in');
        this.adminExpiresIn = this.configService.get<string>('jwtConfig.admin_expires_in');
        this.refreshExpiresIn = this.configService.get<string>('jwtConfig.refresh_expires_in');
    }

    async ExcuteAuthentication(command: AuthenticationCommand): Promise<{ code: string, url: string }[] | null> {
        const requestId = command.requestId || 'N/A';
        this.logger.log(`[AUTHENTICATE] INIT requestId=${requestId} username=${command.username} device=${command.typeDevice} CorrelationId=${command.CorrelationId}`);
        const usuario = await this.usuarioRepository.getUsuarioByUsername(command.username);
        if (!usuario) {
            this.logger.warn(`[AUTHENTICATE] USER_NOT_FOUND requestId=${requestId} username=${command.username} CorrelationId=${command.CorrelationId}`);
            throw new UserNotFoundError("Usuario no encontrado");
        }
        if (!await bcrypt.compare(command.password, usuario.password)) {
            this.logger.warn(`[AUTHENTICATE] INVALID_CREDENTIALS requestId=${requestId} username=${command.username} CorrelationId=${command.CorrelationId}`);
            throw new LoginError("Usuario no encontrado o contraseña incorrecta");
        }
        if (!usuario.emailVerificado) {
            const email = usuario.contacto?.correo ?? command.username;
            this.logger.warn(`[AUTHENTICATE] EMAIL_NOT_VERIFIED requestId=${requestId} username=${command.username} CorrelationId=${command.CorrelationId}`);
            throw new EmailNotVerifiedError(email);
        }
        this.logger.log(`[AUTHENTICATE] CREDENTIALS_VALID requestId=${requestId} userUuid=${usuario.uuid} CorrelationId=${command.CorrelationId}`);        const code = await this.authService.createAuthorizationCode(
            usuario,
            // this.authService.hashingCodeChallenge(command.code_challenge),
            command.code_challenge,
            command.typeDevice,
            command.CorrelationId
        );
        this.logger.log(`[AUTHENTICATE] AUTH_CODE_CREATED requestId=${requestId} userUuid=${usuario.uuid} CorrelationId=${command.CorrelationId}`);

        const uris = await this.usuarioRepository
            .getSystemsByUsername(command.username)
            .then(data => {
                return data.map(item => {
                    return {
                        code: encodeURIComponent(code),
                        url: `/validate?code=${encodeURIComponent(code)}&cid=${encodeURIComponent(command.CorrelationId)}`,                        
                    }
                });
            });
        this.logger.log(`[AUTHENTICATE] SUCCESS requestId=${requestId} username=${command.username} systems=${uris.length}`);
        return uris;
    }

    async ExecuteAuthorization(command: authorizationCommand): Promise<{ accessToken: string, refreshToken: string } | null> {
        const requestId = command.requestId || 'N/A';
        this.logger.log(`[AUTHORIZATION] INIT requestId=${requestId} sessionId=${command.sessionId} device=${command.typeDevice} CorrelationId=${command.CorrelationId}`);
        if (!command.code || command.code === '') throw new InvalidcodeToken("Código de autorización inválido");

        const stored = await this.cacheRepository.getAuthCode(command.code);
        if (!stored) throw new InvalidcodeToken("Código de autorización inválido");
        this.logger.log(`[AUTHORIZATION] AUTH_CODE_FOUND requestId=${requestId} CorrelationId=${stored.CorrelationId} userUuid=${stored.userUuid} CorrelationId=${command.CorrelationId}`);

        const incomingChallenge = this.authService.hashingCodeChallenge(command.codeVerifier);
        if (incomingChallenge !== stored.codeChallenge) {
            this.logger.warn(`[AUTHORIZATION] INVALID_PKCE requestId=${requestId} sessionId=${command.sessionId} CorrelationId=${command.CorrelationId}`);
            throw new InvalidcodeToken("Code verifier inválido (PKCE)");
        }

        const storedDevice = (stored.typeDevice || '').trim().toUpperCase();
        const commandDevice = (command.typeDevice || '').trim().toUpperCase();

        if (storedDevice !== commandDevice) {
            this.logger.warn(`[AUTHORIZATION] DEVICE_MISMATCH requestId=${requestId} stored=${storedDevice} incoming=${commandDevice} sessionId=${command.sessionId} CorrelationId=${command.CorrelationId}`);
            throw new InvalidcodeToken("Tipo de dispositivo no coincide");
        }

        stored.sessionId = command.sessionId;

        await this.cacheRepository.deleteAuthCode(command.code);
        this.logger.log(`[AUTHORIZATION] AUTH_CODE_DELETED requestId=${requestId} sessionId=${command.sessionId} CorrelationId=${command.CorrelationId}`);
        const tokens = await this.authService.createRefreshSession(stored);
        this.logger.log(`[AUTHORIZATION] SUCCESS requestId=${requestId} sessionId=${command.sessionId} userUuid=${stored.userUuid} CorrelationId=${command.CorrelationId}`);
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
        const t0 = performance.now();
        const lap = (label: string, prev: number) => {
            const ms = (performance.now() - prev).toFixed(1);
            this.logger.debug(`[REFRESH_PERF] requestId=${requestId} step="${label}" ms=${ms}`);
            return performance.now();
        };
        let t = t0;
        this.logger.log(`[REFRESH_SESSION] INIT requestId=${requestId} device=${command.typeDevice}`);

        const refreshCookie = command.tokens?.[COOKIES.REFRESH];
        if (!refreshCookie) {
            this.logger.error(`[REFRESH_SESSION] MISSING_REFRESH_TOKEN requestId=${requestId} device=${command.typeDevice}`);
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }

        try {
            this.jwtService.verify(refreshCookie, { secret: this.refreshSecret });
        } catch (_error) {
            this.logger.error(`[REFRESH_SESSION] INVALID_REFRESH_TOKEN_FORMAT requestId=${requestId} device=${command.typeDevice}`);
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }
        t = lap('jwt.verify(refreshCookie)', t);

        const decodedRefresh = this.jwtService.decode(refreshCookie) as { refreshToken: string } | null;
        if (!decodedRefresh?.refreshToken) {
            this.logger.error(`[REFRESH_SESSION] INVALID_REFRESH_TOKEN_PAYLOAD requestId=${requestId} device=${command.typeDevice}`);
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }
        const [sessionId, sessionUuid, secret] = decodedRefresh.refreshToken.split('.');
        t = lap('jwt.decode(refreshCookie)', t);

        let sessionHandler: sessionHandler = {} as sessionHandler;

        if (!sessionId || !sessionUuid || !secret) {
            this.logger.error(`[REFRESH_SESSION] INVALID_REFRESH_TOKEN_PARTS requestId=${requestId} device=${command.typeDevice}`);
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }
        this.logger.log(`[REFRESH_SESSION] TOKEN_PARSED requestId=${requestId} cacheSessionId=${sessionId} sessionUuid=${sessionUuid}`);

        let sessionCache = await this.cacheRepository.getAccessToken(sessionId);
        t = lap('redis.getAccessToken', t);
        if (!sessionCache) {
            this.logger.warn(`[REFRESH_SESSION] NO_CACHED_SESSION requestId=${requestId} cacheSessionId=${sessionId} sessionUuid=${sessionUuid}`);
        }

        const refreshSession = await this.refreshSessionRepo.findById(sessionUuid);
        t = lap('db.findRefreshSession', t);
        if (!refreshSession || refreshSession.revokedAt || new Date(refreshSession.expiresAt) < new Date()) {
            this.logger.error(`[REFRESH_SESSION] SESSION_NOT_FOUND_OR_EXPIRED requestId=${requestId} sessionUuid=${sessionUuid}`);
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }

        const ok = this.authService.verifyTokenSecret(secret, refreshSession.refreshTokenHash);
        t = lap('hmac.verifyTokenSecret', t);

        if (!ok) {
            this.logger.error(`[REFRESH_SESSION] INVALID_REFRESH_TOKEN_SECRET requestId=${requestId} sessionUuid=${sessionUuid}`);
            throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
        }
        this.logger.log(`[REFRESH_SESSION] SESSION_VALIDATED requestId=${requestId} rotating sessionUuid=${sessionUuid}`);
        let tokenDecode = this.jwtService.decode(sessionCache) as AccessTokenPayload | null;
        if (!tokenDecode) {
            this.logger.warn(`[REFRESH_SESSION] CACHE_MISS_FALLBACK requestId=${requestId} rebuilding payload from DB sessionUuid=${sessionUuid}`);
            const usuario = await this.usuarioRepository.getUsuarioById(refreshSession.userId);
            t = lap('db.getUsuarioById(fallback)', t);
            if (!usuario) {
                this.logger.error(`[REFRESH_SESSION] USER_NOT_FOUND_ON_FALLBACK requestId=${requestId} userId=${refreshSession.userId}`);
                throw new UnauthorizedException('Session inactiva, porfavor loguearse de nuevo');
            }
            tokenDecode = {
                userId: refreshSession.userId,
                username: usuario.userName,
                userUuid: refreshSession.userUuid,
                sessionUuid: refreshSession.sessionUuid,
                sessionId: refreshSession.sessionId,
                roles: usuario.rol.map(r => r.codigo) as string[],
                permissions: usuario.rol.flatMap(r => r.permisos ? r.permisos.map(p => p.codigo) : []) as string[],
                typeDevice: refreshSession.deviceType,
            } as AccessTokenPayload;
        }
        sessionHandler = await this.authService.rotateSession(tokenDecode, { ip: refreshSession.ip, ua: refreshSession.userAgent, fingerprint: refreshSession.deviceFingerprint });
        t = lap('rotateSession (revoke+insert)', t);

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
                expiresIn: (payload.permissions.includes('SUPER_ADMIN') || payload.roles.includes('ADMIN')) ?
                    this.adminExpiresIn :
                    this.accessExpiresIn,
                secret: this.accessSecret,
            } as JwtSignOptions);
        t = lap('jwt.sign(accessToken)', t);

        await this.cacheRepository.setAccessToken(payload.sessionId, accessToken);
        t = lap('redis.setAccessToken', t);
        this.logger.log(`[REFRESH_SESSION] ACCESS_TOKEN_CACHED requestId=${requestId} userUuid=${payload.userUuid} sessionId=${payload.sessionId}`);

        const refreshToken = this.jwtService.sign(
            { refreshToken: sessionHandler.plainToken },
            {
                expiresIn: this.refreshExpiresIn,
                secret: this.refreshSecret,
            } as JwtSignOptions
        );
        t = lap('jwt.sign(refreshToken)', t);

        const totalMs = (performance.now() - t0).toFixed(1);
        this.logger.log(`[REFRESH_PERF] requestId=${requestId} TOTAL=${totalMs}ms`);
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