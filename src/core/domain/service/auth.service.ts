/*
https://docs.nestjs.com/providers#services
*/


import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { TokenCacheService } from './token-cache.service';
import { UsuarioModel } from '../model/usuario.model';
import { IAuthService } from '../puertos/inbound/IAuthService.interface';
import { IUsuarioRepository } from '../puertos/outbound/iUsuarioRepository.interface';
import * as bcrypt from 'bcrypt';
import { UserNotFoundError } from 'src/core/share/errors/UserNotFound.error';
import { LoginError } from 'src/core/share/errors/LoginError.error';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { randomBytes } from 'crypto';
import { IRefreshSessionRepository } from '../puertos/outbound/iRefreshSessionRepository.interface';
import { UsuarioEntity } from 'src/infrastructure/database/entities/usuario.entity';
import { Id } from 'src/core/share/valueObject/id.valueObject';
import { RefreshSession } from '../model/RefreshSession.model';
import { InvalidcodeToken } from 'src/core/share/errors/InvalidCodeToken.error';
import { createHash } from 'crypto';
import { IPasswordResetRepository } from '../puertos/outbound/IPasswordResetRepository.interface';
import { IContactoRepository } from '../puertos/outbound/iContactoRepository.interface';

interface AuthCodeStored {
    userId: number;
    userUuid: string;
    sessionId: string;
    sessionUuid: string;
    sub: string;
    rol: string[];
    permisos: string[];
    typeDevice: string;
    codeChallenge: string;
    createdAt: number;
}

@Injectable()
export class AuthService implements IAuthService {
    private readonly logger = new Logger(AuthService.name);
    // private codes = new Map<string, any>();

    constructor(
        private usuarioRepository: IUsuarioRepository,
        private jwtService: JwtService,
        private tokenCacheService: TokenCacheService,
        private refreshSessionRepo: IRefreshSessionRepository,
        private contactoRepository: IContactoRepository,
        private passwordResetRepo: IPasswordResetRepository,
    ) { }

    private refreshTtlDays(): number {
        return Number(process.env.JWT_REFRESH_DAYS ?? 7);
    }
    /** validar que el usuario no tenga mas de 1 session por dispositivo y validar en cache antes que en db */
    private async createRefreshSession(sessionActive: AuthCodeStored, deviceType: string, meta?: { ip?: string, ua?: string, fingerprint?: string }) {
        const secret = randomBytes(48).toString('hex');
        const hash = await bcrypt.hash(secret, 10);
        const expiresAt = new Date(Date.now() + this.refreshTtlDays() * 86400000);
        let session = sessionActive;
        let sessionHandler: { plainToken?: string, session?: RefreshSession } = {};
        let sessionCache: RefreshSession = this.jwtService.decode(await this.tokenCacheService.getRefreshToken(session.userId.toString(), deviceType)) as RefreshSession;
        if (!sessionCache) {
            this.logger.log(`session:${session.sessionId} - CACHE INACTIVA`);
            sessionCache = await this.refreshSessionRepo.findByUserAndDevice(session.userUuid, deviceType);
        }
        if (sessionCache) {
            this.logger.log(`session:${session.sessionId} | REFRESH-SESION - ACTIVA - | ROTACION`);
            sessionHandler = await this.rotateSession(sessionCache);
        } else {
            this.logger.log(`session:${session.sessionId} | CREANDO`);
            const usuario = new UsuarioEntity();
            usuario.usuarioUuid = session.userUuid;
            usuario.id = session.userId;
            const sessionRepo = await this.refreshSessionRepo.create({
                user: usuario,
                sessionId: session.sessionId,
                deviceType,
                deviceFingerprint: meta?.fingerprint,
                refreshTokenHash: hash,
                ip: meta?.ip,
                userAgent: meta?.ua,
                expiresAt
            });
            sessionHandler.plainToken = `${sessionRepo.sessionUuid}.${secret}`;
            sessionHandler.session = sessionRepo;
            this.logger.log(`session:${session.sessionId} | SESSION OK`);
        }
        const accessToken = this.jwtService.sign({
            userId: sessionHandler.session.user.id,
            username: sessionActive.sub,
            userUuid: sessionActive.userUuid,
            sessionuuid: sessionHandler.session.sessionUuid,
            roles: sessionActive.rol,
            permissions: sessionActive.permisos,
            typeDevice: session.typeDevice
        },
            {
                expiresIn: (sessionActive.rol.includes("SUPER_ADMIN") || sessionActive.rol.includes("ADMIN")) ? process.env.JWT_ADMIN_EXPIRES_IN : process.env.JWT_EXPIRES_IN, secret: process.env.JWT_SECRET
            } as JwtSignOptions);
        await this.tokenCacheService.setJson(
            `session:${session.sessionId}`,
            { accessToken }
        ).then(() => {
            this.logger.log(`Sesión cacheada para usuario ${session.userUuid} con clave session:${session.sessionId}`);
        });
        return { accessToken, refreshToken: `${session.sessionUuid}.${secret}` };
    }

    private async rotateSession(oldSession: RefreshSession) {
        this.refreshSessionRepo.revokeById(oldSession.sessionUuid);
        this.tokenCacheService.deleteKey(`session:${oldSession.sessionId}`);

        // Crear nueva sesión encadenada (rotationParentId)
        const secret = randomBytes(48).toString('hex');
        const hash = await bcrypt.hash(secret, 10);
        const expiresAt = new Date(Date.now() + this.refreshTtlDays() * 86400000);

        const newSession = await this.refreshSessionRepo.rotate(oldSession, {
            user: oldSession.user,
            sessionId: oldSession.sessionId,
            deviceType: oldSession.deviceType,
            deviceFingerprint: oldSession.deviceFingerprint,
            refreshTokenHash: hash,
            ip: oldSession.ip,
            userAgent: oldSession.userAgent,
            expiresAt,
            rotationParentId: oldSession.id
        });

        const plainToken = `${newSession.sessionId}.${secret}`;
        return { plainToken, session: newSession };
    }

    /** Actualizarpara flujo nuevo
     * validar token en cache, si no existe validar en db. no en ambos de igual manera. 
     */
    async refreshToken(token: string, userId: string, typeDevice: string): Promise<{ accessToken: string, refreshToken: string } | null> {
        try {
            // Nuevo flujo híbrido
            if (token.includes('.')) {
                const [sessionIdStr, secret] = token.split('.');
                const sessionUuid = sessionIdStr;
                if (!sessionUuid || !secret) return null;

                // Cache lookup
                const cacheKey = `session:${sessionUuid}`;
                const cached = await this.tokenCacheService.getJson(cacheKey);
                let session = null;

                if (cached) {
                    if (cached.revoked === 1) return null;
                    if (cached.deviceType !== typeDevice || String(cached.userId) !== userId) return null;
                }

                // Fetch DB (si no hay cache o para verificar hash)
                session = await this.refreshSessionRepo.findById(sessionUuid);
                if (!session) return null;
                if (session.revokedAt) return null;
                if (session.userId !== Number(userId) || session.deviceType !== typeDevice) return null;
                if (session.expiresAt < new Date()) return null;

                const ok = await bcrypt.compare(secret, session.refreshTokenHash);
                if (!ok) return null;

                // Cargar usuario
                const usuarioDB = await this.usuarioRepository.getUsuarioById(Number(userId));
                if (!usuarioDB) return null;
                const usuario = UsuarioModel.create(usuarioDB);
                const payload = {
                    id: usuario.id.getValue(),
                    sub: usuario.userName,
                    rol: usuario.rol.map(r => r.nombre),
                    permisos: usuario.rol.flatMap(r => r.permisos ? r.permisos.map(p => p.nombre) : [])
                };
                const accessToken = this.jwtService.sign(payload, {
                    expiresIn: (payload.rol.includes("SUPER_ADMIN") || payload.rol.includes("ADMIN")) ? process.env.JWT_ADMIN_EXPIRES_IN : process.env.JWT_EXPIRES_IN,
                    secret: process.env.JWT_SECRET
                } as JwtSignOptions);

                // Rotación
                const newRefresh = await this.rotateSession(session);
                return { accessToken, refreshToken: newRefresh.plainToken };
            }

            // Fase transitoria: si token viejo (sin '.')
            const storedToken = await this.tokenCacheService.getRefreshToken(userId, typeDevice);
            if (!storedToken || storedToken !== token) return null;

            const usuarioDB = await this.usuarioRepository.getUsuarioById(Number(userId));
            if (!usuarioDB) return null;
            const usuario = UsuarioModel.create(usuarioDB);
            const payload = {
                userUuid: usuario.uuid,
                sub: usuario.userName,
                rol: usuario.rol.map(r => r.nombre),
                permisos: usuario.rol.flatMap(r => r.permisos ? r.permisos.map(p => p.nombre) : []),
            } as AuthCodeStored;

            // Migración: crear sesión nueva y no volver a emitir formato viejo
            const newRefresh = await this.createRefreshSession(payload, typeDevice);
            // Revoca cache legacy
            await this.tokenCacheService.deleteRefreshToken(userId, typeDevice);
            const accessToken = this.jwtService.sign(newRefresh[1], {
                expiresIn: (payload.rol.includes("SUPER_ADMIN") || payload.rol.includes("ADMIN")) ? process.env.JWT_ADMIN_EXPIRES_IN : process.env.JWT_EXPIRES_IN,
                secret: process.env.JWT_SECRET
            } as JwtSignOptions);
            return { accessToken, refreshToken: newRefresh[0] };
        } catch {
            return null;
        }
    }

    async validateToken(token: string): Promise<string | null> {
        try {
            this.jwtService.verify(token, { secret: process.env.JWT_SECRET });
            return token;
        } catch (error) {
            return null;
        }
    }


    async authetication(username: string, password: string, typeDevice: string, code_challenge: string, sessionId: string): Promise<{ code: string, url: string }[] | null> {
        const usuarioDB = await this.usuarioRepository.getUsuarioByUsername(username);
        if (!usuarioDB) {
            throw new UserNotFoundError("Usuario no encontrado");
        }
        const usuario = UsuarioModel.create(usuarioDB);
        if (!await bcrypt.compare(password, usuario.password)) {
            throw new LoginError("Usuario no encontrado o contraseña incorrecta");
        }

        const code = await this.createAuthorizationCode(
            usuario,
            code_challenge,
            typeDevice,
            sessionId
        );
        const uris = await this.usuarioRepository
            .getSystemsByUsername(username)
            .then(data => {
                return data.map(item => {
                    return {
                        code: encodeURIComponent(code),
                        url: `${item.path}/validate?code=${encodeURIComponent(code)}`
                    }
                }); // Ajusta según la estructura real de 'item'
            });

        return uris;
    }

    async createAuthorizationCode(usuario: UsuarioModel, codeChallenge: string, typeDevice: string, sessionId: string): Promise<string> {
        const code = randomBytes(32).toString('hex');
        await this.tokenCacheService.setJson(
            `auth_code:${code}`,
            {
                userId: usuario.id.getValue(),
                userUuid: usuario.uuid,
                sessionId,
                sub: usuario.userName,
                rol: usuario.rol.map(r => r.codigo) as string[],
                permisos: usuario.rol.flatMap(r => r.permisos ? r.permisos.map(p => p.codigo) : []) as string[],
                typeDevice,
                codeChallenge,
                createdAt: Date.now()
            } as AuthCodeStored,
            1000 * 10
        );
        return code;
    }

    private base64url(buffer: Buffer) {
        return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    private sha256base64url(input: string) {
        const digest = createHash('sha256').update(input).digest();  // ✅ Cambiar bcrypt.createHash por createHash
        return this.base64url(digest);
    }

    async exchangeCodeForToken(
        code: string,
        codeVerifier: string,
        typeDevice: string,
        sessionId: string,
        meta?: { ip?: string, ua?: string, fingerprint?: string }
    ): Promise<{ accessToken: string; refreshToken: string; } | null> {
        if (!code || code === '') throw new InvalidcodeToken("Código de autorización inválido");

        const stored = await this.tokenCacheService.getJson<AuthCodeStored>(`auth_code:${code}`);
        // const stored = this.codes.get(code) as AuthCodeStored;
        if (!stored) throw new InvalidcodeToken("Código de autorización inválido");

        const computedChallenge = this.sha256base64url(codeVerifier);
        if (computedChallenge !== stored.codeChallenge) {
            throw new InvalidcodeToken("Code verifier inválido (PKCE)");
        }

        if (stored.typeDevice !== typeDevice) {
            throw new InvalidcodeToken("Tipo de dispositivo no coincide");
        }

        stored.sessionId = sessionId;

        const refreshToken = await this.createRefreshSession(stored, typeDevice, meta);

        // invalidar code (one-time)
        this.tokenCacheService.deleteKey(`auth_code:${code}`);
        return refreshToken;
    }

    async revokeUserSessions(sessionId: any): Promise<number> {
        const infoToken: any = await this.tokenCacheService.getJson<any>(`session:${sessionId}`);
        if (!infoToken) {
            this.logger.warn(`No cache entry found for sessionUuid: ${sessionId}`);
            return 0;
        }
        const decodedJWT: any = this.jwtService.decode(infoToken.accessToken);
        this.logger.log(`Revoking sessions for userId: ${decodedJWT.userUuid}, deviceType: ${decodedJWT.typeDevice}`);
        if (!decodedJWT) {
            this.logger.warn(`Failed to decode JWT for sessionUuid: ${decodedJWT.sessionuuid}`);
            return 0;
        }
        const response = Promise.all([
            this.refreshSessionRepo.revokeUserSessions(decodedJWT.userId, decodedJWT.typeDevice),
            this.tokenCacheService.deleteKey(`session:${sessionId}`)
        ]);
        const [revokedCount] = await response;
        this.logger.log(`session revoked for userId: ${decodedJWT.userUuid}`);

        return revokedCount;
    }

    async requestPasswordReset(
        email: string,
        ipAddress?: string,
        userAgent?: string
    ): Promise<{ message: string }> {
        // Buscar usuario por email (necesitas agregar este método en usuarioRepository)
        const contacto = await this.contactoRepository.findByCorreo(email);

        if (!contacto) {
            // Por seguridad, no revelar si el email existe o no
            return {
                message: 'Si el correo existe, recibirás un enlace de restablecimiento',
            };
        }

        if (!contacto.usuario.activo) {
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
            email,
            tokenHash,
            expiresAt,
            ipAddress,
            userAgent,
        );

        // Construir URL de restablecimiento
        const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:8082'}/reset-password?token=${token}&uuid=${tokenUuid}`;

        // TODO: Enviar email con el enlace
        // await this.emailService.sendPasswordResetEmail(email, resetUrl, contacto.usuario.username);

        console.log('🔐 Password Reset URL:', resetUrl);

        return {
            message: 'Si el correo existe, recibirás un enlace de restablecimiento',
        };
    }

    async validateResetToken(token: string): Promise<{ valid: boolean; email?: string }> {
        const tokenHash = await bcrypt.hash(token, 10);

        const resetToken = await this.passwordResetRepo.findValidToken(tokenHash);

        if (!resetToken) {
            return { valid: false };
        }

        return {
            valid: true,
            email: resetToken.email,
        };
    }

    async resetPassword(
        token: string,
        newPassword: string,
        confirmPassword: string
    ): Promise<{ message: string }> {
        if (newPassword !== confirmPassword) {
            throw new BadRequestException('Las contraseñas no coinciden');
        }

        // Validar token
        const tokenHash = await bcrypt.hash(token, 10);
        const resetToken = await this.passwordResetRepo.findValidToken(tokenHash);

        if (!resetToken) {
            throw new BadRequestException('Token inválido o expirado');
        }

        // Hash de la nueva contraseña
        const passwordHash = await bcrypt.hash(newPassword, 10);

        const usuario = await this.usuarioRepository.getUsuarioById(resetToken.userId);

        if (!usuario) {
            throw new BadRequestException('Usuario no encontrado');
        }

        usuario.password = passwordHash;

        // Actualizar contraseña del usuario
        await this.usuarioRepository.updateUsuario(resetToken.userId, usuario);

        // Marcar token como usado
        await this.passwordResetRepo.markTokenAsUsed(resetToken.id);

        // TODO: Enviar email de confirmación
        // await this.emailService.sendPasswordChangedConfirmation(resetToken.email);

        // Invalidar todas las sesiones del usuario (opcional pero recomendado)
        await this.refreshSessionRepo.revokeAllUserSessions(usuario.id.toString());

        return {
            message: 'Contraseña restablecida exitosamente',
        };
    }



    async cleanupExpiredTokens(): Promise<void> {
        await this.passwordResetRepo.deleteExpiredTokens();
    }
}
