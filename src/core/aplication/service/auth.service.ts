import { Logger } from "@nestjs/common";
import { JwtService, JwtSignOptions, JwtVerifyOptions } from "@nestjs/jwt";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "crypto";
import { performance } from "perf_hooks";
import { RefreshSessionModel } from "./../../domain/model/RefreshSession.model";
import { ICacheRepository } from "./../../domain/puertos/outbound/CacheRepository.interface";
import { IRefreshSessionRepository } from "./../../domain/puertos/outbound/iRefreshSessionRepository.interface";
import { ConfigService } from "@nestjs/config";
import { AccessTokenPayload } from "./../../domain/model/jwt.model";
import { sessionHandler } from "../model/application.model";
import { UsuarioModel } from "src/core/domain/model/usuario.model";



export class AuthAplicationService {
    private readonly logger = new Logger(AuthAplicationService.name);
    private readonly accessSecret: string;
    private readonly refreshSecret: string;
    private readonly accessExpiresIn: string;
    private readonly adminExpiresIn: string;
    private readonly refreshExpiresIn: string;
    private readonly ttlRefreshSession: number;

    constructor(
        private cacheRepository: ICacheRepository,
        private refreshSessionRepo: IRefreshSessionRepository,
        private jwtService: JwtService,
        private configService: ConfigService
    ) {
        this.accessSecret = this.configService.get<string>('jwtConfig.access_secret');
        this.refreshSecret = this.configService.get<string>('jwtConfig.refresh_secret');
        this.accessExpiresIn = this.configService.get<string>('jwtConfig.access_expires_in');
        this.adminExpiresIn = this.configService.get<string>('jwtConfig.admin_expires_in');
        this.refreshExpiresIn = this.configService.get<string>('jwtConfig.refresh_expires_in');
        this.ttlRefreshSession = this.configService.get<number>('app.ttlRefreshSession');
    }

    /** HMAC-SHA256 token hash — ~0.1ms vs bcrypt's ~100ms; safe because secret has 384 bits of entropy */
    private hashTokenSecret(secret: string): string {
        return createHmac('sha256', this.refreshSecret).update(secret).digest('hex');
    }

    /** Constant-time comparison to prevent timing attacks */
    verifyTokenSecret(secret: string, stored: string): boolean {
        const expected = Buffer.from(this.hashTokenSecret(secret));
        const actual = Buffer.from(stored);
        if (expected.length !== actual.length) return false;
        return timingSafeEqual(expected, actual);
    }



    /** TTL del access token: los roles ADMIN y SUPER_ADMIN usan el TTL de administrador. */
    accessTokenExpiresIn(roles: string[]): string {
        const isAdmin = (roles ?? []).some(r => r === 'SUPER_ADMIN' || r === 'ADMIN');
        return isAdmin ? this.adminExpiresIn : this.accessExpiresIn;
    }

    /** validar que el usuario no tenga mas de 1 session por dispositivo y validar en cache antes que en db */
    public async createRefreshSession(
        sessionActive: AuthCodeStored,
        meta?: { ip?: string, ua?: string, fingerprint?: string })
        : Promise<{ accessToken: string, refreshToken: string }> {
        this.logger.log("INIT - CREATE REFRESH SESSION");
        // let session = sessionActive;
        let sessionHandler: sessionHandler = {} as sessionHandler;
        let accesTokenCache: string | null = await this.cacheRepository.getAccessToken(sessionActive.sessionId);
        let SessionObject: AccessTokenPayload = this.jwtService.decode(accesTokenCache) as AccessTokenPayload;
        // Valido si existe session en cache, si existe la sesion en un mismo dispositivo, se rota la session 
        if (accesTokenCache && this.jwtService.verify(accesTokenCache, { secret: this.accessSecret } as JwtVerifyOptions)) {
            this.logger.log(`session:${SessionObject.sessionId} | DB SESSION ACTIVA - | ROTACION`);
            sessionHandler = await this.rotateSession(SessionObject, meta);
        } else {
            // si no existe, se crea session nueva
            this.logger.log(`session:${sessionActive.sessionId} | DB SESSION INACTIVA - | CREACION`);
            sessionHandler = await this.createSession(sessionActive, meta);
        }
        const payload: AccessTokenPayload = {
            userId: sessionHandler.session.userId,
            username: sessionActive.sub,
            userUuid: sessionActive.userUuid,
            sessionUuid: sessionHandler.session.sessionUuid,
            sessionId: sessionHandler.session.sessionId,
            roles: sessionActive.rol,
            permissions: sessionActive.permisos,
            typeDevice: sessionActive.typeDevice
        }
        const expireToken = this.accessTokenExpiresIn(sessionActive.rol);
        const accessToken = this.jwtService.sign(
            payload,
            { expiresIn: expireToken, secret: this.accessSecret } as JwtSignOptions);

        await this.cacheRepository.setAccessToken(payload.sessionId, accessToken);
        this.logger.log(`Sesión cacheada para usuario ${payload.userUuid} con clave session:${payload.sessionId}`);

        const refreshToken = this.jwtService.sign(
            { refreshToken: sessionHandler.plainToken },
            { expiresIn: this.refreshExpiresIn, secret: this.refreshSecret } as JwtSignOptions);

        this.logger.log("REFRESH SESSION - OK");
        return { accessToken, refreshToken };
    }

    /**
     * Rota la sesión: revoca la actual y crea la siguiente enlazada por `rotation_parent_id`. El enlace es lo
     * que permite distinguir después un refresh token ROTADO (su reutilización delata un robo) de uno cerrado por
     * logout. `parentRowId` es el id (fila) de la sesión que se rota; si no se conoce se consulta por su uuid.
     */
    public async rotateSession(SessionObject: AccessTokenPayload, meta?: { ip?: string, ua?: string, fingerprint?: string }, parentRowId?: number | null): Promise<sessionHandler> {
        const t0 = performance.now();
        const lap = (label: string, prev: number) => {
            const ms = (performance.now() - prev).toFixed(1);
            this.logger.debug(`[ROTATE_PERF] step="${label}" ms=${ms}`);
            return performance.now();
        };
        let t = t0;
        this.logger.log('ROTATE SESSION - INIT');

        const parentId = parentRowId ?? (await this.refreshSessionRepo.findById(SessionObject.sessionUuid))?.id ?? null;

        await Promise.all([
            this.refreshSessionRepo.revokeById(SessionObject.sessionUuid),
            this.cacheRepository.deleteAccessToken(SessionObject.sessionId),
        ]);
        t = lap('db.revokeById + redis.deleteToken (parallel)', t);

        const expiresAt = new Date(Date.now() + this.ttlRefreshSession);
        const secret = randomBytes(48).toString('hex');
        const hash = this.hashTokenSecret(secret);
        t = lap('hmac.hashTokenSecret', t);

        const oldSession = RefreshSessionModel.create({
            id: parentId,
            sessionUuid: SessionObject.sessionUuid,
            sessionId: SessionObject.sessionId,
            userId: SessionObject.userId,
            userUuid: SessionObject.userUuid,
            deviceType: SessionObject.typeDevice,
            deviceFingerprint: meta?.fingerprint,
            refreshTokenHash: null,
            ip: meta?.ip,
            userAgent: meta?.ua,
            expiresAt: null,
        });

        const newSession = RefreshSessionModel.create({
            userId: oldSession.userId,
            userUuid: oldSession.userUuid,
            sessionId: oldSession.sessionId,
            deviceType: oldSession.deviceType,
            deviceFingerprint: oldSession.deviceFingerprint,
            refreshTokenHash: hash,
            ip: oldSession.ip,
            userAgent: oldSession.userAgent,
            expiresAt,
            rotationParentId: oldSession.id,
        });

        const sessionRotated = await this.refreshSessionRepo.rotate(oldSession, newSession);
        t = lap('db.rotate (transaction: update+insert)', t);

        this.logger.debug(`[ROTATE_PERF] TOTAL=${(performance.now() - t0).toFixed(1)}ms`);
        return { plainToken: `${sessionRotated.sessionId}.${sessionRotated.sessionUuid}.${secret}`, session: sessionRotated };
    }

    private async createSession(sessionActive: AuthCodeStored, meta?: { ip?: string, ua?: string, fingerprint?: string }): Promise<sessionHandler> {
        this.logger.warn('CREATE SESSION - INIT');
        const expiresAt = new Date(Date.now() + this.ttlRefreshSession);

        const secret = randomBytes(48).toString('hex');
        const hash = this.hashTokenSecret(secret);
        const session = RefreshSessionModel.create({
            sessionId: sessionActive.sessionId,
            userId: sessionActive.userId,
            userUuid: sessionActive.userUuid,
            deviceType: sessionActive.typeDevice,
            deviceFingerprint: meta?.fingerprint,
            refreshTokenHash: hash,
            ip: meta?.ip,
            userAgent: meta?.ua,
            expiresAt,
        });

        const sessionRepo = await this.refreshSessionRepo.create(session);
        this.logger.log(`session:${session.sessionId} | SESSION OK`);
        return { plainToken: `${sessionRepo.sessionId}.${sessionRepo.sessionUuid}.${secret}`, session: sessionRepo };
    }

    /**
     * Revoca todas las sesiones activas de un usuario dado su sessionId.
     * @param sessionId 
     * @returns 
     */
    async revokeUserSessions(sessionId: any): Promise<number> {
        this.logger.log(`LOGOUT - SessionId: ${sessionId}`);
        const accessToken: any = await this.cacheRepository.getAccessToken(sessionId);
        if (!accessToken) {
            this.logger.warn(`NO SESSION: ${sessionId}`);
            return 0;
        }
        const decodedJWT: any = this.jwtService.decode(accessToken);
        if (!decodedJWT) {
            this.logger.warn(`Failed to decode JWT for sessionId: ${sessionId}`);
            return 0;
        }
        this.logger.log(`CERRANDO SESSION UUID: ${decodedJWT.userUuid} | deviceType: ${decodedJWT.typeDevice}`);
        const response = Promise.all([
            this.refreshSessionRepo.revokeUserSessions(decodedJWT.sessionUuid, decodedJWT.typeDevice),
            this.cacheRepository.deleteAccessToken(sessionId)
        ]);
        const [revokedCount] = await response;
        this.logger.log(`session revoked for userId: ${decodedJWT.userUuid}`);

        return revokedCount;
    }

    /**
     * Cierra TODAS las sesiones de un usuario: las revoca en BD (el refresh token deja de servir) y
     * borra sus access tokens de la caché (deja de pasar el guard sin esperar a que el JWT expire).
     * La BD es obligatoria y su error se propaga; la caché es "mejor esfuerzo": si falla se registra,
     * y el access token cacheado sigue vivo como máximo hasta su expiración.
     */
    async revokeAllUserSessions(userId: number | string): Promise<{ revoked: number; cacheCleared: number; cacheFailed: number }> {
        const id = String(userId);
        // Listar ANTES de revocar: la consulta solo devuelve sesiones no revocadas.
        const active = await this.refreshSessionRepo.getSessionsByUserId(id);
        const sessionIds = [...new Set(active.map(s => s.sessionId).filter(Boolean))];

        const revoked = await this.refreshSessionRepo.revokeAllUserSessions(id);

        const results = await Promise.allSettled(sessionIds.map(sid => this.cacheRepository.deleteAccessToken(sid)));
        const cacheFailed = results.filter(r => r.status === 'rejected').length;
        if (cacheFailed > 0) {
            this.logger.error(`No se pudo borrar ${cacheFailed} access token(s) de la caché del usuario ${id}; expirarán solos.`);
        }
        this.logger.log(`Sesiones cerradas para userId=${id}: bd=${revoked} cache=${sessionIds.length - cacheFailed}`);
        return { revoked, cacheCleared: sessionIds.length - cacheFailed, cacheFailed };
    }

    async createAuthorizationCode(usuario: UsuarioModel, codeChallenge: string, typeDevice: string, CorrelationId: string): Promise<string> {
        const code = randomBytes(32).toString('hex');
        await this.cacheRepository.setAuthCode(
            code,
            {
                userId: usuario.id.getValue(),
                userUuid: usuario.uuid,
                CorrelationId,
                sub: usuario.userName,
                rol: usuario.rol.map(r => r.codigo) as string[],
                permisos: usuario.rol.flatMap(r => r.permisos ? r.permisos.map(p => p.codigo) : []) as string[],
                typeDevice,
                codeChallenge,
                createdAt: Date.now()
            } as AuthCodeStored
        );
        return code;
    }

    hashingCodeChallenge(codeVerifier: string): string {
        const hash = createHash('sha256').update(codeVerifier).digest();
        return hash.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
}