import { Logger } from "@nestjs/common";
import { JwtService, JwtSignOptions, JwtVerifyOptions } from "@nestjs/jwt";
import { createHash, randomBytes } from "crypto";
import { RefreshSessionModel } from "./../../domain/model/RefreshSession.model";
import { ICacheRepository } from "./../../domain/puertos/outbound/CacheRepository.interface";
import { IRefreshSessionRepository } from "./../../domain/puertos/outbound/iRefreshSessionRepository.interface";
import * as bcrypt from 'bcrypt';
import { ConfigService } from "@nestjs/config";
import { AccessTokenPayload } from "./../../domain/model/jwt.model";
import { sessionHandler } from "../model/application.model";
import { UsuarioModel } from "src/core/domain/model/usuario.model";



export class AuthAplicationService {
    private readonly logger = new Logger(AuthAplicationService.name);

    constructor(
        private cacheRepository: ICacheRepository,
        private refreshSessionRepo: IRefreshSessionRepository,
        private jwtService: JwtService,
        private configService: ConfigService
    ) { }



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
        //TODO: Validar que JWTService esta funcionando modularmente, posible error
            console.log(accesTokenCache);
        if (accesTokenCache && this.jwtService.verify(accesTokenCache,{secret: this.configService.get<string>('jwtConfig.access_secret')} as JwtVerifyOptions)) {
            this.logger.log(`session:${SessionObject.sessionId} | DB SESSION ACTIVA - | ROTACION`);
            sessionHandler = await this.rotateSession(SessionObject, meta);
        } else {
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
        const accessToken = this.jwtService.sign(
            payload,
            {
                expiresIn: (sessionActive.rol.includes("SUPER_ADMIN") || sessionActive.rol.includes("ADMIN")) ? process.env.JWT_ADMIN_EXPIRES_IN : process.env.JWT_EXPIRES_IN, secret: process.env.JWT_SECRET
            } as JwtSignOptions);
        // await this.cacheRepository.setAccessToken(
        //     payload.sessionId,
        //     accessToken
        // ).then(() => {
        //     this.logger.log(`Sesión cacheada para usuario ${payload.userUuid} con clave session:${payload.sessionId}`);
        // });

        const refreshToken = this.jwtService.sign(
            { refreshToken: sessionHandler.plainToken },
            { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN, secret: process.env.JWT_REFRESH_SECRET } as JwtSignOptions);

        this.logger.log("REFRESH SESSION - OK");
        return { accessToken, refreshToken };
    }

    public async rotateSession(SessionObject: AccessTokenPayload, meta?: { ip?: string, ua?: string, fingerprint?: string }): Promise<sessionHandler> {
        this.logger.log("ROTATE SESSION - INIT");
        this.refreshSessionRepo.revokeById(SessionObject.sessionUuid);
        this.cacheRepository.deleteAccessToken(SessionObject.sessionId);
        const expiresAt = new Date(Date.now() + this.configService.get<number>('app.ttlRefreshSession') * 86400000);

        SessionObject.sessionId = SessionObject.sessionId;
        const secret = randomBytes(48).toString('hex');
        const hash = await bcrypt.hash(secret, 10);

        const oldSession = RefreshSessionModel.create({
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
            rotationParentId: oldSession.id
        });
        const sessionRotated = await this.refreshSessionRepo.rotate(oldSession, newSession);

        return { plainToken: `${sessionRotated.sessionId}.${sessionRotated.sessionUuid}.${secret}`, session: sessionRotated };
    }

    private async createSession(sessionActive: AuthCodeStored, meta?: { ip?: string, ua?: string, fingerprint?: string }): Promise<sessionHandler> {
        this.logger.warn(`CREATE SESSION - INIT`);
        const expiresAt = new Date(Date.now() + this.configService.get<number>('app.ttlRefreshSession'));

        const secret = randomBytes(48).toString('hex');
        const hash = await bcrypt.hash(secret, 10);
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
        this.logger.log(`CERRANDO SESSION UUID: ${decodedJWT.userUuid} | deviceType: ${decodedJWT.typeDevice}`);
        if (!decodedJWT) {
            this.logger.warn(`Failed to decode JWT for sessionUuid: ${decodedJWT.sessionUuid}`);
            return 0;
        }
        const response = Promise.all([
            this.refreshSessionRepo.revokeUserSessions(decodedJWT.sessionUuid, decodedJWT.typeDevice),
            this.cacheRepository.deleteAccessToken(sessionId)
        ]);
        const [revokedCount] = await response;
        this.logger.log(`session revoked for userId: ${decodedJWT.userUuid}`);

        return revokedCount;
    }

    async createAuthorizationCode(usuario: UsuarioModel, codeChallenge: string, typeDevice: string, sessionId: string): Promise<string> {
        const code = randomBytes(32).toString('hex');
        await this.cacheRepository.setAuthCode(
            code,
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
            } as AuthCodeStored
        );
        return code;
    }

    hashingCodeChallenge(codeVerifier: string): string {
        const hash = createHash('sha256').update(codeVerifier).digest();
        return hash.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
}