/*
https://docs.nestjs.com/providers#services
*/


import { Injectable } from '@nestjs/common';
import { TokenCacheService } from './token-cache.service';
import { UsuarioModel } from '../model/usuario.model';
import { IAuthService } from '../puertos/inbound/IAuthService.interface';
import { IUsuarioRepository } from '../puertos/outbound/iUsuarioRepository.interface';
import * as bcrypt from 'bcrypt';
import { UserNotFoundError } from 'src/core/share/errors/UserNotFound.error';
import { LoginError } from 'src/core/share/errors/LoginError.error';
import { JwtService } from '@nestjs/jwt';
import { randomBytes } from 'crypto';
import { IRefreshSessionRepository } from '../puertos/outbound/iRefreshSessionRepository.interface';
import { UsuarioEntity } from 'src/infrastructure/database/entities/usuario.entity';
import { SessionExistsError } from 'src/core/share/errors/sessionExists.error';

@Injectable()
export class AuthService implements IAuthService {

    constructor(
        private usuarioRepository: IUsuarioRepository,
        private jwtService: JwtService,
        private tokenCacheService: TokenCacheService,
        private refreshSessionRepo: IRefreshSessionRepository
    ) { }

    private refreshTtlDays(): number {
        return Number(process.env.JWT_REFRESH_DAYS ?? 7);
    }
    /** validar que el usuario no tenga mas de 1 session por dispositivo y validar en cache antes que en db */
    private async createRefreshSession(user: UsuarioModel, deviceType: string, meta?: { ip?: string, ua?: string, fingerprint?: string }) {
        const secret = randomBytes(48).toString('hex');
        const hash = await bcrypt.hash(secret, 10);
        const expiresAt = new Date(Date.now() + this.refreshTtlDays() * 86400000);

        const existing = await this.refreshSessionRepo.findByUserAndDevice(user.id.getValue(), deviceType);
        let plainToken = '';
        if (existing) {
            plainToken = await this.rotateSession(existing);
        } else {
            const session = await this.refreshSessionRepo.create({
                user: new UsuarioEntity(user.id.getValue()),
                deviceType,
                deviceFingerprint: meta?.fingerprint,
                refreshTokenHash: hash,
                ip: meta?.ip,
                userAgent: meta?.ua,
                expiresAt
            });

            plainToken = `${session.id}.${secret}`;

            // Cache ligera (sin secreto)
            await this.tokenCacheService.setJson(
                `refresh_session:${session.id}`,
                { userId: user.id.getValue(), deviceType, exp: session.expiresAt.toISOString(), revoked: 0 },
                Math.floor((expiresAt.getTime() - Date.now()) / 1000)
            );
        }
        return plainToken;
    }

    private async rotateSession(oldSession: any) {
        // Revocar anterior
        // implementar revokeById en refreshSessionRepo
        await this.refreshSessionRepo.revokeById(oldSession.id);
        await this.tokenCacheService.deleteKey(`refresh_session:${oldSession.id}`);

        // Crear nueva sesión encadenada (rotationParentId)
        const secret = randomBytes(48).toString('hex');
        const hash = await bcrypt.hash(secret, 10);
        const expiresAt = new Date(Date.now() + this.refreshTtlDays() * 86400000);

        const newSession = await this.refreshSessionRepo.rotate(oldSession, {
            user: oldSession.user.id,
            deviceType: oldSession.deviceType,
            deviceFingerprint: oldSession.deviceFingerprint,
            refreshTokenHash: hash,
            ip: oldSession.ip,
            userAgent: oldSession.userAgent,
            expiresAt,
            rotationParentId: oldSession.id
        });

        const plainToken = `${newSession.id}.${secret}`;
        await this.tokenCacheService.setJson(
            `refresh_session:${newSession.id}`,
            { user: newSession.user, deviceType: newSession.deviceType, exp: expiresAt.toISOString(), revoked: 0 },
            Math.floor((expiresAt.getTime() - Date.now()) / 1000)
        );
        return plainToken;
    }

    /** Actualizarpara flujo nuevo
     * validar token en cache, si no existe validar en db. no en ambos de igual manera. 
     */
    async refreshToken(token: string, userId: string, typeDevice: string): Promise<{ access_token: string, refresh_token: string } | null> {
        try {
            // Nuevo flujo híbrido
            if (token.includes('.')) {
                const [sessionIdStr, secret] = token.split('.');
                const sessionId = Number(sessionIdStr);
                if (!sessionId || !secret) return null;

                // Cache lookup
                const cacheKey = `refresh_session:${sessionId}`;
                const cached = await this.tokenCacheService.getJson(cacheKey);
                let session = null;

                if (cached) {
                    if (cached.revoked === 1) return null;
                    if (cached.deviceType !== typeDevice || String(cached.userId) !== userId) return null;
                }

                // Fetch DB (si no hay cache o para verificar hash)
                session = await this.refreshSessionRepo.findById(sessionId);
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
                const access_token = this.jwtService.sign(payload, {
                    expiresIn: (payload.rol.includes("SUPER_ADMIN") || payload.rol.includes("ADMIN")) ? process.env.JWT_ADMIN_EXPIRES_IN : process.env.JWT_EXPIRES_IN,
                    secret: process.env.JWT_SECRET
                });

                // Rotación
                const newRefresh = await this.rotateSession(session);
                return { access_token, refresh_token: newRefresh };
            }

            // Fase transitoria: si token viejo (sin '.')
            const storedToken = await this.tokenCacheService.getRefreshToken(userId, typeDevice);
            if (!storedToken || storedToken !== token) return null;

            const usuarioDB = await this.usuarioRepository.getUsuarioById(Number(userId));
            if (!usuarioDB) return null;
            const usuario = UsuarioModel.create(usuarioDB);
            const payload = {
                id: usuario.id.getValue(),
                sub: usuario.userName,
                rol: usuario.rol.map(r => r.nombre),
                permisos: usuario.rol.flatMap(r => r.permisos ? r.permisos.map(p => p.nombre) : [])
            };
            const access_token = this.jwtService.sign(payload, {
                expiresIn: (payload.rol.includes("SUPER_ADMIN") || payload.rol.includes("ADMIN")) ? process.env.JWT_ADMIN_EXPIRES_IN : process.env.JWT_EXPIRES_IN,
                secret: process.env.JWT_SECRET
            });

            // Migración: crear sesión nueva y no volver a emitir formato viejo
            const newRefresh = await this.createRefreshSession(usuario, typeDevice);
            // Revoca cache legacy
            await this.tokenCacheService.deleteRefreshToken(userId, typeDevice);

            return { access_token, refresh_token: newRefresh };
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


    async login(username: string, password: string, typeDevice: string): Promise<{ access_token: string, refresh_token: string } | null> {
        const usuarioDB = await this.usuarioRepository.getUsuarioByUsername(username);
        if (!usuarioDB) {
            throw new UserNotFoundError("Usuario no encontrado");
        }
        const usuario = UsuarioModel.create(usuarioDB);
        if (!await bcrypt.compare(password, usuario.password)) {
            throw new LoginError("Usuario no encontrado o contraseña incorrecta");
        }
        delete usuario.password;
        const payload = {
            id: usuario.id.getValue(),
            sub: usuario.userName,
            rol: usuario.rol.map(r => r.codigo),
            permisos: usuario.rol.flatMap(r => r.permisos ? r.permisos.map(p => p.codigo) : [])
        };
        const access_token = this.jwtService.sign(payload, { expiresIn: process.env.JWT_EXPIRES_IN, secret: process.env.JWT_SECRET });

        // Nuevo: siempre formato <id>.<secret>
        const refresh_token = await this.createRefreshSession(usuario, typeDevice);

        return { access_token, refresh_token };
    }
}
