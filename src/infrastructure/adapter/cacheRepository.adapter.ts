import { CACHE_MANAGER } from "@nestjs/cache-manager";
import { Inject } from "@nestjs/common";
import { ICacheRepository } from "./../../core/domain/puertos/outbound/CacheRepository.interface";
import { Cache } from 'cache-manager';
import { ConfigService } from "@nestjs/config";

export class CacheRepositoryAdapter implements ICacheRepository {

    private readonly EMAIL_VERIFY_TTL_MS = 10 * 60 * 1000; // 10 minutos

    key = {
        authCode:     (code: string)     => `auth_code:${code}`,
        session:      (sessionId: string) => `session:${sessionId}`,
        emailVerify:  (userUuid: string)  => `email_verify:${userUuid}`,
    }

    constructor(
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
        private configService: ConfigService
    ) { }
    // Guarda el codigo de uso unico al Authenticar
    async setAuthCode(code: string, authCode: AuthCodeStored): Promise<void> {
        const key = this.key.authCode(code);
        await this.cacheManager.set(key, JSON.stringify(authCode), this.configService.get<number>('app.ttlAuthCode'));
    }

    // Obtiene el codigo de uso unico al autenticar
    async getAuthCode(code: string): Promise<AuthCodeStored | null> {
        const key = this.key.authCode(code);
        const data = await this.cacheManager.get<string>(key);
        if (!data) return null;
        return JSON.parse(data) as AuthCodeStored;
    }

    // Elimina el codigo de uso unico al autenticar
    async deleteAuthCode(code: string): Promise<void> {
        const key = this.key.authCode(code);
        await this.cacheManager.del(key);
    }

    async setAccessToken(sessionId: string, token: string): Promise<void> {
        const key = this.key.session(sessionId);
        console.log("sessionTTL: ", this.configService.get<number>('app.ttlSession'));
        await this.cacheManager.set(key, token, 0);
    }

    async getAccessToken(sessionId: string): Promise<string | null> {
        const key = this.key.session(sessionId);
        const data = await this.cacheManager.get<string>(key);
        if (!data) return null;
        return data;
    }

    async deleteAccessToken(sessionId: string): Promise<void> {
        const key = this.key.session(sessionId);
        await this.cacheManager.del(key);
    }

    async setEmailVerificationCode(userUuid: string, codeHash: string): Promise<void> {
        const key = this.key.emailVerify(userUuid);
        await this.cacheManager.set(key, codeHash, this.EMAIL_VERIFY_TTL_MS);
    }

    async getEmailVerificationCode(userUuid: string): Promise<string | null> {
        const key = this.key.emailVerify(userUuid);
        const data = await this.cacheManager.get<string>(key);
        return data ?? null;
    }

    async deleteEmailVerificationCode(userUuid: string): Promise<void> {
        const key = this.key.emailVerify(userUuid);
        await this.cacheManager.del(key);
    }

}