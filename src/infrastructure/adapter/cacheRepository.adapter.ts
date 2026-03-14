import { CACHE_MANAGER } from "@nestjs/cache-manager";
import { Inject } from "@nestjs/common";
import { ICacheRepository } from "./../../core/domain/puertos/outbound/CacheRepository.interface";
import { Cache } from 'cache-manager';
import { ConfigService } from "@nestjs/config";

export class CacheRepositoryAdapter implements ICacheRepository {

    key = {
        authCode: (code: string) => `auth_code:${code}`,
        session: (sessionId: string) => `session:${sessionId}`
    }

    constructor(
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
        private configService: ConfigService
    ) { }

    async setAuthCode(code: string, authCode: AuthCodeStored): Promise<void> {
        const key = this.key.authCode(code);
        await this.cacheManager.set(key, JSON.stringify(authCode), this.configService.get<number>('app.ttlAuthCode'));
    }

    async getAuthCode(code: string): Promise<AuthCodeStored | null> {
        const key = this.key.authCode(code);
        const data = await this.cacheManager.get<string>(key);
        if (!data) return null;
        return JSON.parse(data) as AuthCodeStored;
    }

    async deleteAuthCode(code: string): Promise<void> {
        const key = this.key.authCode(code);
        await this.cacheManager.del(key);
    }

    async setAccessToken(sessionId: string, token: string): Promise<void> {
        const key = this.key.session(sessionId);
        await this.cacheManager.set(key, token, this.configService.get<number>('app.ttlSession'));
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

}