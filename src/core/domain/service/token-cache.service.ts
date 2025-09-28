import { Inject, Injectable } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

@Injectable()
export class TokenCacheService {

    constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) { }


    async setRefreshToken(token: string, userId: string, typeDevice: string, ttlSeconds: number = 3600): Promise<void> {
        const key = `refresh_token:${userId}:${typeDevice}`;
        console.log(`[Redis] SET key: ${key} value: ${token} ttl: ${ttlSeconds}`);
        await this.cacheManager.set(key, token, ttlSeconds);
    }

    async getRefreshToken(userId: string, typeDevice: string): Promise<string | null> {
        const key = `refresh_token:${userId}:${typeDevice}`;
        const value = await this.cacheManager.get<string>(key);
        console.log(`[Redis] GET key: ${key} value: ${value}`);
        return value;
    }

    async deleteRefreshToken(userId: string, typeDevice: string): Promise<void> {
        const key = `refresh_token:${userId}:${typeDevice}`;
        console.log(`[Redis] DEL key: ${key}`);
        await this.cacheManager.del(key);
    }
}
