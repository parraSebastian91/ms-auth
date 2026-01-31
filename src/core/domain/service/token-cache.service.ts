import { Inject, Injectable, Logger } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

@Injectable()
export class TokenCacheService {
  private readonly logger = new Logger(TokenCacheService.name);

  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) { }

  async setRefreshToken(token: string, userId: string, typeDevice: string, ttlSeconds: number = 3600): Promise<void> {
    const key = `refresh_token:${userId}:${typeDevice}`;
    this.logger.log(`[Redis] SET key: ${key} ttl: ${ttlSeconds}s`);
    await this.cacheManager.set(key, token, ttlSeconds * 1000); // Convertir a ms
  }

  async getRefreshToken(userId: string, typeDevice: string): Promise<string | null> {
    const key = `refresh_token:${userId}:${typeDevice}`;
    const value = await this.cacheManager.get<string>(key);
    this.logger.log(`[Redis] GET key: ${key} found: ${!!value}`);
    return value || null;
  }

  async deleteRefreshToken(userId: string, typeDevice: string): Promise<void> {
    const key = `refresh_token:${userId}:${typeDevice}`;
    this.logger.log(`[Redis] DEL key: ${key}`);
    await this.cacheManager.del(key);
  }

  // Métodos JSON genéricos
  async setJson(key: string, value: any, ttlSeconds: number = 3600): Promise<void> {
    const ttlMs = ttlSeconds * 1000; // Convertir segundos a milisegundos
    this.logger.log(`[Redis] SET JSON key: ${key} ttl: ${ttlSeconds}s`);
    await this.cacheManager.set(key, JSON.stringify(value), ttlMs);
  }

  async getJson<T = any>(key: string): Promise<T | null> {
    const v = await this.cacheManager.get<string>(key);
    this.logger.log(`[Redis] GET JSON key: ${key} found: ${!!v}`);
    return v ? JSON.parse(v) : null;
  }

  async deleteKey(key: string): Promise<void> {
    this.logger.log(`[Redis] DEL key: ${key}`);
    await this.cacheManager.del(key);
  }

  // Debug: listar todas las claves (solo desarrollo)
  async getAllKeys(): Promise<string[]> {
    // cache-manager may expose stores[] or a single store; use both safely
    const stores: any[] = (this.cacheManager as any).stores ?? ((this.cacheManager as any).store ? [(this.cacheManager as any).store] : []);
    const keysArrays = await Promise.all(stores.map(s => (s.getKeys ? s.getKeys() : [])));
    const keys = ([] as string[]).concat(...keysArrays);
    this.logger.log(`[Redis] Keys: ${JSON.stringify(keys)}`);
    return keys || [];
  }
}