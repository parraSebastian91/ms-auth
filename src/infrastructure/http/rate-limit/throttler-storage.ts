import { Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ThrottlerStorage, ThrottlerStorageService } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from '@nest-lab/throttler-storage-redis';

type Record = Awaited<ReturnType<ThrottlerStorage['increment']>>;

/**
 * Almacenamiento del rate limit en Redis con respaldo en memoria. Los contadores viven en Redis (compartidos
 * entre réplicas y sobreviven a reinicios). Si Redis falla, cada instancia sigue limitando con su propia
 * memoria en vez de devolver 500 o dejar de limitar: se degrada a "límite por instancia" y se avisa en el log.
 */
export class ResilientThrottlerStorage implements ThrottlerStorage, OnModuleDestroy {
  private readonly logger = new Logger('RateLimit');
  private lastWarnAt = 0;
  private degraded = false;

  private fallback?: ThrottlerStorage & { onApplicationShutdown?: () => void };

  /** `fallback` es opcional y perezoso: la memoria solo se crea si Redis falla (sin temporizadores ociosos). */
  constructor(
    private readonly primary: ThrottlerStorage & { onModuleDestroy?: () => void },
    fallback?: ThrottlerStorage & { onApplicationShutdown?: () => void },
  ) {
    this.fallback = fallback;
  }

  private getFallback(): ThrottlerStorage {
    return (this.fallback ??= new ThrottlerStorageService());
  }

  async increment(key: string, ttl: number, limit: number, blockDuration: number, throttlerName: string): Promise<Record> {
    try {
      const result = await this.primary.increment(key, ttl, limit, blockDuration, throttlerName);
      if (this.degraded) {
        this.degraded = false;
        this.logger.log('Redis disponible de nuevo: el rate limit vuelve a ser compartido entre instancias.');
      }
      return result;
    } catch (error: any) {
      this.degraded = true;
      const now = Date.now();
      if (now - this.lastWarnAt > 30_000) {
        this.lastWarnAt = now;
        this.logger.error(`Redis no disponible para el rate limit (${error?.message ?? error}); usando memoria de esta instancia.`);
      }
      return this.getFallback().increment(key, ttl, limit, blockDuration, throttlerName);
    }
  }

  onModuleDestroy(): void {
    this.primary.onModuleDestroy?.();
    this.fallback?.onApplicationShutdown?.();
  }
}

/**
 * Servicio Redis del rate limit, con un cliente pensado para no colgar las peticiones: falla rápido si no hay
 * conexión (y entonces se usa el respaldo en memoria) y reintenta conectar en segundo plano. El servicio es dueño
 * del cliente y lo cierra al apagar la app.
 */
export function createRedisThrottlerStorage(options: { host: string; port?: number; password?: string; db?: number }): ThrottlerStorageRedisService {
  const logger = new Logger('RateLimit');
  let lastErrorAt = 0;
  const service = new ThrottlerStorageRedisService({
    host: options.host,
    port: options.port ?? 6379,
    password: options.password || undefined,
    db: options.db ?? 0,
    connectTimeout: 2000,
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false, // sin conexión, los comandos fallan al instante
    retryStrategy: times => Math.min(times * 200, 5000),
  });
  service.redis.on('error', err => {
    if (Date.now() - lastErrorAt > 30_000) {
      lastErrorAt = Date.now();
      logger.error(`Conexión Redis del rate limit: ${err?.message ?? err}`);
    }
  });
  return service;
}

/**
 * Devuelve el almacenamiento según la configuración: Redis (por defecto, si hay `redis.host`) o `undefined`
 * (= memoria por instancia). `RATE_LIMIT_STORAGE=memory` fuerza memoria.
 */
export function createThrottlerStorage(config: ConfigService): ThrottlerStorage | undefined {
  const host = config.get<string>('redis.host');
  if (process.env.RATE_LIMIT_STORAGE === 'memory' || !host) return undefined;
  return new ResilientThrottlerStorage(
    createRedisThrottlerStorage({
      host,
      port: config.get<number>('redis.port'),
      password: config.get<string>('redis.password'),
      db: config.get<number>('redis.db'),
    }),
  );
}
