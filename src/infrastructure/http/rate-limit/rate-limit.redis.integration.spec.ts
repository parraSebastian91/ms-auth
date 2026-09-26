import Redis from 'ioredis';
import { PASSWORD_RESET_USE_CASE } from 'src/core/domain/puertos/inbound/IPasswordResetUseCase.interface';
import { createHttpApp } from 'src/test-support/http-app';
import { PasswordResetController } from '../controllers/passwordReset.controller';
import { createThrottlerOptions } from './rate-limit';
import { createRedisThrottlerStorage, ResilientThrottlerStorage } from './throttler-storage';

/**
 * Requiere un Redis real:  docker run -d --rm -p 6390:6379 redis:7-alpine
 *                          TEST_REDIS_URL=redis://localhost:6390 npx jest rate-limit.redis
 * Sin TEST_REDIS_URL se omite.
 */
const waitUntilReady = (redis: Redis) =>
  redis.status === 'ready' ? Promise.resolve() : new Promise<void>(resolve => redis.once('ready', () => resolve()));

const url = process.env.TEST_REDIS_URL;
const suite = url ? describe : describe.skip;

suite('Rate limit con Redis real', () => {
  const { hostname, port } = new URL(url ?? 'redis://localhost:6379');
  const redisOpts = { host: hostname, port: Number(port) };
  let admin: Redis;
  const apps: { close: () => Promise<void> }[] = [];

  beforeAll(() => { admin = new Redis(redisOpts); });
  beforeEach(async () => { await admin.flushall(); });
  afterAll(async () => { for (const a of apps) await a.close(); await admin.quit(); });

  /** Una "réplica" del servicio: su propia app y su propio cliente Redis. */
  async function replica(options: { host: string; port: number } = redisOpts) {
    const reset = { ExecuteRequestReset: jest.fn().mockResolvedValue({ message: 'ok' }), ExecuteValidateResetToken: jest.fn(), ExecuteResetPassword: jest.fn() };
    const service = createRedisThrottlerStorage(options);
    // Con enableOfflineQueue=false, una petición anterior a la conexión usaría el respaldo en memoria;
    // en el servicio real la conexión se abre al arrancar, mucho antes de la primera petición.
    if (options.port === redisOpts.port) await waitUntilReady(service.redis as Redis);
    const storage = new ResilientThrottlerStorage(service);
    const ctx = await createHttpApp(
      { controllers: [PasswordResetController], providers: [{ provide: PASSWORD_RESET_USE_CASE, useValue: reset }] },
      undefined,
      createThrottlerOptions(storage),
    );
    let closing: Promise<void> | undefined;
    const close = () => (closing ??= ctx.app.close()); // idempotente: el test puede cerrarla antes que afterAll
    apps.push({ close });
    return { ...ctx, reset, close };
  }
  const request = (r: Awaited<ReturnType<typeof replica>>, correo = 'ana@test.cl') => r.http().post('/security/password-reset/request').send({ correo });

  it('el contador se COMPARTE entre réplicas: 3 solicitudes en A y la 4.ª, en B, da 429', async () => {
    const a = await replica();
    const b = await replica();
    for (let i = 0; i < 3; i++) expect((await request(a)).status).toBe(201);

    const blocked = await request(b);
    expect(blocked.status).toBe(429);
    expect(b.reset.ExecuteRequestReset).not.toHaveBeenCalled();
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('los contadores sobreviven a un reinicio del servicio (nueva instancia, mismo Redis)', async () => {
    const before = await replica();
    for (let i = 0; i < 3; i++) await request(before);
    await before.close();

    const after = await replica();
    expect((await request(after)).status).toBe(429);
  });

  it('las claves llevan prefijo, expiran y no exponen el correo ni el username en claro', async () => {
    const a = await replica();
    await request(a, 'ana.secreta@test.cl');

    const keys = await admin.keys('*');
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys) {
      expect(key).toContain('ms-identity:ratelimit:');
      expect(key).not.toMatch(/ana|secreta|test\.cl/i);
      expect(await admin.pttl(key)).toBeGreaterThan(0);
    }
  });

  it('otra cuenta no queda bloqueada por la de otra réplica', async () => {
    const a = await replica();
    const b = await replica();
    for (let i = 0; i < 4; i++) await request(a);
    expect((await request(b, 'beto@test.cl')).status).toBe(201);
  });

  it('con Redis caído no hay 500: cada réplica limita con su memoria', async () => {
    const down = await replica({ host: 'localhost', port: 6399 }); // nadie escucha ahí
    for (let i = 0; i < 3; i++) expect((await request(down)).status).toBe(201);
    expect((await request(down)).status).toBe(429);
  });
});
