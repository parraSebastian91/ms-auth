import { Logger } from '@nestjs/common';
import { ThrottlerStorageService } from '@nestjs/throttler';
import { ResilientThrottlerStorage } from './throttler-storage';

const rec = (totalHits: number) => ({ totalHits, timeToExpire: 60, isBlocked: false, timeToBlockExpire: 0 });

function setup() {
  const primary = { increment: jest.fn(), onModuleDestroy: jest.fn() };
  const fallback = new ThrottlerStorageService();
  const storage = new ResilientThrottlerStorage(primary as any, fallback);
  return { storage, primary, fallback };
}

describe('ResilientThrottlerStorage', () => {
  let errors: string[];
  beforeEach(() => {
    errors = [];
    jest.spyOn(Logger.prototype, 'error').mockImplementation((m: any) => { errors.push(String(m)); });
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  });
  afterEach(() => jest.restoreAllMocks());

  it('usa el almacenamiento principal (Redis) mientras responde', async () => {
    const { storage, primary, fallback } = setup();
    primary.increment.mockResolvedValue(rec(3));
    const spy = jest.spyOn(fallback, 'increment');
    expect(await storage.increment('k', 1000, 5, 1000, 'ip')).toEqual(rec(3));
    expect(primary.increment).toHaveBeenCalledWith('k', 1000, 5, 1000, 'ip');
    expect(spy).not.toHaveBeenCalled();
  });

  it('si Redis falla no lanza: cuenta en la memoria de la instancia y sigue limitando', async () => {
    const { storage, primary } = setup();
    primary.increment.mockRejectedValue(new Error('ECONNREFUSED'));
    const hits = [];
    for (let i = 0; i < 4; i++) hits.push((await storage.increment('k', 60_000, 3, 60_000, 'ip')).totalHits);
    expect(hits).toEqual([1, 2, 3, 4]);
    expect((await storage.increment('k', 60_000, 3, 60_000, 'ip')).isBlocked).toBe(true);
  });

  it('avisa del fallo una sola vez cada 30 s (no inunda el log)', async () => {
    const { storage, primary } = setup();
    primary.increment.mockRejectedValue(new Error('ECONNREFUSED'));
    for (let i = 0; i < 20; i++) await storage.increment('k', 1000, 5, 1000, 'ip');
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/Redis no disponible/);
  });

  it('cuando Redis vuelve, se retoma el almacenamiento compartido', async () => {
    const { storage, primary } = setup();
    primary.increment.mockRejectedValueOnce(new Error('caído')).mockResolvedValue(rec(7));
    await storage.increment('k', 1000, 5, 1000, 'ip');
    expect((await storage.increment('k', 1000, 5, 1000, 'ip')).totalHits).toBe(7);
  });

  it('el respaldo en memoria es perezoso: no se crea si Redis nunca falla', async () => {
    const primary = { increment: jest.fn().mockResolvedValue(rec(1)), onModuleDestroy: jest.fn() };
    const storage = new ResilientThrottlerStorage(primary as any);
    await storage.increment('k', 1000, 5, 1000, 'ip');
    expect((storage as any).fallback).toBeUndefined();
    expect(() => storage.onModuleDestroy()).not.toThrow();
  });

  it('al apagar cierra el cliente de Redis y limpia los temporizadores del respaldo', () => {
    const { storage, primary, fallback } = setup();
    const shutdown = jest.spyOn(fallback, 'onApplicationShutdown');
    storage.onModuleDestroy();
    expect(primary.onModuleDestroy).toHaveBeenCalled();
    expect(shutdown).toHaveBeenCalled();
  });
});
