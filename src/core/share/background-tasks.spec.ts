import { Logger } from '@nestjs/common';
import { BackgroundTasks } from './background-tasks';

describe('BackgroundTasks', () => {
  const logger = new Logger('test');
  let errors: string[];
  beforeEach(() => {
    errors = [];
    jest.spyOn(Logger.prototype, 'error').mockImplementation((m: any) => { errors.push(String(m)); });
  });
  afterEach(() => jest.restoreAllMocks());

  it('run() devuelve de inmediato: la tarea no bloquea al que la encola', async () => {
    const bg = new BackgroundTasks(logger);
    let release!: () => void;
    let finished = false;
    bg.run('lenta', () => new Promise<void>(r => { release = () => { finished = true; r(); }; }));
    expect(bg.size).toBe(1);
    expect(finished).toBe(false);
    await new Promise(r => setImmediate(r));
    release();
    await bg.whenIdle();
    expect(finished).toBe(true);
    expect(bg.size).toBe(0);
  });

  it('un error (asíncrono o síncrono) se registra y no se propaga', async () => {
    const bg = new BackgroundTasks(logger);
    bg.run('a', async () => { throw new Error('asincrono'); });
    bg.run('b', () => { throw new Error('sincrono'); });
    await expect(bg.whenIdle()).resolves.toBeUndefined();
    expect(errors.some(e => e.includes('[a]') && e.includes('asincrono'))).toBe(true);
    expect(errors.some(e => e.includes('[b]') && e.includes('sincrono'))).toBe(true);
  });

  it('whenIdle espera también a lo que se encole mientras espera', async () => {
    const bg = new BackgroundTasks(logger);
    const order: string[] = [];
    bg.run('uno', async () => { order.push('uno'); bg.run('dos', async () => { order.push('dos'); }); });
    await bg.whenIdle();
    expect(order).toEqual(['uno', 'dos']);
  });

  it('sin tareas pendientes whenIdle resuelve al instante', async () => {
    await expect(new BackgroundTasks(logger).whenIdle()).resolves.toBeUndefined();
  });
});
