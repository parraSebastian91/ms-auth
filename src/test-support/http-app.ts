import { ModuleMetadata } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { ThrottlerModule } from '@nestjs/throttler';
import * as request from 'supertest';
import { createThrottlerOptions } from 'src/infrastructure/http/rate-limit/rate-limit';
import { ValidationPipe } from 'src/infrastructure/http/pipes/validation.pipe';
import { AuthMetricsService } from 'src/infrastructure/metrics/auth-metrics.service';

const cookieParser = require('cookie-parser');

/** Sesión falsa con la misma forma que express-session (save/destroy con callback). */
export function makeFakeSession(over: Record<string, any> = {}): Record<string, any> {
  return {
    id: 'sess-1',
    save: jest.fn((cb: (e?: any) => void) => cb()),
    destroy: jest.fn((cb: (e?: any) => void) => cb()),
    ...over,
  };
}

export function makeMetricsMock() {
  return { loginAttempt: jest.fn(), sessionRefreshed: jest.fn(), passwordResetRequested: jest.fn() };
}

/** Levanta solo los controladores indicados, con el mismo pipe/cookies que main.ts y sin guards globales. */
export async function createHttpApp(meta: Pick<ModuleMetadata, 'controllers' | 'providers'>, session = makeFakeSession()) {
  const metrics = makeMetricsMock();
  const moduleRef = await Test.createTestingModule({
    imports: [ThrottlerModule.forRoot(createThrottlerOptions())],
    controllers: meta.controllers,
    providers: [...(meta.providers ?? []), { provide: AuthMetricsService, useValue: metrics }],
  }).compile();
  const app = moduleRef.createNestApplication({ logger: false });
  app.useGlobalPipes(new ValidationPipe());
  app.use(cookieParser());
  app.use((req: any, _res: any, next: () => void) => { req.session = session; next(); });
  await app.init();
  return { app, session, metrics, http: () => request(app.getHttpServer()) };
}
