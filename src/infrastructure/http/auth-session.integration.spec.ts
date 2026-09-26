import { Controller, Get, UnauthorizedException } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { ThrottlerModule } from '@nestjs/throttler';
import * as request from 'supertest';
import { AUTHORIZATION_USE_CASE } from 'src/core/domain/puertos/inbound/IAuthorizationUseCase.interface';
import { SESSION_USE_CASE } from 'src/core/domain/puertos/inbound/ISessionUseCase.interface';
import { AuthMetricsService } from 'src/infrastructure/metrics/auth-metrics.service';
import { makeMetricsMock } from 'src/test-support/http-app';
import { AuthorizationController } from './controllers/authorization.controller';
import { AuthGuard } from './guards/auth.guard';
import { createThrottlerOptions } from './rate-limit/rate-limit';
import { ValidationPipe } from './pipes/validation.pipe';

const cookieParser = require('cookie-parser');
const session = require('express-session');

@Controller('protegido')
class ProtectedController {
  @Get() ok() { return { ok: true }; }
}

/** express-session REAL (firma de cookie incluida) + AuthGuard global + controlador de autorización. */
async function setup() {
  const authorization = { ExecuteAuthorize: jest.fn(), ExecuteToken: jest.fn().mockResolvedValue({ accessToken: 'AT', refreshToken: 'RT' }) };
  const sessions = {
    ExecuteValidateSession: jest.fn(async ({ sessionId }: any) => {
      if (sessionId !== validId) throw new UnauthorizedException('Por favor inicia sesión.');
      return true;
    }),
  };
  let validId = '';
  const moduleRef = await Test.createTestingModule({
    imports: [ThrottlerModule.forRoot(createThrottlerOptions())],
    controllers: [AuthorizationController, ProtectedController],
    providers: [
      { provide: AUTHORIZATION_USE_CASE, useValue: authorization },
      { provide: SESSION_USE_CASE, useValue: sessions },
      { provide: AuthMetricsService, useValue: makeMetricsMock() },
      { provide: APP_GUARD, useClass: AuthGuard },
    ],
  }).compile();
  const app = moduleRef.createNestApplication({ logger: false });
  app.useGlobalPipes(new ValidationPipe());
  app.use(cookieParser());
  app.use(session({ name: 'auth.session', secret: 'secreto-de-prueba', resave: false, saveUninitialized: false, cookie: { httpOnly: true } }));
  await app.init();
  return {
    app, authorization, sessions,
    setValidId: (id: string) => { validId = id; },
    agent: () => request.agent(app.getHttpServer()),
  };
}

const tokenBody = { code: 'abc', codeVerifier: 'ver', typeDevice: 'WEB', cid: 'cid-1' };
const idFromSetCookie = (res: request.Response) => {
  const raw = (res.headers['set-cookie'] as unknown as string[]).find(c => c.startsWith('auth.session='))!;
  return decodeURIComponent(raw.split(';')[0].split('=')[1]).split(':')[1].split('.')[0];
};

describe('Sesión de punta a punta (express-session real + AuthGuard)', () => {
  it('el id con el que /token crea la sesión es el mismo que valida el guard en la petición siguiente', async () => {
    const { agent, authorization, sessions, setValidId } = await setup();
    const client = agent();

    const res = await client.post('/security/token').send(tokenBody);
    expect(res.status).toBe(200);
    const cookieId = idFromSetCookie(res);
    setValidId(cookieId);

    const usedByToken = authorization.ExecuteToken.mock.calls[0][0].sessionId;
    expect(usedByToken).toBe(cookieId);

    const protectedRes = await client.get('/protegido');
    expect(protectedRes.status).toBe(200);
    expect(sessions.ExecuteValidateSession).toHaveBeenCalledWith({ sessionId: cookieId });
  });

  it('una cookie auth.session forjada NO permite elegir el sessionId con el que se emite la sesión', async () => {
    const { agent, authorization } = await setup();
    const res = await agent().post('/security/token').set('Cookie', 'auth.session=s:id-de-otra-victima.firma-falsa').send(tokenBody);

    expect(res.status).toBe(200);
    const usedByToken = authorization.ExecuteToken.mock.calls[0][0].sessionId;
    expect(usedByToken).not.toBe('id-de-otra-victima');
    expect(usedByToken).toBe(idFromSetCookie(res)); // el id emitido es el que el servidor generó
  });

  it('una cookie forjada tampoco pasa el guard: se valida con un id generado por el servidor', async () => {
    const { agent, sessions, setValidId } = await setup();
    setValidId('id-de-otra-victima');
    const res = await agent().get('/protegido').set('Cookie', 'auth.session=s:id-de-otra-victima.firma-falsa');

    expect(res.status).toBe(401);
    expect(sessions.ExecuteValidateSession).toHaveBeenCalledTimes(1);
    expect(sessions.ExecuteValidateSession.mock.calls[0][0].sessionId).not.toBe('id-de-otra-victima');
  });

  it('sin cookie el guard responde 401 (no 500)', async () => {
    const { agent } = await setup();
    expect((await agent().get('/protegido')).status).toBe(401);
  });

  it('las rutas @Public (authorize, token) no exigen sesión previa', async () => {
    const { agent, authorization } = await setup();
    authorization.ExecuteAuthorize.mockResolvedValue([]);
    const res = await agent().post('/security/authorize').send({ username: 'a', password: 'b', code_challenge: 'c', typeDevice: 'WEB', CorrelationId: 'x' });
    expect(res.status).toBe(200);
  });
});
