import { JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import { ThrottlerModule } from '@nestjs/throttler';
import { DiskHealthIndicator, HealthCheckService, MemoryHealthIndicator, TypeOrmHealthIndicator } from '@nestjs/terminus';
import { getToken } from '@willsoto/nestjs-prometheus';
import { AUTHORIZATION_USE_CASE } from 'src/core/domain/puertos/inbound/IAuthorizationUseCase.interface';
import { PASSWORD_RESET_USE_CASE } from 'src/core/domain/puertos/inbound/IPasswordResetUseCase.interface';
import { SESSION_USE_CASE } from 'src/core/domain/puertos/inbound/ISessionUseCase.interface';
import { USER_PROFILE_USE_CASE } from 'src/core/domain/puertos/inbound/IUserProfile.usecase.interface';
import { AuthorizationController } from 'src/infrastructure/http/controllers/authorization.controller';
import { HealthController } from 'src/infrastructure/http/controllers/health.controller';
import { PasswordResetController } from 'src/infrastructure/http/controllers/passwordReset.controller';
import { RegistroController } from 'src/infrastructure/http/controllers/registro.controller';
import { SessionController } from 'src/infrastructure/http/controllers/session.controller';
import { UserProfileController } from 'src/infrastructure/http/controllers/userProfile.controller';
import { buildOpenApiDocument } from 'src/infrastructure/http/openapi/build-openapi-document';
import { createThrottlerOptions } from 'src/infrastructure/http/rate-limit/rate-limit';
import { AuthMetricsService } from 'src/infrastructure/metrics/auth-metrics.service';

/** App (SIN inicializar) con los controladores REALES y dependencias de mentira (sin BD, Redis ni Vault). */
export async function createOpenApiApp() {
  const stub = { useValue: {} };
  const moduleRef = await Test.createTestingModule({
    imports: [ThrottlerModule.forRoot(createThrottlerOptions())],
    controllers: [AuthorizationController, SessionController, PasswordResetController, RegistroController, UserProfileController, HealthController],
    providers: [
      { provide: AUTHORIZATION_USE_CASE, ...stub },
      { provide: SESSION_USE_CASE, ...stub },
      { provide: PASSWORD_RESET_USE_CASE, ...stub },
      { provide: USER_PROFILE_USE_CASE, ...stub },
      { provide: 'REGISTRO_USE_CASE', ...stub },
      { provide: AuthMetricsService, ...stub },
      { provide: getToken('auth_register_attempts_total'), ...stub },
      { provide: JwtService, ...stub },
      { provide: HealthCheckService, ...stub },
      { provide: TypeOrmHealthIndicator, ...stub },
      { provide: MemoryHealthIndicator, ...stub },
      { provide: DiskHealthIndicator, ...stub },
    ],
  }).compile();
  return moduleRef.createNestApplication({ logger: false });
}

export async function createOpenApiDocument() {
  const app = await createOpenApiApp();
  await app.init();
  const document = buildOpenApiDocument(app, '1.0.0');
  await app.close();
  return document;
}
