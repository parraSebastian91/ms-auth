import { ConfigModule, ConfigService } from '@nestjs/config';
/*
https://docs.nestjs.com/modules
*/

import { Module } from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { JwtModule, JwtSignOptions } from '@nestjs/jwt';
import { TerminusModule } from '@nestjs/terminus';
import { AuthController } from './controllers/auth.controller';
import { HealthController } from './controllers/health.controller';
import { AuthGuard } from './guards/auth.guard';
import { SecretsModule } from '../secrets/secrets.module';
import { HttpModule } from '@nestjs/axios';
import { LoggerInterceptor } from './middleware/logger.interceptor';
import { RegistroController } from './controllers/registro.controller';

@Module({
  imports: [
    TerminusModule,
    SecretsModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret:
          configService.get<string>('jwtConfig.access_secret'),
        signOptions: { expiresIn: '1h' },
      }),
    }),
    HttpModule.register({
      timeout: 5000,
      maxRedirects: 5,
    }),
  ],
  controllers: [AuthController, RegistroController, HealthController],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: LoggerInterceptor,
    },
    AuthGuard,
    // PermissionsGuard,
    // Aplicar AuthGuard globalmente
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
    // Aplicar PermissionsGuard globalmente después del AuthGuard
    // {
    //     provide: APP_GUARD,
    //     useClass: PermissionsGuard,
    // },
  ],
})
export class HttpServerModule {}
