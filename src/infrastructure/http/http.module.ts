import { ConfigModule, ConfigService } from '@nestjs/config';
/*
https://docs.nestjs.com/modules
*/

import { Module } from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { JwtModule, JwtSignOptions } from '@nestjs/jwt';
import { TerminusModule } from '@nestjs/terminus';
import { AuthorizationController } from './controllers/authorization.controller';
import { SessionController } from './controllers/session.controller';
import { PasswordResetController } from './controllers/passwordReset.controller';
import { HealthController } from './controllers/health.controller';
import { AuthGuard } from './guards/auth.guard';
import { HttpModule } from '@nestjs/axios';
import { LoggerInterceptor } from './middleware/logger.interceptor';
import { RegistroController } from './controllers/registro.controller';
import { UserProfileController } from './controllers/userProfile.controller';
import { JwtAccessGuard } from './guards/jwt-access.guard';
import { PermissionsGuard } from './guards/permissions.guard';

@Module({
  imports: [
    TerminusModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('jwtConfig.access_secret'),
        signOptions: { expiresIn: '1h' },
      }),
    }),
    HttpModule.register({
      timeout: 5000,
      maxRedirects: 5,
    }),
  ],
  controllers: [
    AuthorizationController,
    SessionController,
    PasswordResetController,
    RegistroController,
    HealthController,
    UserProfileController,
  ],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: LoggerInterceptor,
    },
    AuthGuard,
    JwtAccessGuard,
    PermissionsGuard,
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
