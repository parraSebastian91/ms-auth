/*
https://docs.nestjs.com/modules
*/

import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { JwtModule, JwtSignOptions } from '@nestjs/jwt';
import { TerminusModule } from '@nestjs/terminus';
import { AuthController } from './controllers/auth.controller';
import { HealthController } from './controllers/health.controller';
import { AuthGuard } from './guards/auth.guard';
import { PermissionsGuard } from './guards/permissions.guard';
import { BffProxyController } from './controllers/bffproxy.controller';
import { SecretsModule } from '../secrets/secrets.module';

@Module({
    imports: [
        TerminusModule,
        SecretsModule,
        JwtModule.register({
            secret: process.env.JWT_SECRET || 'TU_SECRETO_AQUI',
            signOptions: { expiresIn: process.env.JWT_EXPIRES_IN || '1h' } as JwtSignOptions,
        }),
    ],
    controllers: [
        AuthController,
        BffProxyController,
        HealthController
    ],
    providers: [
        AuthGuard,
        PermissionsGuard,
        // Aplicar AuthGuard globalmente
        {
            provide: APP_GUARD,
            useClass: AuthGuard,
        },
        // Aplicar PermissionsGuard globalmente después del AuthGuard
        {
            provide: APP_GUARD,
            useClass: PermissionsGuard,
        },
    ],
})
export class HttpServerModule { }
