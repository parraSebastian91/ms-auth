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
import { VaultService } from '../secrets/vault.service';
import { HttpModule } from '@nestjs/axios';
import { LoggerInterceptor } from './middleware/logger.interceptor';

@Module({
    imports: [
        TerminusModule,
        SecretsModule,
        JwtModule.registerAsync({
            imports: [SecretsModule],
            inject: [VaultService],
            useFactory: async (vaultService: VaultService) => ({
                secret: vaultService.getSecret(
                    'auth-service',
                    'jwt_secret',
                    process.env.JWT_SECRET || 'TU_SECRETO_AQUI'
                ),
                signOptions: { expiresIn: '1h' },
            }),
        }),
        HttpModule.register({
            timeout: 5000,
            maxRedirects: 5,
        }),
    ],
    controllers: [
        AuthController,
        HealthController
    ],
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
export class HttpServerModule { }
