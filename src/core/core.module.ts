/*
https://docs.nestjs.com/modules
*/

import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { DynamicModule, Module, Type } from '@nestjs/common';
import { Cache } from 'cache-manager';
import { AuthAplicationService } from './aplication/service/auth.service';
import { AuthUseCase } from './aplication/useCase/auth/auth.usecase';
import { IUsuarioRepository } from './domain/puertos/outbound/iUsuarioRepository.interface';
import { IContactoRepository } from './domain/puertos/outbound/iContactoRepository.interface';
import { IRolRepository } from './domain/puertos/outbound/iRolRepository.interface';
import { IRefreshSessionRepository } from './domain/puertos/outbound/iRefreshSessionRepository.interface';
import { IPasswordResetRepository } from './domain/puertos/outbound/IPasswordResetRepository.interface';
import { CacheRepositoryAdapter } from 'src/infrastructure/adapter/cacheRepository.adapter';

export type CoreModuleOptions = {
    modules: any[];
    adapters: {
        usuarioRepository: Type<IUsuarioRepository>;
        contactoRepository: Type<IContactoRepository>;
        rolRepository: Type<IRolRepository>;
        refreshSessionRepository: Type<IRefreshSessionRepository>;
        passwordResetRepository: Type<IPasswordResetRepository>;
    }
}

// Application USE CASE reference
export const AUTH_USE_CASE = 'AUTH_USE_CASE';

// Application services reference
export const AUTH_APPLICATION_SERVICE = 'AUTH_APPLICATION_SERVICE'

// Domain services references;



@Module({})
export class CoreModule {

    static register(options: CoreModuleOptions): DynamicModule {
        const { adapters, modules } = options;
        const {
            usuarioRepository,
            contactoRepository,
            refreshSessionRepository,
            passwordResetRepository,
        } = adapters;

        const cacheRepositoryProvider = {
            provide: CacheRepositoryAdapter,
            useFactory(cacheManager: Cache, configService: ConfigService) {
                return new CacheRepositoryAdapter(cacheManager, configService);
            },
            inject: [CACHE_MANAGER, ConfigService],
        };

        const jwtServiceProvider = {
            provide: JwtService,
            useFactory(configService: ConfigService) {
                return new JwtService({
                    secret: configService.get<string>('JWT_SECRET'),
                });
            },
            inject: [ConfigService],
        };

        // Auth Service Provider

        const authAplicationServiceProvider = {
            provide: AUTH_APPLICATION_SERVICE,
            useFactory(
                cacheRepository: CacheRepositoryAdapter,
                refreshSessionRepo: IRefreshSessionRepository,
                jwtService: JwtService,
                configService: ConfigService,
            ) {
                return new AuthAplicationService(
                    cacheRepository,
                    refreshSessionRepo,
                    jwtService,
                    configService,
                );
            },
            inject: [CacheRepositoryAdapter, refreshSessionRepository, JwtService, ConfigService],
        };

        const authUseCaseProvider = {
            provide: AUTH_USE_CASE,
            inject: [
                usuarioRepository,
                contactoRepository,
                passwordResetRepository,
                refreshSessionRepository,
                AUTH_APPLICATION_SERVICE,
                JwtService,
                CacheRepositoryAdapter,
                ConfigService,
            ],
            useFactory(
                authRepository: IUsuarioRepository,
                contactoRepository: IContactoRepository,
                passwordResetRepository: IPasswordResetRepository,
                refreshSessionRepo: IRefreshSessionRepository,
                authService: AuthAplicationService,
                jwtService: JwtService,
                cacheRepository: CacheRepositoryAdapter,
                configService: ConfigService,
            ) {
                return new AuthUseCase(
                    authRepository,
                    contactoRepository,
                    passwordResetRepository,
                    refreshSessionRepo,
                    authService,
                    jwtService,
                    cacheRepository,
                    configService,
                );
            },

        };

        return {
            module: CoreModule,
            global: true,
            imports: [
                ...modules,
            ],
            providers: [
                cacheRepositoryProvider,
                jwtServiceProvider,
                // usuarioAplicationProvider,
                authAplicationServiceProvider,
                authUseCaseProvider,
            ],
            exports: [
                // USUARIO_APPLICATION,
                AUTH_USE_CASE,
            ],
        };
    }

}
