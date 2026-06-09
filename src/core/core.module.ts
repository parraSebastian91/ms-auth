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
import { ICacheRepository } from './domain/puertos/outbound/CacheRepository.interface';
import { IEmailService, EMAIL_SERVICE } from './domain/puertos/outbound/IEmailService.interface';
import { RegistroUseCaseImpl } from './aplication/useCase/registro/registro.usecase.impl';

export type CoreModuleOptions = {
    modules: any[];
    adapters: {
        usuarioRepository: Type<IUsuarioRepository>;
        contactoRepository: Type<IContactoRepository>;
        rolRepository: Type<IRolRepository>;
        refreshSessionRepository: Type<IRefreshSessionRepository>;
        passwordResetRepository: Type<IPasswordResetRepository>;
        cacheRepository: Type<ICacheRepository>;
    }
}

// Application USE CASE reference
export const AUTH_USE_CASE = 'AUTH_USE_CASE';
export const REGISTRO_USE_CASE = 'REGISTRO_USE_CASE';

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
            cacheRepository,
            rolRepository,
        } = adapters;

        // Auth Service Provider

        const authAplicationServiceProvider = {
            provide: AUTH_APPLICATION_SERVICE,
            useFactory(
                cacheRepository: ICacheRepository,
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
            inject: [cacheRepository, refreshSessionRepository, JwtService, ConfigService],
        };

        const registroUseCaseProvider = {
            provide: REGISTRO_USE_CASE,
            inject: [
                usuarioRepository,
                contactoRepository,
                cacheRepository,
                EMAIL_SERVICE,
                rolRepository,
            ],
            useFactory(
                authRepository: IUsuarioRepository,
                contactoRepository: IContactoRepository,
                cacheRepository: ICacheRepository,
                emailService: IEmailService,
                rolRepository: IRolRepository,
            ) {
                return new RegistroUseCaseImpl(
                    authRepository,
                    contactoRepository,
                    cacheRepository,
                    emailService,
                    rolRepository,
                );
            },
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
                cacheRepository,
                ConfigService,
            ],
            useFactory(
                authRepository: IUsuarioRepository,
                contactoRepository: IContactoRepository,
                passwordResetRepository: IPasswordResetRepository,
                refreshSessionRepo: IRefreshSessionRepository,
                authService: AuthAplicationService,
                jwtService: JwtService,
                cacheRepository: ICacheRepository,
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
                JwtService,
                authAplicationServiceProvider,
                authUseCaseProvider,
                registroUseCaseProvider,
            ],
            exports: [
                REGISTRO_USE_CASE,
                AUTH_USE_CASE,
            ],
        };
    }

}
