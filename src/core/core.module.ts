/*
https://docs.nestjs.com/modules
*/

import { DynamicModule, Inject, Module, Type } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { IUsuarioRepository } from './domain/puertos/outbound/iUsuarioRepository.interface';
import { IUsuarioService } from './domain/puertos/inbound/iUsuarioService.interface';
import { IContactoRepository } from './domain/puertos/outbound/iContactoRepository.interface';
import { IRolRepository } from './domain/puertos/outbound/iRolRepository.interface';
import { IAuthService } from './domain/puertos/inbound/IAuthService.interface';
import { AuthService } from './domain/service/auth.service';
import { AuthAplicationService } from './aplication/auth/service/authaplication.service';
import { TokenCacheService } from './domain/service/token-cache.service';
import { UsuarioService } from './domain/service/Usuario.service';
import { UsuarioAplicationService } from './aplication/usuario/service/usuarioAplication.service';
import { IRefreshSessionRepository } from './domain/puertos/outbound/iRefreshSessionRepository.interface';
import { BffService } from './domain/service/bff.service';
import { HttpService } from '@nestjs/axios';
import { IBffService } from './domain/puertos/inbound/IBffService.interface';
import { BffAplicationService } from './aplication/bff/service/BffAplication.service';

export type CoreModuleOptions = {
    modules: any[];
    adapters: {
        usuarioRepository: Type<IUsuarioRepository>;
        contactoRepository: Type<IContactoRepository>;
        rolRepository: Type<IRolRepository>;
        refreshSessionRepository: Type<IRefreshSessionRepository>;
    }
}

// Application service reference
export const USUARIO_APPLICATION = 'USUARIO_APPLICATION';
export const AUTH_APLICATION = 'AUTH_APLICATION'
export const BFF_APPLICATION = 'BFF_APPLICATION';

// Domain services references

export const USUARIO_SERVICE = 'USUARIO_SERVICE';
export const AUTH_SERVICE = 'AUTH_SERVICE'
export const BFF_SERVICE = 'BFF_SERVICE';



@Module({})
export class CoreModule {

    static register(options: CoreModuleOptions): DynamicModule {
        const { adapters, modules } = options;
        const { usuarioRepository, contactoRepository, rolRepository, refreshSessionRepository } = adapters;

        // Auth Service Provider

        const authAplicationProvider = {
            provide: AUTH_APLICATION,
            useFactory(authService: IAuthService) {
                return new AuthAplicationService(authService);
            },
            inject: [AUTH_SERVICE]
        };

        const authServiceProvider = {
            provide: AUTH_SERVICE,
            useFactory(authRepository: IUsuarioRepository, tokenCacheService: TokenCacheService, refreshSessionRepository: IRefreshSessionRepository) {
                return new AuthService(authRepository, new (require('@nestjs/jwt').JwtService)(), tokenCacheService, refreshSessionRepository);
            },
            inject: [usuarioRepository, TokenCacheService, refreshSessionRepository]
        };

        // Usuario Service Provider

        const usuarioAplicationProvider = {
            provide: USUARIO_APPLICATION,
            useFactory(usuarioService: IUsuarioService) {
                return new UsuarioAplicationService(usuarioService);
            },
            inject: [USUARIO_SERVICE]
        };

        const usuarioServiceProvider = {
            provide: USUARIO_SERVICE,
            useFactory(
                usuarioRepository: IUsuarioRepository,
                contactoRepository: IContactoRepository,
                rolRepository: IRolRepository
            ) {
                return new UsuarioService(
                    usuarioRepository,
                    contactoRepository,
                    rolRepository
                );
            },
            inject: [
                usuarioRepository,
                contactoRepository,
                rolRepository
            ]
        };

        // BFF Service Provider

        const bffAplicationProvider = {
            provide: BFF_APPLICATION,
            useFactory(bffService: IBffService) {
                return new BffAplicationService(bffService);
            },
            inject: [BFF_SERVICE]
        }


        const bffServiceProvider = {
            provide: BFF_SERVICE,
            useFactory() {
                return new BffService(new (require('@nestjs/axios').HttpService)());
            }
        };

        return {
            module: CoreModule,
            global: true,
            imports: [
                CacheModule.register(),
                ...modules,
            ],
            providers: [
                TokenCacheService,
                usuarioAplicationProvider,
                usuarioServiceProvider,
                authAplicationProvider,
                authServiceProvider,
                bffAplicationProvider,
                bffServiceProvider,
            ],
            exports: [
                TokenCacheService,
                USUARIO_APPLICATION,
                AUTH_APLICATION,
                AUTH_SERVICE,
                BFF_APPLICATION,
            ],
        };
    }

}
