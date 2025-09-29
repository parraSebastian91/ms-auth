/*
https://docs.nestjs.com/modules
*/

import { DynamicModule, Inject, Module, Type } from '@nestjs/common';
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

export type CoreModuleOptions = {
    modules: any[];
    adapters: {
        usuarioRepository: Type<IUsuarioRepository>;
        contactoRepository: Type<IContactoRepository>;
        rolRepository: Type<IRolRepository>;
    }
}

// Application service reference
export const USUARIO_APPLICATION = 'USUARIO_APPLICATION';
export const AUTH_APLICATION = 'AUTH_APLICATION'


// Domain services references

export const USUARIO_SERVICE = 'USUARIO_SERVICE';
export const AUTH_SERVICE = 'AUTH_SERVICE'


@Module({})
export class CoreModule {

    static register(options: CoreModuleOptions): DynamicModule {
        const { adapters, modules } = options;
        const { usuarioRepository, contactoRepository, rolRepository } = adapters;


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
            useFactory(authRepository: IUsuarioRepository, tokenCacheService: TokenCacheService) {
                return new AuthService(authRepository,  new (require('@nestjs/jwt').JwtService)(), tokenCacheService);
            },
            inject: [usuarioRepository, TokenCacheService]
        };

          const usuarioAplicationProvider = {
            provide: USUARIO_APPLICATION,
            useFactory(usuarioService: IUsuarioService) {
                return new UsuarioAplicationService(usuarioService);
            },
            inject: [USUARIO_SERVICE]
        };

        // Usuario Service Provider
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

        return {
            module: CoreModule,
            global: true,
            imports: [
                ...modules,
            ],
            providers: [
                TokenCacheService,
                usuarioAplicationProvider,
                usuarioServiceProvider,
                authAplicationProvider,
                authServiceProvider,
            ],
            exports: [
                USUARIO_APPLICATION,
                AUTH_APLICATION,
                AUTH_SERVICE
            ],
        };
    }

}
