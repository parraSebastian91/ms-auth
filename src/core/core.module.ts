/*
https://docs.nestjs.com/modules
*/

import { DynamicModule, Inject, Module, Type } from '@nestjs/common';
import { IUsuarioRepository } from './domain/puertos/outbound/iUsuarioRepository.interface';
import { UsuarioService } from './domain/service/Usuario.service';
import { IUsuarioService } from './domain/puertos/inbound/iUsuarioService.interface';
import { UsuarioAplicationService } from './aplication/usuario/service/usuarioAplication.service';
import { IContactoRepository } from './domain/puertos/outbound/iContactoRepository.interface';
import { ITipoContactoRepository } from './domain/puertos/outbound/iTipoContactoRepository.interface';
import { IContactoService } from './domain/puertos/inbound/iContactoService.interface';
import { ContactoAplicationService } from './aplication/contacto/service/contactoAplication.service';
import { ContactoService } from './domain/service/contacto.service';
import { ContactoRepositoryAdapter } from 'src/infrastructure/adapter/contactoRepository.adapter';
import { ITipoContactoService } from './domain/puertos/inbound/iTipoContacto.interface';
import { TipoContactoAplicationService } from './aplication/tipoContacto/service/tipoContactoAplication.service';
import { TipoContactoService } from './domain/service/tipoContacto.service';
import { TipoContactoRepositoryAdapter } from 'src/infrastructure/adapter/tipoContactoRepository.adapter';
import { IRolRepository } from './domain/puertos/outbound/iRolRepository.interface';
import { RolService } from './domain/service/rol.service';
import { RolAplicationService } from './aplication/rol/service/rolAplication.service';
import { IRolService } from './domain/puertos/inbound/iRolService.interface';
import { IAuthService } from './domain/puertos/inbound/IAuthService.interface';
import { AuthService } from './domain/service/auth.service';
import { AuthAplicationService } from './aplication/auth/service/authaplication.service';
import { TokenCacheService } from './domain/service/token-cache.service';
import { ISistemaRepository } from './domain/puertos/outbound/ISistemaRepository.interface';
import { SistemaAplicationService } from './aplication/sistema/service/sistemaAplication.service';
import { ISistemaService } from './domain/puertos/inbound/ISistemaService.interface';
import { SistemaService } from './domain/service/sistema.service';

export type CoreModuleOptions = {
    modules: any[];
    adapters: {
        usuarioRepository: Type<IUsuarioRepository>;
        contactoRepository: Type<IContactoRepository>;
        tipoContactoRepository: Type<ITipoContactoRepository>;
        rolRepository: Type<IRolRepository>;
        sistemaRepository: Type<ISistemaRepository>;
    }
}

// Application service reference
export const USUARIO_APPLICATION = 'USUARIO_APPLICATION';
export const CONTACTO_APPLICATION = 'CONTACTO_APPLICATION'
export const TIPO_CONTACTO_APPLICATION = 'TIPO_CONTACTO_APPLICATION'
export const ROL_APLICATION = 'ROL_APLICATION'
export const AUTH_APLICATION = 'AUTH_APLICATION'
export const SISTEMA_APLICATION = 'SISTEMA_APLICATION'


// Domain services references
export const USUARIO_SERVICE = 'USUARIO_SERVICE';
export const CONTACTO_SERVICE = 'CONTACTO_SERVICE'
export const TIPO_CONTACTO_SERVICE = 'TIPO_CONTACTO_SERVICE'
export const ROL_SERVICE = 'ROL_SERVICE'
export const AUTH_SERVICE = 'AUTH_SERVICE'
export const SISTEMA_SERVICE = 'SISTEMA_SERVICE'


@Module({})
export class CoreModule {

    static register(options: CoreModuleOptions): DynamicModule {
        const { adapters, modules } = options;
        const { usuarioRepository, contactoRepository, rolRepository, sistemaRepository } = adapters;

        // Define the providers for the application service and domain service
        // Contacto Aplication Service
        const contactoAplicationProvider = {
            provide: CONTACTO_APPLICATION,
            useFactory(contactoService: IContactoService) {
                return new ContactoAplicationService(contactoService);
            },
            inject: [CONTACTO_SERVICE]
        };

        // Contacto Service Provider
        const contactoServiceProvider = {
            provide: CONTACTO_SERVICE,
            useFactory(repository: IContactoRepository) {
                return new ContactoService(repository);
            },
            inject: [ContactoRepositoryAdapter]
        };

        //TipoContacto Service Provider

        const tipoContactoAplicationServiceProvider = {
            provide: TIPO_CONTACTO_APPLICATION,
            useFactory(tipoContactoService: ITipoContactoService) {
                return new TipoContactoAplicationService(tipoContactoService);
            },
            inject: [TIPO_CONTACTO_SERVICE]
        };

        // TipoContacto Service Provider

        const tipoContactoServiceProvider = {
            provide: TIPO_CONTACTO_SERVICE,
            useFactory(tipoContactoRepository: ITipoContactoRepository) {
                return new TipoContactoService(tipoContactoRepository);
            },
            inject: [TipoContactoRepositoryAdapter]
        };

        // Usuario Aplication Service
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
                rolRepository]
        };

        const rolAplicationProvider = {
            provide: ROL_APLICATION,
            useFactory(
                rolService: IRolService
            ) {
                return new RolAplicationService(rolService)
            },
            Inject: [ROL_SERVICE]
        }

        const rolServiceProvider = {
            provide: ROL_SERVICE,
            useFactory(
                rolRepository: IRolRepository
            ) {
                return new RolService(rolRepository)
            },
            Inject: [rolRepository]
        }

        // Sistema Aplication Service
        const sistemaAplicationProvider = {
            provide: SISTEMA_APLICATION,
            useFactory(sistemaService: ISistemaService) {
                return new SistemaAplicationService(sistemaService);
            },
            inject: [SISTEMA_SERVICE]
        };

        const sistemaServiceProvider = {
            provide: SISTEMA_SERVICE,
            useFactory(sistemaRepository: ISistemaRepository) {
                return new SistemaService(sistemaRepository);
            },
            inject: [sistemaRepository]
        };

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
                contactoAplicationProvider,
                contactoServiceProvider,
                tipoContactoAplicationServiceProvider,
                tipoContactoServiceProvider,
                rolAplicationProvider,
                rolServiceProvider,
                authAplicationProvider,
                authServiceProvider,
                sistemaAplicationProvider,
                sistemaServiceProvider,
            ],
            exports: [
                USUARIO_APPLICATION,
                CONTACTO_APPLICATION,
                TIPO_CONTACTO_APPLICATION,
                ROL_APLICATION,
                AUTH_APLICATION,
                AUTH_SERVICE,
                SISTEMA_APLICATION
            ],
        };
    }

}
