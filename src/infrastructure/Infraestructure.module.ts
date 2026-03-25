/*
https://docs.nestjs.com/modules
*/

import { Module } from '@nestjs/common';
import { DatabaseModule } from './database/databaseConfig.module';
import { HttpServerModule } from './http/http.module';
import { UsuarioRepositoryAdapter } from './adapter/usuarioRepository.adapter';
import { ContactoRepositoryAdapter } from './adapter/contactoRepository.adapter';
import { RolRepositoryAdapter } from './adapter/rolRepository.adapter';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ContactoEntity } from './database/entities/contacto.entity';
import { CuentaBancariaEntity } from './database/entities/cuentaBancaria.entity';
import { ModuloEntity } from './database/entities/modulo.entity';
import { OrganizacionEntity } from './database/entities/organizacion.entity';
import { OrganizacionContactoEntity } from './database/entities/organizacionContacto.entity';
import { OrganizacionSistemaEntity } from './database/entities/organizacionSistema.entity';
import { PermisoEntity } from './database/entities/permisos.entity';
import { RolEntity } from './database/entities/rol.entity';
import { RolModuloPermisoEntity } from './database/entities/rolModuloPermiso.entity';
import { SistemaEntity } from './database/entities/sistema.entity';
import { TipoContactoEntity } from './database/entities/tipoContacto.entity';
import { UsuarioEntity } from './database/entities/usuario.entity';
import { FuncionalidadEntity } from './database/entities/funcionalidad.entity';
import { RefreshSessionEntity } from './database/entities/RefreshSession.entity';
import { RefreshSessionRepositoryAdapter } from './adapter/RefresshSessionRepository.adapter';
import { ConfigModule, ConfigService, ConfigModule as NestConfigModule } from '@nestjs/config';
import { SecretsModule } from './secrets/secrets.module';
import { MetricsModule } from './metrics/metrics.module';
import { PasswordResetRepositoryAdapter } from './adapter/passwordResetRepository.adapter';
import { CacheModule } from '@nestjs/cache-manager';
import { RedisStore } from 'connect-redis';
import { CacheRepositoryAdapter } from './adapter/cacheRepository.adapter';

@Module({
    imports: [
        DatabaseModule,
        SecretsModule,
        HttpServerModule,
        MetricsModule,
        ConfigModule,
        TypeOrmModule.forFeature([
            ContactoEntity,
            CuentaBancariaEntity,
            ModuloEntity,
            OrganizacionEntity,
            OrganizacionContactoEntity,
            OrganizacionSistemaEntity,
            PermisoEntity,
            RolEntity,
            RolModuloPermisoEntity,
            SistemaEntity,
            TipoContactoEntity,
            UsuarioEntity,
            FuncionalidadEntity,
            RefreshSessionEntity
        ]),
        CacheModule.register({
            isGlobal: true,
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: async (configService: ConfigService) => ({
                isGlobal: true,
                store: RedisStore,
                host: configService.get('redis.host') || 'localhost',
                port: configService.get('redis.port') || '6379',
                ttl: configService.get('redis.ttl') || '3600', // 1 hora por defecto
            }),
        }),
        NestConfigModule.forRoot({
            isGlobal: true,
            envFilePath: ['.env.dev', '.env'],
        }),
    ],
    providers: [
        UsuarioRepositoryAdapter,
        ContactoRepositoryAdapter,
        RolRepositoryAdapter,
        RefreshSessionRepositoryAdapter,
        PasswordResetRepositoryAdapter,
        CacheRepositoryAdapter
    ],
    exports: [
        UsuarioRepositoryAdapter,
        ContactoRepositoryAdapter,
        RolRepositoryAdapter,
        RefreshSessionRepositoryAdapter,
        SecretsModule,
        MetricsModule,
        PasswordResetRepositoryAdapter,
        CacheRepositoryAdapter
    ],
})
export class InfraestructureModule { }
