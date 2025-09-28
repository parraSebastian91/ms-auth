/*
https://docs.nestjs.com/modules
*/

import { Module } from '@nestjs/common';
import { DatabaseModule } from './database/databaseConfig.module';
import { HttpServerModule } from './http-server/http-server.module';
import { UsuarioRepositoryAdapter } from './adapter/usuarioRepository.adapter';
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
import { ContactoRepositoryAdapter } from './adapter/contactoRepository.adapter';
import { TipoContactoRepositoryAdapter } from './adapter/tipoContactoRepository.adapter';
import { RolRepositoryAdapter } from './adapter/rolRepository.adapter';
import { FuncionalidadEntity } from './database/entities/funcionalidad.entity';
import { SistemaRepositoryAdapter } from './adapter/sistemaRepository.adapter';

@Module({
    imports: [
        DatabaseModule,
        HttpServerModule,
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
        ]),
    ],
    providers: [
        UsuarioRepositoryAdapter,
        ContactoRepositoryAdapter,
        TipoContactoRepositoryAdapter,
        RolRepositoryAdapter,
        SistemaRepositoryAdapter
    ],
    exports: [
        UsuarioRepositoryAdapter,
        ContactoRepositoryAdapter,
        TipoContactoRepositoryAdapter,
        RolRepositoryAdapter,
        SistemaRepositoryAdapter
    ],
})
export class InfraestructureModule { }
