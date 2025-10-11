import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ContactoEntity } from './entities/contacto.entity';
import { OrganizacionEntity } from './entities/organizacion.entity';
import { TipoContactoEntity } from './entities/tipoContacto.entity';
import { UsuarioEntity } from './entities/usuario.entity';
import { ModuloEntity } from './entities/modulo.entity';
import { SistemaEntity } from './entities/sistema.entity';
import { OrganizacionContactoEntity } from './entities/organizacionContacto.entity';
import { OrganizacionSistemaEntity } from './entities/organizacionSistema.entity';
import { PermisoEntity } from './entities/permisos.entity';
import { RolEntity } from './entities/rol.entity';
import { RolModuloPermisoEntity } from './entities/rolModuloPermiso.entity';
import { CuentaBancariaEntity } from './entities/cuentaBancaria.entity';
import { FuncionalidadEntity } from './entities/funcionalidad.entity';
import { RefreshSessionEntity } from './entities/RefreshSession.entity';

@Module({
    imports: [
        TypeOrmModule.forRootAsync({
            useFactory: () => ({
                type: 'postgres',
                host: process.env.DB_HOST || 'localhost',
                port: parseInt(process.env.DB_PORT, 10) || 5432,
                username: process.env.DB_USERNAME || 'desarrollo',
                password: process.env.DB_PASSWORD || '071127',
                database: process.env.DB_NAME || 'core_erp',
                schema: process.env.DB_SCHEMA || 'core',
                entities: [
                    ContactoEntity,
                    CuentaBancariaEntity,
                    ModuloEntity,
                    RolModuloPermisoEntity,
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
                ],
                synchronize: false, // Set to false in production
                logging: process.env.DB_LOGGING === 'true',
            })
        })
    ]
})
export class DatabaseModule {
    // This module can be used to configure database specific settings or providers
    // if needed in the future.
}