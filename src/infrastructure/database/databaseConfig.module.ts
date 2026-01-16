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
                host: process.env.DATABASE_HOST || 'localhost',
                port: parseInt(process.env.DATABASE_PORT, 10) || 5432,
                username: process.env.DATABASE_USER || 'desarrollo',
                password: process.env.DATABASE_PASSWORD || 'desarrollo123',
                database: process.env.DATABASE_NAME || 'core_erp',
                schema: process.env.DATABASE_SCHEMA || 'core',
                // entities: [
                //     ContactoEntity,
                //     CuentaBancariaEntity,
                //     ModuloEntity,
                //     RolModuloPermisoEntity,
                //     OrganizacionEntity,
                //     OrganizacionContactoEntity,
                //     OrganizacionSistemaEntity,
                //     PermisoEntity,
                //     RolEntity,
                //     RolModuloPermisoEntity,
                //     SistemaEntity,
                //     TipoContactoEntity,
                //     UsuarioEntity,
                //     FuncionalidadEntity,
                //     RefreshSessionEntity
                // ],
                entities: [__dirname + '/entities/*.entity{.ts,.js}'],

                synchronize: false,  // ← NO usar true en producción

                // ✅ ACTIVAR LOGGING COMPLETO
                logging: true,  // O más específico:  ['query', 'error', 'schema', 'warn', 'info', 'log']
                logger: 'advanced-console',  // O 'debug', 'simple-console'

                // ✅ Ver todas las queries
                maxQueryExecutionTime: 1000,
                // ✅ Opciones adicionales de debugging
                extra: {
                    // Ver detalles de conexión
                    connectionTimeoutMillis: 5000,
                    query_timeout: 10000,
                    statement_timeout: 10000,
                },
            })
        })
    ]
})
export class DatabaseModule {
    // This module can be used to configure database specific settings or providers
    // if needed in the future.
}