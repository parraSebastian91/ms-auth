import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { VaultService } from '../secrets/vault.service';
import { SecretsModule } from '../secrets/secrets.module';



@Module({
    imports: [
        SecretsModule,
        TypeOrmModule.forRootAsync({
            imports: [SecretsModule],
            useFactory: async (vaultService: VaultService) => {
                const dbSecrets = vaultService.getAllSecrets('database');
                console.log(dbSecrets);
                return {
                    type: 'postgres',
                    host: dbSecrets.DATABASE_HOST || process.env.DATABASE_HOST || 'localhost',
                    port:   parseInt(dbSecrets.DATABASE_PORT, 10) ||parseInt(process.env.DATABASE_PORT, 10) || 5432,
                    username: dbSecrets.DATABASE_USER || process.env.DATABASE_USER || 'desarrollo',
                    password: dbSecrets.DATABASE_PASSWORD || process.env.DATABASE_PASSWORD || 'desarrollo123',
                    database: dbSecrets.DATABASE_NAME || process.env.DATABASE_NAME || 'core_erp',
                    schema: dbSecrets.DATABASE_SCHEMA || process.env.DATABASE_SCHEMA || 'core',
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
                }
            },
            inject: [VaultService],
        })
    ],
    providers: [],
    exports: [],
})
export class DatabaseModule {
    // This module can be used to configure database specific settings or providers
    // if needed in the future.
}