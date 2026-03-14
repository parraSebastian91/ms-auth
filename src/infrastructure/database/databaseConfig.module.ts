import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { VaultService } from '../secrets/vault.service';
import { SecretsModule } from '../secrets/secrets.module';
import { ConfigModule, ConfigService } from '@nestjs/config';



@Module({
    imports: [
        SecretsModule,
        TypeOrmModule.forRootAsync({
            imports: [SecretsModule, ConfigModule],
            inject: [VaultService, ConfigService],
            useFactory: async (vaultService: VaultService, configService: ConfigService) => {
                const dbSecrets = vaultService.getAllSecrets('database');
                return {
                    type: 'postgres',
                    host: dbSecrets.DATABASE_HOST || configService.get('DATABASE_HOST') || 'localhost',
                    port:   parseInt(dbSecrets.DATABASE_PORT, 10) || parseInt(configService.get('DATABASE_PORT'), 10) || 5432,
                    username: dbSecrets.DATABASE_USER || configService.get('DATABASE_USER') || 'desarrollo',
                    password: dbSecrets.DATABASE_PASSWORD || configService.get('DATABASE_PASSWORD') || 'desarrollo123',
                    database: dbSecrets.DATABASE_NAME || configService.get('DATABASE_NAME') || 'core_erp',
                    schema: dbSecrets.DATABASE_SCHEMA || configService.get('DATABASE_SCHEMA') || 'core',
                    entities: [__dirname + '/entities/*.entity{.ts,.js}'],
                    synchronize: false,  // ← NO usar true en producción
                    // ✅ ACTIVAR LOGGING COMPLETO
                    logging: false,  // O más específico:  ['query', 'error', 'schema', 'warn', 'info', 'log']
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
        })
    ],
    providers: [],
    exports: [],
})
export class DatabaseModule {
    // This module can be used to configure database specific settings or providers
    // if needed in the future.
}