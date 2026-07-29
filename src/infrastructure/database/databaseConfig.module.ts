import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SecretsModule } from '../secrets/secrets.module';
import { ConfigModule, ConfigService } from '@nestjs/config';



@Module({
    imports: [
        SecretsModule,
        TypeOrmModule.forRootAsync({
            imports: [SecretsModule, ConfigModule],
            inject: [ConfigService],
            useFactory: async (configService: ConfigService) => {
                console.log( configService.get('database'));
                let dbConfig: any = {
                    type: 'postgres' as const,
                    host: configService.get('database.host'),
                    port: configService.get('database.port'),
                    username: configService.get('database.username'),
                    password: configService.get('database.password'),
                    database: configService.get('database.database'),
                    schema: configService.get('database.schema'),
                    entities: [__dirname + '/entities/*.entity{.ts,.js}'],
                    synchronize: false,
                    logging: false,
                    logger: 'advanced-console',
                    maxQueryExecutionTime: 1000,
                    ssl: configService.get('database.ssl'),
                    extra: {
                        ssl: configService.get('database.ssl'),
                        // Connection pool
                        max: 20,                        // was unset (defaulted to ~10); 20 handles burst traffic
                        min: 2,                         // keep 2 warm connections idle at all times
                        idleTimeoutMillis: 30_000,      // release idle connections after 30s
                        connectionTimeoutMillis: 3_000, // fail fast if pool is full (was 5000)
                        // Keep TCP connections alive so reconnect latency doesn't spike queries
                        keepAlive: true,
                        keepAliveInitialDelayMillis: 10_000,
                        query_timeout: 10_000,
                        statement_timeout: 10_000,
                    },
                };
                return dbConfig;
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