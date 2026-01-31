import { BffService } from './core/domain/service/bff.service';
import { BffAplicationService } from './core/aplication/bff/service/BffAplication.service';

import { Module } from '@nestjs/common';
import { InfraestructureModule } from './infrastructure/Infraestructure.module';
import { CoreModule } from './core/core.module';
import { UsuarioRepositoryAdapter } from './infrastructure/adapter/usuarioRepository.adapter';
import { ConfigModule } from '@nestjs/config';
import configurations from 'config/configurations';
import databaseConfig from 'config/database.config';
import { JwtModule } from '@nestjs/jwt';

import { CacheModule } from '@nestjs/cache-manager';
import * as redisStore from 'cache-manager-ioredis';
import { ContactoRepositoryAdapter } from './infrastructure/adapter/contactoRepository.adapter';
import { RolRepositoryAdapter } from './infrastructure/adapter/rolRepository.adapter';
import { RefreshSessionRepositoryAdapter } from './infrastructure/adapter/RefresshSessionRepository.adapter';
import { HttpModule } from '@nestjs/axios';
import { SecretsModule } from './infrastructure/secrets/secrets.module';
import { VaultService } from './infrastructure/secrets/vault.service';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { LogginInterceptor } from './infrastructure/http-server/loggin.interceptor';

@Module({
  imports: [
    InfraestructureModule,
    ConfigModule.forRoot({
      load: [configurations, databaseConfig],
      isGlobal: true,
      envFilePath: ['.env']

    }),
    CacheModule.register({
      imports: [SecretsModule],
      inject: [VaultService, redisStore],
      useFactory: async (vaultService: VaultService) => ({
        isGlobal: true,
        store: redisStore,
        host: vaultService.getSecret('redis', 'redis_host', process.env.REDIS_HOST || 'localhost'),
        port: vaultService.getSecret('redis', 'redis_port', process.env.REDIS_PORT || '6379'),
        ttl: vaultService.getSecret('redis', 'ttl', process.env.REDIS_TTL || '3600'), // 1 hora por defecto
      }),

    }),
    CoreModule.register({
      modules: [InfraestructureModule],
      adapters: {
        usuarioRepository: UsuarioRepositoryAdapter,
        contactoRepository: ContactoRepositoryAdapter,
        rolRepository: RolRepositoryAdapter,
        refreshSessionRepository: RefreshSessionRepositoryAdapter
      },
    }),
    JwtModule.registerAsync({
      imports: [SecretsModule],
      inject: [VaultService],
      useFactory: async (vaultService: VaultService) => ({
        secret: vaultService.getSecret('auth-service', 'jwt_secret', process.env.JWT_SECRET || 'TU_SECRETO_AQUI'),
        signOptions: { expiresIn: '1h' },
      }),
    }),
    HttpModule.register({
      timeout: 5000,
      maxRedirects: 5,
    }),
  ],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: LogginInterceptor,
    },
  ],
})
export class AppModule { }
