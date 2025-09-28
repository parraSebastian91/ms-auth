import { AuthService } from './core/domain/service/auth.service';
import { AuthAplicationService } from './core/aplication/auth/service/authaplication.service';
import { AuthController } from './infrastructure/http-server/controllers/auth.controller';
import { Module } from '@nestjs/common';
import { InfraestructureModule } from './infrastructure/Infraestructure.module';
import { CoreModule } from './core/core.module';
import { UsuarioRepositoryAdapter } from './infrastructure/adapter/usuarioRepository.adapter';
import { ConfigModule } from '@nestjs/config';
import configurations from 'config/configurations';
import databaseConfig from 'config/database.config';
import { ContactoRepositoryAdapter } from './infrastructure/adapter/contactoRepository.adapter';
import { TipoContactoRepositoryAdapter } from './infrastructure/adapter/tipoContactoRepository.adapter';
import { RolRepositoryAdapter } from './infrastructure/adapter/rolRepository.adapter';
import { JwtModule } from '@nestjs/jwt';

import { CacheModule } from '@nestjs/cache-manager';
import * as redisStore from 'cache-manager-ioredis';
import { SistemaRepositoryAdapter} from './infrastructure/adapter/sistemaRepository.adapter';

@Module({
  imports: [
    InfraestructureModule,
    ConfigModule.forRoot({
      load: [configurations, databaseConfig],
      isGlobal: true,
      envFilePath: ['.env']

    }),
    CacheModule.register({
      isGlobal: true,
      store: redisStore,
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT,
      ttl: 60 * 60, // 1 hora por defecto
    }),
    CoreModule.register({
      modules: [InfraestructureModule],
      adapters: {
        usuarioRepository: UsuarioRepositoryAdapter,
        contactoRepository: ContactoRepositoryAdapter,
        tipoContactoRepository: TipoContactoRepositoryAdapter,
        rolRepository: RolRepositoryAdapter,
        sistemaRepository: SistemaRepositoryAdapter
      },
    }),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'TU_SECRETO_AQUI',
      signOptions: { expiresIn: '1h' },
    }),
  ]
})
export class AppModule { }
