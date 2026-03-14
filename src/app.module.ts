import { Module } from '@nestjs/common';
import { InfraestructureModule } from './infrastructure/Infraestructure.module';
import { CoreModule } from './core/core.module';
import { UsuarioRepositoryAdapter } from './infrastructure/adapter/usuarioRepository.adapter';
import { ConfigModule } from '@nestjs/config';
import configurations from 'config/configurations';
import { ContactoRepositoryAdapter } from './infrastructure/adapter/contactoRepository.adapter';
import { RolRepositoryAdapter } from './infrastructure/adapter/rolRepository.adapter';
import { RefreshSessionRepositoryAdapter } from './infrastructure/adapter/RefresshSessionRepository.adapter';
import { PasswordResetRepositoryAdapter } from './infrastructure/adapter/passwordResetRepository.adapter';

@Module({
  imports: [
    InfraestructureModule,
    ConfigModule.forRoot({
      load: [configurations],
      isGlobal: true,
      envFilePath: ['.env']
    }),
    CoreModule.register({
      modules: [InfraestructureModule],
      adapters: {
        usuarioRepository: UsuarioRepositoryAdapter,
        contactoRepository: ContactoRepositoryAdapter,
        rolRepository: RolRepositoryAdapter,
        refreshSessionRepository: RefreshSessionRepositoryAdapter,
        passwordResetRepository: PasswordResetRepositoryAdapter,
      },
    }),
  ],
})
export class AppModule { }
