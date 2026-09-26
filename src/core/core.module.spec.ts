import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { AuthorizationUseCase } from './aplication/useCase/authorization/authorization.usecase';
import { PasswordResetUseCase } from './aplication/useCase/passwordReset/passwordReset.usecase';
import { SessionUseCase } from './aplication/useCase/session/session.usecase';
import { CoreModule } from './core.module';
import { AUTHORIZATION_USE_CASE } from './domain/puertos/inbound/IAuthorizationUseCase.interface';
import { PASSWORD_RESET_USE_CASE } from './domain/puertos/inbound/IPasswordResetUseCase.interface';
import { SESSION_USE_CASE } from './domain/puertos/inbound/ISessionUseCase.interface';
import { USER_PROFILE_USE_CASE } from './domain/puertos/inbound/IUserProfile.usecase.interface';
import { EMAIL_SERVICE } from './domain/puertos/outbound/IEmailService.interface';
import { UserProfileUseCase } from './aplication/useCase/userProfile/userProfile.usecase';
import { SECRETS } from 'src/test-support/fixtures';

class UsuarioRepo { } class ContactoRepo { } class RolRepo { } class RefreshRepo { }
class PasswordResetRepo { } class CacheRepo { } class UserProfileRepo { }
const adapters = [UsuarioRepo, ContactoRepo, RolRepo, RefreshRepo, PasswordResetRepo, CacheRepo, UserProfileRepo];

@Module({
  providers: [...adapters, { provide: EMAIL_SERVICE, useValue: {} }],
  exports: [...adapters, EMAIL_SERVICE],
})
class StubInfraModule { }

describe('CoreModule (cableado de inyección de dependencias)', () => {
  it('resuelve los cuatro casos de uso con sus dependencias', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true, load: [() => ({
          jwtConfig: { access_secret: SECRETS.access, refresh_secret: SECRETS.refresh, access_expires_in: '5m', admin_expires_in: '30m', refresh_expires_in: '7d' },
          app: { ttlRefreshSession: 1000 },
        })] }),
        CoreModule.register({
          modules: [StubInfraModule],
          adapters: {
            usuarioRepository: UsuarioRepo as any, contactoRepository: ContactoRepo as any, rolRepository: RolRepo as any,
            refreshSessionRepository: RefreshRepo as any, passwordResetRepository: PasswordResetRepo as any,
            cacheRepository: CacheRepo as any, userProfileRepository: UserProfileRepo as any,
          },
        }),
      ],
    }).compile();

    expect(moduleRef.get(AUTHORIZATION_USE_CASE)).toBeInstanceOf(AuthorizationUseCase);
    expect(moduleRef.get(SESSION_USE_CASE)).toBeInstanceOf(SessionUseCase);
    expect(moduleRef.get(PASSWORD_RESET_USE_CASE)).toBeInstanceOf(PasswordResetUseCase);
    expect(moduleRef.get(USER_PROFILE_USE_CASE)).toBeInstanceOf(UserProfileUseCase);
  });
});
