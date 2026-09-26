import { Injectable, Logger } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { EmailNotVerifiedError } from 'src/core/domain/errors/EmailNotVerified.error';
import { InvalidcodeToken } from 'src/core/domain/errors/InvalidCodeToken.error';
import { LoginError } from 'src/core/domain/errors/LoginError.error';
import { UserNotFoundError } from 'src/core/domain/errors/UserNotFound.error';
import { IAuthorizationUseCase } from 'src/core/domain/puertos/inbound/IAuthorizationUseCase.interface';
import { ICacheRepository } from 'src/core/domain/puertos/outbound/CacheRepository.interface';
import { IUsuarioRepository } from './../../../domain/puertos/outbound/iUsuarioRepository.interface';
import { AuthAplicationService } from './../../service/auth.service';
import { AuthorizeCommand, TokenCommand } from './../auth/command/AuthCommand.interface';

/** Authorization Code + PKCE: `authorize` emite el código, `token` lo canjea por tokens. */
@Injectable()
export class AuthorizationUseCase implements IAuthorizationUseCase {
  private readonly logger = new Logger(AuthorizationUseCase.name);

  constructor(
    private usuarioRepository: IUsuarioRepository,
    private authService: AuthAplicationService,
    private cacheRepository: ICacheRepository,
  ) {}

  async ExecuteAuthorize(
    command: AuthorizeCommand,
  ): Promise<{ code: string; url: string }[]> {
    const requestId = command.requestId || 'N/A';
    this.logger.log(
      `[AUTHORIZE] INIT requestId=${requestId} username=${command.username} device=${command.typeDevice} CorrelationId=${command.CorrelationId}`,
    );
    const usuario = await this.usuarioRepository.getUsuarioByUsername(
      command.username,
    );
    if (!usuario) {
      this.logger.warn(
        `[AUTHORIZE] USER_NOT_FOUND requestId=${requestId} username=${command.username} CorrelationId=${command.CorrelationId}`,
      );
      throw new UserNotFoundError('Usuario no encontrado');
    }
    if (!(await bcrypt.compare(command.password, usuario.password))) {
      this.logger.warn(
        `[AUTHORIZE] INVALID_CREDENTIALS requestId=${requestId} username=${command.username} CorrelationId=${command.CorrelationId}`,
      );
      throw new LoginError('Usuario no encontrado o contraseña incorrecta');
    }
    if (!usuario.emailVerificado) {
      const email = usuario.contacto?.correo ?? command.username;
      this.logger.warn(
        `[AUTHORIZE] EMAIL_NOT_VERIFIED requestId=${requestId} username=${command.username} CorrelationId=${command.CorrelationId}`,
      );
      throw new EmailNotVerifiedError(email);
    }
    this.logger.log(
      `[AUTHORIZE] CREDENTIALS_VALID requestId=${requestId} userUuid=${usuario.uuid} CorrelationId=${command.CorrelationId}`,
    );
    const code = await this.authService.createAuthorizationCode(
      usuario,
      command.code_challenge,
      command.typeDevice,
      command.CorrelationId,
    );
    this.logger.log(
      `[AUTHORIZE] AUTH_CODE_CREATED requestId=${requestId} userUuid=${usuario.uuid} CorrelationId=${command.CorrelationId}`,
    );

    const systems = await this.usuarioRepository.getSystemsByUsername(
      command.username,
    );
    const uris = systems.map(() => ({
      code: encodeURIComponent(code),
      url: `/validate?code=${encodeURIComponent(code)}&cid=${encodeURIComponent(command.CorrelationId)}`,
    }));
    this.logger.log(
      `[AUTHORIZE] SUCCESS requestId=${requestId} username=${command.username} systems=${uris.length}`,
    );
    return uris;
  }

  async ExecuteToken(
    command: TokenCommand,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const requestId = command.requestId || 'N/A';
    this.logger.log(
      `[TOKEN] INIT requestId=${requestId} sessionId=${command.sessionId} device=${command.typeDevice} CorrelationId=${command.CorrelationId}`,
    );
    if (!command.code || command.code === '')
      throw new InvalidcodeToken('Código de autorización inválido');

    const stored = await this.cacheRepository.getAuthCode(command.code);
    if (!stored) throw new InvalidcodeToken('Código de autorización inválido');
    this.logger.log(
      `[TOKEN] AUTH_CODE_FOUND requestId=${requestId} CorrelationId=${stored.CorrelationId} userUuid=${stored.userUuid}`,
    );

    const incomingChallenge = this.authService.hashingCodeChallenge(
      command.codeVerifier,
    );
    if (incomingChallenge !== stored.codeChallenge) {
      this.logger.warn(
        `[TOKEN] INVALID_PKCE requestId=${requestId} sessionId=${command.sessionId} CorrelationId=${command.CorrelationId}`,
      );
      throw new InvalidcodeToken('Code verifier inválido (PKCE)');
    }

    const storedDevice = (stored.typeDevice || '').trim().toUpperCase();
    const commandDevice = (command.typeDevice || '').trim().toUpperCase();
    if (storedDevice !== commandDevice) {
      this.logger.warn(
        `[TOKEN] DEVICE_MISMATCH requestId=${requestId} stored=${storedDevice} incoming=${commandDevice} sessionId=${command.sessionId}`,
      );
      throw new InvalidcodeToken('Tipo de dispositivo no coincide');
    }

    stored.sessionId = command.sessionId;

    await this.cacheRepository.deleteAuthCode(command.code);
    this.logger.log(
      `[TOKEN] AUTH_CODE_DELETED requestId=${requestId} sessionId=${command.sessionId} CorrelationId=${command.CorrelationId}`,
    );
    const tokens = await this.authService.createRefreshSession(stored);
    this.logger.log(
      `[TOKEN] SUCCESS requestId=${requestId} sessionId=${command.sessionId} userUuid=${stored.userUuid} CorrelationId=${command.CorrelationId}`,
    );
    return tokens;
  }
}
