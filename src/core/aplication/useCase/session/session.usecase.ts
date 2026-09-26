import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { performance } from 'perf_hooks';
import { AccessTokenPayload } from 'src/core/domain/model/jwt.model';
import { ISessionUseCase } from 'src/core/domain/puertos/inbound/ISessionUseCase.interface';
import { ICacheRepository } from 'src/core/domain/puertos/outbound/CacheRepository.interface';
import { IRefreshSessionRepository } from 'src/core/domain/puertos/outbound/iRefreshSessionRepository.interface';
import { IUsuarioRepository } from './../../../domain/puertos/outbound/iUsuarioRepository.interface';
import { sessionHandler } from '../../model/application.model';
import { AuthAplicationService } from './../../service/auth.service';
import { refreshSessionCommand } from './../auth/command/AuthCommand.interface';
import { validateQuery } from './../auth/query/validate.query';

const COOKIES = {
  REFRESH: 'auth.refresh',
};

/** Ciclo de vida de la sesión: validar el access token cacheado, rotar el refresh y cerrar sesión. */
@Injectable()
export class SessionUseCase implements ISessionUseCase {
  private readonly logger = new Logger(SessionUseCase.name);
  private readonly accessSecret: string;
  private readonly refreshSecret: string;
  private readonly refreshExpiresIn: string;

  constructor(
    private usuarioRepository: IUsuarioRepository,
    private refreshSessionRepo: IRefreshSessionRepository,
    private authService: AuthAplicationService,
    private jwtService: JwtService,
    private cacheRepository: ICacheRepository,
    private configService: ConfigService,
  ) {
    this.accessSecret = this.configService.get<string>('jwtConfig.access_secret');
    this.refreshSecret = this.configService.get<string>('jwtConfig.refresh_secret');
    this.refreshExpiresIn = this.configService.get<string>('jwtConfig.refresh_expires_in');
  }

  async ExecuteValidateSession(command: validateQuery): Promise<boolean> {
    this.logger.log(`[VALIDATE_SESSION] INIT sessionId=${command.sessionId}`);
    const session = await this.cacheRepository.getAccessToken(
      command.sessionId,
    );
    if (!session) {
      this.logger.error(
        `[VALIDATE_SESSION] SESSION_NOT_FOUND sessionId=${command.sessionId}`,
      );
      throw new UnauthorizedException('Por favor inicia sesión.');
    }
    try {
      this.jwtService.verify(session);
    } catch {
      // verify() lanza ante un JWT vencido/inválido; sin este catch el error sube como 500.
      this.logger.error(
        `[VALIDATE_SESSION] INVALID_OR_EXPIRED_JWT sessionId=${command.sessionId}`,
      );
      throw new UnauthorizedException('Por favor inicia sesión.');
    }

    const payload = this.jwtService.decode(session);
    if (!payload) {
      this.logger.error(
        `[VALIDATE_SESSION] CORRUPTED_TOKEN sessionId=${command.sessionId}`,
      );
      throw new UnauthorizedException('Por favor inicia sesión.');
    }

    // const tiempoLogeado = ahora - iat; // segundos desde que se emitió
    // const tiempoRestante = exp - ahora; // segundos hasta expiración

    // this.logger.log(`⏱️ Token - Logeado: ${tiempoLogeado}s | Expira en: ${tiempoRestante}s`);
    // this.logger.log(`✅ Usuario autenticado: ${request['user'].username} (ID: ${request['user'].userId})`);

    this.logger.log(
      `[VALIDATE_SESSION] SUCCESS sessionId=${command.sessionId}`,
    );
    return true;
  }

  async ExecuteRefreshSession(
    command: refreshSessionCommand,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const requestId = command.requestId || 'N/A';
    const t0 = performance.now();
    const lap = (label: string, prev: number) => {
      const ms = (performance.now() - prev).toFixed(1);
      this.logger.debug(
        `[REFRESH_PERF] requestId=${requestId} step="${label}" ms=${ms}`,
      );
      return performance.now();
    };
    let t = t0;
    this.logger.log(
      `[REFRESH_SESSION] INIT requestId=${requestId} device=${command.typeDevice}`,
    );

    const refreshCookie = command.tokens?.[COOKIES.REFRESH];
    if (!refreshCookie) {
      this.logger.error(
        `[REFRESH_SESSION] MISSING_REFRESH_TOKEN requestId=${requestId} device=${command.typeDevice}`,
      );
      throw new UnauthorizedException(
        'Session inactiva, porfavor loguearse de nuevo',
      );
    }

    try {
      this.jwtService.verify(refreshCookie, { secret: this.refreshSecret });
    } catch (_error) {
      this.logger.error(
        `[REFRESH_SESSION] INVALID_REFRESH_TOKEN_FORMAT requestId=${requestId} device=${command.typeDevice}`,
      );
      throw new UnauthorizedException(
        'Session inactiva, porfavor loguearse de nuevo',
      );
    }
    t = lap('jwt.verify(refreshCookie)', t);

    const decodedRefresh = this.jwtService.decode(refreshCookie) as {
      refreshToken: string;
    } | null;
    if (!decodedRefresh?.refreshToken) {
      this.logger.error(
        `[REFRESH_SESSION] INVALID_REFRESH_TOKEN_PAYLOAD requestId=${requestId} device=${command.typeDevice}`,
      );
      throw new UnauthorizedException(
        'Session inactiva, porfavor loguearse de nuevo',
      );
    }
    const [sessionId, sessionUuid, secret] =
      decodedRefresh.refreshToken.split('.');
    t = lap('jwt.decode(refreshCookie)', t);

    let sessionHandler: sessionHandler = {} as sessionHandler;

    if (!sessionId || !sessionUuid || !secret) {
      this.logger.error(
        `[REFRESH_SESSION] INVALID_REFRESH_TOKEN_PARTS requestId=${requestId} device=${command.typeDevice}`,
      );
      throw new UnauthorizedException(
        'Session inactiva, porfavor loguearse de nuevo',
      );
    }
    this.logger.log(
      `[REFRESH_SESSION] TOKEN_PARSED requestId=${requestId} cacheSessionId=${sessionId} sessionUuid=${sessionUuid}`,
    );

    let sessionCache = await this.cacheRepository.getAccessToken(sessionId);
    t = lap('redis.getAccessToken', t);
    if (!sessionCache) {
      this.logger.warn(
        `[REFRESH_SESSION] NO_CACHED_SESSION requestId=${requestId} cacheSessionId=${sessionId} sessionUuid=${sessionUuid}`,
      );
    }

    const refreshSession = await this.refreshSessionRepo.findById(sessionUuid);
    t = lap('db.findRefreshSession', t);
    if (
      !refreshSession ||
      refreshSession.revokedAt ||
      new Date(refreshSession.expiresAt) < new Date()
    ) {
      this.logger.error(
        `[REFRESH_SESSION] SESSION_NOT_FOUND_OR_EXPIRED requestId=${requestId} sessionUuid=${sessionUuid}`,
      );
      throw new UnauthorizedException(
        'Session inactiva, porfavor loguearse de nuevo',
      );
    }

    const ok = this.authService.verifyTokenSecret(
      secret,
      refreshSession.refreshTokenHash,
    );
    t = lap('hmac.verifyTokenSecret', t);

    if (!ok) {
      this.logger.error(
        `[REFRESH_SESSION] INVALID_REFRESH_TOKEN_SECRET requestId=${requestId} sessionUuid=${sessionUuid}`,
      );
      throw new UnauthorizedException(
        'Session inactiva, porfavor loguearse de nuevo',
      );
    }
    this.logger.log(
      `[REFRESH_SESSION] SESSION_VALIDATED requestId=${requestId} rotating sessionUuid=${sessionUuid}`,
    );
    let tokenDecode = this.jwtService.decode(
      sessionCache,
    ) as AccessTokenPayload | null;
    if (!tokenDecode) {
      this.logger.warn(
        `[REFRESH_SESSION] CACHE_MISS_FALLBACK requestId=${requestId} rebuilding payload from DB sessionUuid=${sessionUuid}`,
      );
      const usuario = await this.usuarioRepository.getUsuarioById(
        refreshSession.userId,
      );
      t = lap('db.getUsuarioById(fallback)', t);
      if (!usuario) {
        this.logger.error(
          `[REFRESH_SESSION] USER_NOT_FOUND_ON_FALLBACK requestId=${requestId} userId=${refreshSession.userId}`,
        );
        throw new UnauthorizedException(
          'Session inactiva, porfavor loguearse de nuevo',
        );
      }
      tokenDecode = {
        userId: refreshSession.userId,
        username: usuario.userName,
        userUuid: refreshSession.userUuid,
        sessionUuid: refreshSession.sessionUuid,
        sessionId: refreshSession.sessionId,
        roles: usuario.rol.map((r) => r.codigo) as string[],
        permissions: usuario.rol.flatMap((r) =>
          r.permisos ? r.permisos.map((p) => p.codigo) : [],
        ) as string[],
        typeDevice: refreshSession.deviceType,
      } as AccessTokenPayload;
    }
    sessionHandler = await this.authService.rotateSession(tokenDecode, {
      ip: refreshSession.ip,
      ua: refreshSession.userAgent,
      fingerprint: refreshSession.deviceFingerprint,
    });
    t = lap('rotateSession (revoke+insert)', t);

    const payload: AccessTokenPayload = {
      userId: sessionHandler.session.userId,
      username: tokenDecode.username,
      userUuid: sessionHandler.session.userUuid,
      sessionUuid: sessionHandler.session.sessionUuid,
      sessionId: sessionHandler.session.sessionId,
      roles: tokenDecode.roles,
      permissions: tokenDecode.permissions,
      typeDevice: sessionHandler.session.deviceType,
    };
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: this.authService.accessTokenExpiresIn(payload.roles),
      secret: this.accessSecret,
    } as JwtSignOptions);
    t = lap('jwt.sign(accessToken)', t);

    await this.cacheRepository.setAccessToken(payload.sessionId, accessToken);
    t = lap('redis.setAccessToken', t);
    this.logger.log(
      `[REFRESH_SESSION] ACCESS_TOKEN_CACHED requestId=${requestId} userUuid=${payload.userUuid} sessionId=${payload.sessionId}`,
    );

    const refreshToken = this.jwtService.sign(
      { refreshToken: sessionHandler.plainToken },
      {
        expiresIn: this.refreshExpiresIn,
        secret: this.refreshSecret,
      } as JwtSignOptions,
    );
    t = lap('jwt.sign(refreshToken)', t);

    const totalMs = (performance.now() - t0).toFixed(1);
    this.logger.log(`[REFRESH_PERF] requestId=${requestId} TOTAL=${totalMs}ms`);
    this.logger.log(
      `[REFRESH_SESSION] SUCCESS requestId=${requestId} userUuid=${payload.userUuid} sessionId=${payload.sessionId} sessionUuid=${payload.sessionUuid}`,
    );
    return { accessToken, refreshToken };
  }

  async ExecuteLogout(sessionId: string): Promise<void> {
    this.logger.log(`[LOGOUT] INIT sessionId=${sessionId}`);
    await this.authService.revokeUserSessions(sessionId);
    this.logger.log(`[LOGOUT] SUCCESS sessionId=${sessionId}`);
  }
}
