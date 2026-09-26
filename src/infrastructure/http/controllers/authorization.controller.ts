import { Body, Controller, HttpCode, HttpStatus, Inject, Logger, Post, Req, Res, Session, UseFilters } from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthorizeCommand, TokenCommand } from 'src/core/aplication/useCase/auth/command/AuthCommand.interface';
import { AUTHORIZATION_USE_CASE, IAuthorizationUseCase } from 'src/core/domain/puertos/inbound/IAuthorizationUseCase.interface';
import { CoreExceptionFilter } from 'src/infrastructure/exceptionFileter/CoreException.filter';
import { AuthMetricsService } from 'src/infrastructure/metrics/auth-metrics.service';
import { Public } from '../decorators/public.decorator';
import { ApiResponse } from '../model/api-response.model';
import { AuthorizeRequestDto, TokenRequestDto } from '../model/dto/auth.dto';
import { getRequestId } from '../support/request-id';
import { setRefreshCookie, sessionIdFromCookie } from '../support/auth-cookies';
import { establishAuthenticatedSession, HttpSession } from '../support/session-store';

/**
 * Authorization Code + PKCE.
 *  1. POST /security/authorize  credenciales + code_challenge  -> código de autorización
 *  2. POST /security/token      código + code_verifier          -> sesión (cookie de refresh)
 */
@Controller('security')
@UseFilters(CoreExceptionFilter)
export class AuthorizationController {
  private readonly logger = new Logger(AuthorizationController.name);

  constructor(
    @Inject(AUTHORIZATION_USE_CASE) private readonly authorization: IAuthorizationUseCase,
    private readonly metrics: AuthMetricsService,
  ) {}

  @Post('authorize')
  @Public()
  @HttpCode(HttpStatus.OK)
  async authorize(@Body() dto: AuthorizeRequestDto, @Req() req: Request) {
    const command: AuthorizeCommand = {
      username: dto.username,
      password: dto.password,
      typeDevice: dto.typeDevice,
      code_challenge: dto.code_challenge,
      CorrelationId: dto.CorrelationId,
      requestId: getRequestId(req),
    };
    try {
      const redirects = await this.authorization.ExecuteAuthorize(command);
      this.metrics.loginAttempt('success');
      return new ApiResponse(HttpStatus.OK, 'Login exitoso', redirects);
    } catch (error) {
      this.metrics.loginAttempt('failure');
      throw error;
    }
  }

  @Post('token')
  @Public()
  @HttpCode(HttpStatus.OK)
  async token(
    @Body() dto: TokenRequestDto,
    @Session() session: HttpSession,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const requestId = getRequestId(req);
    const command: TokenCommand = {
      code: dto.code,
      codeVerifier: dto.codeVerifier,
      typeDevice: dto.typeDevice,
      sessionId: this.resolveSessionId(session, req, dto.cid, requestId),
      CorrelationId: dto.cid,
      requestId,
    };
    const tokens = await this.authorization.ExecuteToken(command);

    await establishAuthenticatedSession(session, tokens.accessToken);
    setRefreshCookie(req, res, tokens.refreshToken);

    this.logger.log(`[TOKEN] SESSION_ESTABLISHED requestId=${requestId} sessionId=${session.id}`);
    return new ApiResponse(HttpStatus.OK, 'Callback exitoso', { message: 'Autenticación exitosa' });
  }

  /** Conserva el comportamiento previo: si la cookie trae otro id que la sesión actual, prevalece la cookie. */
  private resolveSessionId(session: HttpSession, req: Request, cid: string, requestId: string): string {
    const fromCookie = sessionIdFromCookie(req);
    if (fromCookie && session.id !== fromCookie) {
      this.logger.warn(`[TOKEN] SESSION_ID_MISMATCH requestId=${requestId} CorrelationId=${cid}`);
      return fromCookie;
    }
    return session.id;
  }
}
