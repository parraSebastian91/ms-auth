import { Body, Controller, HttpCode, HttpStatus, Inject, Logger, Post, Req, Res, Session, UseFilters } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { Request, Response } from 'express';
import { AuthorizeCommand, TokenCommand } from 'src/core/aplication/useCase/auth/command/AuthCommand.interface';
import { AUTHORIZATION_USE_CASE, IAuthorizationUseCase } from 'src/core/domain/puertos/inbound/IAuthorizationUseCase.interface';
import { CoreExceptionFilter } from 'src/infrastructure/exceptionFileter/CoreException.filter';
import { AuthMetricsService } from 'src/infrastructure/metrics/auth-metrics.service';
import { Public } from '../decorators/public.decorator';
import { ApiResponse } from '../model/api-response.model';
import { AuthorizeRequestDto, TokenRequestDto } from '../model/dto/auth.dto';
import { ApiEnvelopeResponse, ApiErrorResponse } from '../openapi/api-envelope';
import { getRequestId } from '../support/request-id';
import { setRefreshCookie } from '../support/auth-cookies';
import { establishAuthenticatedSession, HttpSession } from '../support/session-store';

/**
 * Authorization Code + PKCE.
 *  1. POST /security/authorize  credenciales + code_challenge  -> código de autorización
 *  2. POST /security/token      código + code_verifier          -> sesión (cookie de refresh)
 */
@ApiTags('Autorización (Authorization Code + PKCE)')
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
  @ApiOperation({
    summary: 'Paso 1: valida credenciales y emite un código de autorización',
    description: 'El cliente genera un `code_verifier` aleatorio y envía su hash S256 como `code_challenge`. Devuelve una redirección por cada sistema al que el usuario tiene acceso; todas llevan el mismo código.',
  })
  @ApiEnvelopeResponse({
    description: 'Código emitido.',
    message: 'Login exitoso',
    schema: { type: 'array', items: { type: 'object', properties: { code: { type: 'string' }, url: { type: 'string', example: '/validate?code=abc&cid=xyz' } } } },
  })
  @ApiErrorResponse(400, 'Cuerpo inválido (campo obligatorio ausente o typeDevice desconocido).')
  @ApiErrorResponse(401, 'Usuario o contraseña incorrectos (mismo error si el usuario no existe).')
  @ApiEnvelopeResponse({
    status: 403,
    description: 'El correo aún no está verificado. El cuerpo NO usa el sobre estándar: `{ code: "EMAIL_NOT_VERIFIED", email }`.',
    message: 'Email no verificado',
  })
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
  @ApiOperation({
    summary: 'Paso 2: canjea el código (+ code_verifier) por la sesión',
    description: 'Verifica PKCE y el tipo de dispositivo, consume el código (un solo uso), marca la sesión como autenticada (cookie `auth.session`) y fija la cookie HttpOnly `auth.refresh`.',
  })
  @ApiEnvelopeResponse({
    description: 'Sesión establecida.',
    message: 'Callback exitoso',
    schema: { type: 'object', properties: { message: { type: 'string', example: 'Autenticación exitosa' } } },
    headers: { 'Set-Cookie': { description: 'auth.refresh (HttpOnly, SameSite=Lax) y auth.session.', schema: { type: 'string' } } },
  })
  @ApiErrorResponse(400, 'Código inexistente/consumido, verifier PKCE inválido o dispositivo distinto.')
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
      // Solo el id que verificó express-session: la cookie cruda no está verificada y el cliente la controla.
      sessionId: session.id,
      CorrelationId: dto.cid,
      requestId,
    };
    const tokens = await this.authorization.ExecuteToken(command);

    await establishAuthenticatedSession(session, tokens.accessToken);
    setRefreshCookie(req, res, tokens.refreshToken);

    this.logger.log(`[TOKEN] SESSION_ESTABLISHED requestId=${requestId} sessionId=${session.id}`);
    return new ApiResponse(HttpStatus.OK, 'Callback exitoso', { message: 'Autenticación exitosa' });
  }
}
