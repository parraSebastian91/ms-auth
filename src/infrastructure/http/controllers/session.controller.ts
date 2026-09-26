import { Body, Controller, Get, HttpCode, HttpStatus, Inject, Logger, Post, Req, Res, Session, UseFilters } from '@nestjs/common';
import { Request, Response } from 'express';
import { refreshSessionCommand } from 'src/core/aplication/useCase/auth/command/AuthCommand.interface';
import { ISessionUseCase, SESSION_USE_CASE } from 'src/core/domain/puertos/inbound/ISessionUseCase.interface';
import { CoreExceptionFilter } from 'src/infrastructure/exceptionFileter/CoreException.filter';
import { AuthMetricsService } from 'src/infrastructure/metrics/auth-metrics.service';
import { Public } from '../decorators/public.decorator';
import { ApiResponse } from '../model/api-response.model';
import { RefreshSessionRequestDto } from '../model/dto/auth.dto';
import { clearAuthCookies, setRefreshCookie } from '../support/auth-cookies';
import { getRequestId } from '../support/request-id';
import { destroySession, establishAuthenticatedSession, HttpSession } from '../support/session-store';

/** Ciclo de vida de la sesión: renovar (rotar el refresh token) y cerrar. */
@Controller('security')
@UseFilters(CoreExceptionFilter)
export class SessionController {
  private readonly logger = new Logger(SessionController.name);

  constructor(
    @Inject(SESSION_USE_CASE) private readonly sessions: ISessionUseCase,
    private readonly metrics: AuthMetricsService,
  ) {}

  @Post('session/refresh')
  @Public()
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Body() body: RefreshSessionRequestDto,
    @Session() session: HttpSession,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const requestId = getRequestId(req);
    const command: refreshSessionCommand = { tokens: req.cookies, typeDevice: body?.typeDevice, requestId };

    const tokens = await this.sessions.ExecuteRefreshSession(command);
    this.metrics.sessionRefreshed();

    await establishAuthenticatedSession(session, tokens.accessToken);
    setRefreshCookie(req, res, tokens.refreshToken);

    this.logger.log(`[SESSION_REFRESH] SUCCESS requestId=${requestId} sessionId=${session.id}`);
    return { message: 'Sesión renovada' };
  }

  @Get('logout')
  @Public()
  @HttpCode(HttpStatus.OK)
  async logout(@Session() session: HttpSession, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const requestId = getRequestId(req);
    const sessionId = session.id;
    this.logger.log(`[LOGOUT] INIT requestId=${requestId} sessionId=${sessionId}`);

    await this.sessions.ExecuteLogout(sessionId);
    session.accessToken = null;
    session.refreshToken = null;
    // Esperar el destroy antes de responder: evita responder dos veces si falla.
    await destroySession(session);
    clearAuthCookies(req, res);

    this.logger.log(`[LOGOUT] SUCCESS requestId=${requestId} sessionId=${sessionId}`);
    return new ApiResponse(HttpStatus.OK, 'Logout exitoso', null);
  }
}
