/*
https://docs.nestjs.com/controllers#controllers
*/

import { Body, Controller, Get, Inject, Post, Res, HttpStatus as NestHttpStatus, UseFilters, Session, Logger, Req, Headers, Ip, HttpCode, Query, All } from '@nestjs/common';
import { AUTH_USE_CASE } from 'src/core/core.module';
import { CallBackDTO, LoginDto } from '../model/dto/login.dto';
import { ApiResponse } from '../model/api-response.model';
import { CookieOptions, Request, Response } from 'express';
import { CoreExceptionFilter } from 'src/infrastructure/exceptionFileter/CoreException.filter';
import { Public } from '../decorators/public.decorator';
import { RequestPasswordResetDto, ResetPasswordDto, ValidateResetTokenDto } from '../model/dto/forgot-password.dto';
import { IAuthUseCase } from 'src/core/domain/puertos/inbound/IAuthUseCase.interface';
import { AuthenticationCommand, authorizationCommand, refreshSessionCommand, RequestPasswordResetCommand, ResetPasswordCommand, validateResetTokenCommand } from 'src/core/aplication/useCase/auth/command/AuthCommand.interface';

interface bodyRefresh {
  typeDevice: string;
}

const REFRESH_COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

@Controller('security')
@UseFilters(CoreExceptionFilter)
// Todas las rutas de auth son públicas
export class AuthController {

  constructor(@
    Inject(AUTH_USE_CASE) private readonly authUseCase: IAuthUseCase
  ) { }
  private readonly logger = new Logger(AuthController.name);

  private getRequestId(req: Request): string {
    const requestId = req.headers['x-request-id'];
    if (Array.isArray(requestId)) return requestId[0] || ((req as any).requestId ?? 'N/A');
    return requestId || (req as any).requestId || 'N/A';
  }

  private getRefreshCookieOptions(req: Request, maxAge: number = REFRESH_COOKIE_MAX_AGE_MS): CookieOptions {
    const forwardedProto = req.headers['x-forwarded-proto'];
    const proto = Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto;
    const isHttps = req.secure || proto === 'https';

    return {
      httpOnly: true,
      secure: isHttps,
      sameSite: 'lax',
      maxAge,
      path: '/',
    };
  }

  @All('session/test')
  async testSession(
    @Req() req: Request,
    @Res() res: Response
  ) {
    const requestId = this.getRequestId(req);
    this.logger.log(`[SESSION_TEST] INIT requestId=${requestId}`);
    // ✅ Obtener todas las cookies
    const allCookies = req.cookies;

    // ✅ Obtener cookie específica
    const refreshToken = req.cookies['auth.refresh'];

    // ✅ Obtener sessionId (automático de express-session)
    const sessionId = req.cookies['auth.session']?.split(':')[1]; // El ID de sesión está antes del primer punto
    this.logger.debug(`[SESSION_TEST] requestId=${requestId} cookies=${Object.keys(allCookies || {}).length} hasRefresh=${Boolean(refreshToken)} hasSessionId=${Boolean(sessionId)}`);
    this.logger.log(`[SESSION_TEST] SUCCESS requestId=${requestId} sessionId=${sessionId ?? 'N/A'}`);
    return res.status(200).json({ message: 'Session test successful' });
  }

  @Post('session/refresh')
  @Public()
  async refreshSession(
    @Body() body: bodyRefresh,
    @Session() session: Record<string, any>,
    @Req() req: Request,
    @Res() res: Response
  ) {
    const requestId = this.getRequestId(req);
    this.logger.log(`[SESSION_REFRESH] INIT requestId=${requestId} sessionId=${session.id} device=${body.typeDevice}`);

    const command: refreshSessionCommand = {
      tokens: req.cookies,
      typeDevice: body.typeDevice,
      requestId
    };

    const tokens = await this.authUseCase.ExecuteRefreshSession(command);

    if (!tokens) {
      this.logger.error(`[SESSION_REFRESH] INVALID_OR_EXPIRED_REFRESH requestId=${requestId} sessionId=${session.id}`);
      return res.status(NestHttpStatus.UNAUTHORIZED).json(
        new ApiResponse(NestHttpStatus.UNAUTHORIZED, 'Token inválido o expirado', null)
      );
    }

    // ✅ MARCAR LA SESIÓN COMO AUTENTICADA
    session.authenticated = true;
    session.accessToken = tokens.accessToken; // si lo tienes en el response

    // ✅ FORZAR GUARDADO EXPLÍCITO
    await new Promise<void>((resolve, reject) => {
      session.save((err: any) => {
        if (err) {
          this.logger.error(`[SESSION_REFRESH] SESSION_SAVE_ERROR requestId=${requestId} sessionId=${session.id}`, err?.stack);
          return reject(err);
        }
        this.logger.log(`[SESSION_REFRESH] SESSION_SAVED requestId=${requestId} sessionId=${session.id}`);
        resolve();
      });
    });

    res.cookie('auth.refresh', tokens.refreshToken, this.getRefreshCookieOptions(req));

    this.logger.log(`[SESSION_REFRESH] SUCCESS requestId=${requestId} sessionId=${session.id}`);
    return res.status(200).json({ message: 'Session test successful' });
  }

  @Post('authenticate')
  @Public()
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
    @Res() res: Response
  ) {
    const requestId = this.getRequestId(req);

    this.logger.log(`[AUTHENTICATE] INIT requestId=${requestId} username=${loginDto.username} device=${loginDto.typeDevice} CorrelationId=${loginDto.CorrelationId}`);
    const command: AuthenticationCommand = {
      username: loginDto.username,
      password: loginDto.password,
      typeDevice: loginDto.typeDevice,
      code_challenge: loginDto.code_challenge,
      CorrelationId: loginDto.CorrelationId,
      requestId
    };
    const result = await this.authUseCase.ExcuteAuthentication(command);
    if (!result) {
      this.logger.warn(`[AUTHENTICATE] FAILED requestId=${requestId} username=${loginDto.username}`);
      return res.status(NestHttpStatus.UNAUTHORIZED).json(new ApiResponse(NestHttpStatus.UNAUTHORIZED, 'Credenciales inválidas', null));
    }
    this.logger.log(`[AUTHENTICATE] SUCCESS requestId=${requestId} username=${loginDto.username} redirects=${result.length}`);
    return res.status(NestHttpStatus.OK).json(new ApiResponse(NestHttpStatus.OK, 'Login exitoso', result));
  }

  @Post('callback')
  @Public()
  async callback(
    @Body() code: CallBackDTO,
    @Session() session: Record<string, any>,
    @Req() req: Request,
    @Res() res: Response
  ) {
    const requestId = this.getRequestId(req);
    this.logger.log(`[CALLBACK] INIT requestId=${requestId} sessionId=${session.id} device=${code.typeDevice}`);
    const sessionId = req.cookies['auth.session']?.split(':')[1].split('.')[0];
    let sessionID = session.id;
    if (sessionId && (session.id !== sessionId)) {
      this.logger.warn(`[CALLBACK] SESSION_ID_MISMATCH requestId=${requestId} CorrelationId=${code.cid}`);
      sessionID = sessionId;
    }

    const command: authorizationCommand = {
      code: code.code,
      codeVerifier: code.codeVerifier,
      typeDevice: code.typeDevice,
      sessionId: sessionID,
      CorrelationId: code.cid,
      requestId
    };
    this.logger.debug(`[CALLBACK] COMMAND_READY requestId=${requestId} sessionId=${command.sessionId} device=${command.typeDevice}`);
    const tokens = await this.authUseCase.ExecuteAuthorization(command);

    if (!tokens) {
      this.logger.error(`[CALLBACK] AUTHORIZATION_NULL requestId=${requestId} sessionId=${command.sessionId}`);
      return res.status(NestHttpStatus.UNAUTHORIZED).json(new ApiResponse(NestHttpStatus.UNAUTHORIZED, 'Token inválido o expirado', null));
    }

    // ✅ MARCAR LA SESIÓN COMO AUTENTICADA
    session.authenticated = true;
    session.accessToken = tokens.accessToken; // si lo tienes en el response

    // ✅ FORZAR GUARDADO EXPLÍCITO
    await new Promise<void>((resolve, reject) => {
      session.save((err: any) => {
        if (err) {
          this.logger.error(`[CALLBACK] SESSION_SAVE_ERROR requestId=${requestId} sessionId=${session.id}`, err?.stack);
          return reject(err);
        }
        this.logger.log(`[CALLBACK] SESSION_SAVED requestId=${requestId} sessionId=${session.id}`);
        resolve();
      });
    });

    res.cookie('auth.refresh', tokens.refreshToken, this.getRefreshCookieOptions(req));

    this.logger.log(`[CALLBACK] SUCCESS requestId=${requestId} sessionId=${session.id}`);
    return res.status(NestHttpStatus.OK).json(new ApiResponse(NestHttpStatus.OK, 'Callback exitoso', { message: 'Autenticación exitosa' }));
  }

  @Get('logout')
  @Public()
  async logout(
    @Session() session: Record<string, any>,
    @Req() req: Request,
    @Res() res: Response
  ) {
    const requestId = this.getRequestId(req);
    this.logger.log(`[LOGOUT] INIT requestId=${requestId} sessionId=${session.id}`);
    await this.authUseCase.ExecuteLogout(session.id)
    session.accessToken = null;
    session.refreshToken = null;
    session.destroy((err: any) => {
      if (err) {
        this.logger.error(`[LOGOUT] SESSION_DESTROY_ERROR requestId=${requestId} sessionId=${session.id}`, err?.stack);
        return res.status(NestHttpStatus.INTERNAL_SERVER_ERROR).json(new ApiResponse(NestHttpStatus.INTERNAL_SERVER_ERROR, 'Error durante logout', null));
      }
    });
    // Eliminar cookie de refresh
    res.clearCookie('auth.refresh', this.getRefreshCookieOptions(req, 0));

    // Eliminar cookie de sesión (express-session)
    res.clearCookie('auth.session', { // o el nombre real de tu cookie de sesión
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/',
    });

    this.logger.log(`[LOGOUT] SUCCESS requestId=${requestId} sessionId=${session.id}`);
    return res.status(NestHttpStatus.OK).json(new ApiResponse(NestHttpStatus.OK, 'Logout exitoso', null));
  }

  @Post('password-reset/request')
  @Public()
  async requestPasswordReset(
    @Body() dto: RequestPasswordResetDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
    @Req() req: Request,
  ) {
    const requestId = this.getRequestId(req);
    this.logger.log(`[PASSWORD_RESET_REQUEST] INIT requestId=${requestId} email=${dto.correo} ip=${ip}`);

    const command: RequestPasswordResetCommand = {
      correo: dto.correo,
      ip: ip,
      userAgent: userAgent,
      requestId
    }

    const response = await this.authUseCase.ExecuteRequestPasswordRequest(
      command
    );
    this.logger.log(`[PASSWORD_RESET_REQUEST] SUCCESS requestId=${requestId} email=${dto.correo}`);
    return response;
  }

  @Get('password-reset/validate')
  @Public()
  async validateToken(@Query() dto: ValidateResetTokenDto, @Req() req: Request) {
    const requestId = this.getRequestId(req);
    this.logger.log(`[PASSWORD_RESET_VALIDATE] INIT requestId=${requestId} tokenUuid=${dto.uuid}`);

    const command: validateResetTokenCommand = {
      token: dto.token,
      uuid: dto.uuid,
      requestId
    }

    const response = await this.authUseCase.ExecuteRequestPasswordValidation(command);
    this.logger.log(`[PASSWORD_RESET_VALIDATE] RESULT requestId=${requestId} tokenUuid=${dto.uuid} valid=${response.valid}`);
    return response;
  }

  @Post('password-reset/reset')
  @Public()
  async resetPassword(@Body() dto: ResetPasswordDto, @Req() req: Request) {
    const requestId = this.getRequestId(req);
    this.logger.log(`[RESET_PASSWORD] INIT requestId=${requestId} tokenUuid=${dto.uuid}`);

    const command: ResetPasswordCommand = {
      token: dto.token,
      uuid: dto.uuid,
      newPassword: dto.newPassword,
      confirmPassword: dto.confirmPassword,
      requestId
    }

    const response = await this.authUseCase.ExecuteResetPassword(command);
    this.logger.log(`[RESET_PASSWORD] SUCCESS requestId=${requestId} tokenUuid=${dto.uuid}`);
    return response;
  }

}
