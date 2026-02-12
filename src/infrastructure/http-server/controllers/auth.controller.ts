/*
https://docs.nestjs.com/controllers#controllers
*/

import { Body, Controller, Get, Inject, Post, Res, HttpStatus as NestHttpStatus, UseFilters, Session, Logger, Req, Headers, Ip, HttpCode, Query, All } from '@nestjs/common';
import { IAuthAplication } from 'src/core/aplication/auth/authAplication.interface';
import { AUTH_APLICATION } from 'src/core/core.module';
import { CallBackDTO, LoginDto } from '../model/dto/login.dto';
import { ApiResponse } from '../model/api-response.model';
import { Request, Response } from 'express';
import { CoreExceptionFilter } from 'src/infrastructure/exceptionFileter/CoreException.filter';
import { Public } from '../decorators/public.decorator';
import { RequestPasswordResetDto, ResetPasswordDto, ValidateResetTokenDto } from '../model/dto/forgot-password.dto';
import { JwtService } from '@nestjs/jwt';
import { authorizationCommand, LoginCommand, refreshSessionCommand, RequestPasswordResetCommand, ResetPasswordCommand, validateResetTokenCommand } from 'src/core/aplication/auth/command/AuthCommand.interface';

interface bodyRefresh {
  typeDevice: string;
}

@Controller('auth')
@UseFilters(CoreExceptionFilter)
// Todas las rutas de auth son públicas
export class AuthController {

  constructor(@
    Inject(AUTH_APLICATION) private readonly authAplicationService: IAuthAplication
  ) { }
  private readonly logger = new Logger(AuthController.name);

  @All('session/test')
  async testSession(
    @Req() req: Request,
    @Res() res: Response
  ) {
    // ✅ Obtener todas las cookies
    const allCookies = req.cookies;
    console.log('Todas las cookies:', allCookies);

    // ✅ Obtener cookie específica
    const refreshToken = req.cookies['auth.refresh'];
    console.log('Refresh token:', refreshToken);

    // ✅ Obtener sessionId (automático de express-session)
    const sessionId = req.cookies['auth.session'].split(':')[1]; // El ID de sesión está antes del primer punto
    console.log('Session ID:', sessionId);
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
    this.logger.log(`[session/refresh] - sessionId: ${session.id}`);

    const command: refreshSessionCommand = {
      tokens: req.cookies,
      typeDevice: body.typeDevice
    };

    const tokens = await this.authAplicationService.refreshSession(command);

    if (!tokens) {
      this.logger.error('Refresh token inválido o expirado');
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
          this.logger.error('Error guardando sesión:', err);
          return reject(err);
        }
        this.logger.log(`✅ Sesión guardada con ID: ${session.id}`);
        resolve();
      });
    });

    res.cookie('auth.refresh', tokens.refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días,
      path: '/'
    });

    return res.status(200).json({ message: 'Session test successful' });
  }

  @Post('authenticate')
  @Public()
  async login(
    @Body() loginDto: LoginDto,
    @Res() res: Response
  ) {
    this.logger.log(`[authenticate] - [username]:${loginDto.username} - [typeDevice]:${loginDto.typeDevice}`);
    const command: LoginCommand = {
      username: loginDto.username,
      password: loginDto.password,
      typeDevice: loginDto.typeDevice,
      code_challenge: loginDto.code_challenge,
      sessionId: loginDto.sessionId
    };
    const result = await this.authAplicationService.authetication(command);
    if (!result) {
      return res.status(NestHttpStatus.UNAUTHORIZED).json(new ApiResponse(NestHttpStatus.UNAUTHORIZED, 'Credenciales inválidas', null));
    }
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
    this.logger.log(`INIT - [callback] - [sessionId]:${session.id}`);
    const sessionId = req.cookies['auth.session']?.split(':')[1].split('.')[0];
    let sessionID = session.id;
    if (sessionId && (session.id !== sessionId)) {
      this.logger.warn(`session.id (${session.id}) != sessionId (${sessionId}); REMPLAZANDO`);
      sessionID = sessionId;
    }

    const command: authorizationCommand = {
      code: code.code,
      codeVerifier: code.codeVerifier,
      typeDevice: code.typeDevice,
      sessionId: sessionID
    };

    const tokens = await this.authAplicationService.exchangeCodeForToken(command);

    if (!tokens) {
      this.logger.error('Error: exchangeCodeForToken retornó null/undefined');
      return res.status(NestHttpStatus.UNAUTHORIZED).json(new ApiResponse(NestHttpStatus.UNAUTHORIZED, 'Token inválido o expirado', null));
    }

    // ✅ MARCAR LA SESIÓN COMO AUTENTICADA
    session.authenticated = true;
    session.accessToken = tokens.accessToken; // si lo tienes en el response

    // ✅ FORZAR GUARDADO EXPLÍCITO
    await new Promise<void>((resolve, reject) => {
      session.save((err: any) => {
        if (err) {
          this.logger.error('Error guardando sesión:', err);
          return reject(err);
        }
        this.logger.log(`✅ Sesión guardada con ID: ${session.id}`);
        resolve();
      });
    });

    res.cookie('auth.refresh', tokens.refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 3600000,
    });

    return res.status(NestHttpStatus.OK).json(new ApiResponse(NestHttpStatus.OK, 'Callback exitoso', { message: 'Autenticación exitosa' }));
  }

  @Get('logout')
  @Public()
  async logout(
    @Session() session: Record<string, any>,
    @Res() res: Response
  ) {
    this.logger.log('Iniciando logout para la sesión:', session.id);
    await this.authAplicationService.revokeUserSessions(session.id)
    session.accessToken = null;
    session.refreshToken = null;
    session.destroy((err: any) => {
      if (err) {
        this.logger.error('Error destruyendo sesión:', err);
        return res.status(NestHttpStatus.INTERNAL_SERVER_ERROR).json(new ApiResponse(NestHttpStatus.INTERNAL_SERVER_ERROR, 'Error durante logout', null));
      }
    });
    // Eliminar cookie de refresh
    res.clearCookie('auth.refresh', {
      httpOnly: true,
      secure: false,  // true en prod HTTPS
      sameSite: 'lax', // 'none' en prod cross-site
      path: '/',
    });

    // Eliminar cookie de sesión (express-session)
    res.clearCookie('auth.session', { // o el nombre real de tu cookie de sesión
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/',
    });

    this.logger.log('Logout exitoso para la sesión:', session.id);
    return res.status(NestHttpStatus.OK).json(new ApiResponse(NestHttpStatus.OK, 'Logout exitoso', null));
  }

  @Post('password-reset/request')
  @Public()
  async requestPasswordReset(
    @Body() dto: RequestPasswordResetDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ) {

    const command: RequestPasswordResetCommand = {
      correo: dto.correo,
      ip: ip,
      userAgent: userAgent
    }

    return this.authAplicationService.requestPasswordReset(
      command
    );
  }

  @Get('password-reset/validate')
  @Public()
  async validateToken(@Query() dto: ValidateResetTokenDto) {

    const command: validateResetTokenCommand = {
      token: dto.token,
      uuid: dto.uuid
    }

    return this.authAplicationService.validateResetToken(command);
  }

  @Post('password-reset/reset')
  @Public()
  async resetPassword(@Body() dto: ResetPasswordDto) {

    const command: ResetPasswordCommand = {
      token: dto.token,
      uuid: dto.uuid,
      newPassword: dto.newPassword,
      confirmPassword: dto.confirmPassword
    }

    return this.authAplicationService.resetPassword(command);
  }

}
