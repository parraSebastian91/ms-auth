/*
https://docs.nestjs.com/controllers#controllers
*/

import { Body, Controller, Get, Inject, Param, Post, Res, HttpStatus as NestHttpStatus, UseFilters, Session, Logger, Req, Headers, Ip, HttpCode, Query } from '@nestjs/common';
import { IAuthAplication } from 'src/core/aplication/auth/authAplication.interface';
import { AUTH_APLICATION } from 'src/core/core.module';
import { CallBackDTO, LoginDto } from '../model/dto/login.dto';
import { ApiResponse } from '../model/api-response.model';
import { Response } from 'express';
import { CoreExceptionFilter } from 'src/infrastructure/exceptionFileter/CoreException.filter';
import { Public } from '../decorators/public.decorator';
import { RequestPasswordResetDto, ResetPasswordDto, ValidateResetTokenDto } from '../model/dto/forgot-password.dto';


@Controller('auth')
@UseFilters(CoreExceptionFilter)
@Public() // Todas las rutas de auth son públicas
export class AuthController {

  constructor(@
    Inject(AUTH_APLICATION) private readonly authAplicationService: IAuthAplication  
  ) { }
  private readonly logger = new Logger(AuthController.name);

  @Post('authenticate')
  async login(
    @Body() loginDto: LoginDto,
    @Res() res: Response
  ) {
    this.logger.log(`[authenticate] - [username]:${loginDto.username} - [typeDevice]:${loginDto.typeDevice}`);
    const result = await this.authAplicationService.authetication(loginDto);
    if (!result) {
      return res.status(NestHttpStatus.UNAUTHORIZED).json(new ApiResponse(NestHttpStatus.UNAUTHORIZED, 'Credenciales inválidas', null));
    }
    return res.status(NestHttpStatus.OK).json(new ApiResponse(NestHttpStatus.OK, 'Login exitoso', result));
  }

  @Post('callback')
  async callback(
    @Body() code: CallBackDTO,
    @Session() session: Record<string, any>,
    @Res() res: Response
  ) {
    this.logger.log(`INIT - [callback] - [sessionId]:${session.id}`);
    const tokens = await this.authAplicationService.exchangeCodeForToken(code.code, code.codeVerifier, code.typeDevice, session.id);

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

    return res.status(NestHttpStatus.OK).json(new ApiResponse(NestHttpStatus.OK, 'Callback exitoso', { message: 'Autenticación exitosa' }));
  }

  @Get('logout')
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
    this.logger.log('Logout exitoso para la sesión:', session.id);
    return res.status(NestHttpStatus.OK).json(new ApiResponse(NestHttpStatus.OK, 'Logout exitoso', null));
  }

  @Post('password-reset/request')
  async requestPasswordReset(
    @Body() dto: RequestPasswordResetDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ) {
    return this.authAplicationService.requestPasswordReset(
      dto.correo,
      ip,
      userAgent,
    );
  }

  @Get('password-reset/validate')
  async validateToken(@Query() dto: ValidateResetTokenDto) {
    return this.authAplicationService.validateResetToken(dto.token, dto.uuid);
  }

  @Post('password-reset/reset')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authAplicationService.resetPassword(
      dto.token,
      dto.uuid,
      dto.newPassword,
      dto.confirmPassword,
    );
  }

}
