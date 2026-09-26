import { Body, Controller, Get, Headers, Inject, Ip, Logger, Post, Query, Req, UseFilters } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { IPasswordResetUseCase, PASSWORD_RESET_USE_CASE } from 'src/core/domain/puertos/inbound/IPasswordResetUseCase.interface';
import { CoreExceptionFilter } from 'src/infrastructure/exceptionFileter/CoreException.filter';
import { AuthMetricsService } from 'src/infrastructure/metrics/auth-metrics.service';
import { Public } from '../decorators/public.decorator';
import { RequestPasswordResetDto, ResetPasswordDto, ValidateResetTokenDto } from '../model/dto/forgot-password.dto';
import { ApiErrorResponse } from '../openapi/api-envelope';
import { getRequestId } from '../support/request-id';

/** Recuperación de contraseña. Devuelve el resultado del caso de uso tal cual (contrato existente). */
@ApiTags('Recuperación de contraseña')
@Controller('security/password-reset')
@UseFilters(CoreExceptionFilter)
@Public()
export class PasswordResetController {
  private readonly logger = new Logger(PasswordResetController.name);

  constructor(
    @Inject(PASSWORD_RESET_USE_CASE) private readonly passwordReset: IPasswordResetUseCase,
    private readonly metrics: AuthMetricsService,
  ) {}

  @Post('request')
  @ApiOperation({
    summary: 'Solicita el enlace de restablecimiento',
    description: 'Responde siempre el mismo mensaje genérico (exista o no el correo, esté o no activa la cuenta). Estado actual: el envío del correo aún NO está implementado.',
  })
  @ApiOkResponse({ description: 'Solicitud aceptada.', schema: { type: 'object', properties: { message: { type: 'string', example: 'Si el correo existe, recibirás un enlace de restablecimiento' } } } })
  @ApiErrorResponse(400, 'Correo con formato inválido.')
  async request(@Body() dto: RequestPasswordResetDto, @Ip() ip: string, @Headers('user-agent') userAgent: string, @Req() req: Request) {
    const response = await this.passwordReset.ExecuteRequestReset({
      correo: dto.correo,
      ip,
      userAgent,
      requestId: getRequestId(req),
    });
    this.metrics.passwordResetRequested();
    return response;
  }

  @Get('validate')
  @ApiOperation({ summary: 'Comprueba si el token del enlace sigue siendo válido' })
  @ApiOkResponse({ description: 'Resultado de la validación.', schema: { type: 'object', properties: { valid: { type: 'boolean' }, email: { type: 'string', nullable: true } } } })
  async validate(@Query() dto: ValidateResetTokenDto, @Req() req: Request) {
    return this.passwordReset.ExecuteValidateResetToken({ token: dto.token, uuid: dto.uuid, requestId: getRequestId(req) });
  }

  @Post('reset')
  @ApiOperation({ summary: 'Establece la nueva contraseña con el token del enlace', description: 'Marca el token como usado y revoca las sesiones del usuario en base de datos.' })
  @ApiOkResponse({ description: 'Contraseña restablecida.', schema: { type: 'object', properties: { message: { type: 'string', example: 'Contraseña restablecida exitosamente' } } } })
  @ApiErrorResponse(400, 'Contraseñas distintas, token inválido o expirado.')
  async reset(@Body() dto: ResetPasswordDto, @Req() req: Request) {
    const response = await this.passwordReset.ExecuteResetPassword({
      token: dto.token,
      uuid: dto.uuid,
      newPassword: dto.newPassword,
      confirmPassword: dto.confirmPassword,
      requestId: getRequestId(req),
    });
    this.logger.log(`[RESET_PASSWORD] SUCCESS tokenUuid=${dto.uuid}`);
    return response;
  }
}
