import { Body, Controller, Get, Headers, Inject, Ip, Logger, Post, Query, Req, UseFilters } from '@nestjs/common';
import { Request } from 'express';
import { IPasswordResetUseCase, PASSWORD_RESET_USE_CASE } from 'src/core/domain/puertos/inbound/IPasswordResetUseCase.interface';
import { CoreExceptionFilter } from 'src/infrastructure/exceptionFileter/CoreException.filter';
import { AuthMetricsService } from 'src/infrastructure/metrics/auth-metrics.service';
import { Public } from '../decorators/public.decorator';
import { RequestPasswordResetDto, ResetPasswordDto, ValidateResetTokenDto } from '../model/dto/forgot-password.dto';
import { getRequestId } from '../support/request-id';

/** Recuperación de contraseña. Devuelve el resultado del caso de uso tal cual (contrato existente). */
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
  async validate(@Query() dto: ValidateResetTokenDto, @Req() req: Request) {
    return this.passwordReset.ExecuteValidateResetToken({ token: dto.token, uuid: dto.uuid, requestId: getRequestId(req) });
  }

  @Post('reset')
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
