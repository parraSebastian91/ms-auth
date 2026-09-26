import { Body, Controller, Get, HttpCode, Inject, Logger, Param, Post, Query, Req, Res, UseGuards } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { ApiOkResponse, ApiOperation, ApiParam, ApiCreatedResponse, ApiQuery, ApiTags } from '@nestjs/swagger';
import { ApiErrorResponse } from '../openapi/api-envelope';
import { RATE_LIMITS } from '../rate-limit/rate-limit';
import { Request, Response } from 'express';
import { Public } from '../decorators/public.decorator';
import { IRegistroUseCase } from 'src/core/domain/puertos/inbound/IRegistro.usecase.interface';
import { FormRegisterDto } from '../model/dto/formRegister.dto';
import { AuthThrottlerGuard } from '../rate-limit/auth-throttler.guard';
import { IsNotEmpty, IsString, Length, IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { InjectMetric } from '@willsoto/nestjs-prometheus';
import { maskEmail, maskIdentifier } from 'src/core/share/log-sanitizer';
import { Counter } from 'prom-client';

class VerificarEmailDto {
    @ApiProperty({ example: 'ana@correo.cl' })
    @IsEmail({}, { message: 'Debe ser un correo electrónico válido' })
    @IsNotEmpty()
    email: string;

    @ApiProperty({ minLength: 6, maxLength: 6, example: '123456' })
    @IsString() @Length(6, 6, { message: 'El código debe tener exactamente 6 dígitos' })
    otp: string;
}

class ResendOtpDto {
    @ApiProperty({ example: 'ana@correo.cl' })
    @IsEmail({}, { message: 'Debe ser un correo electrónico válido' })
    @IsNotEmpty()
    email: string;
}

@ApiTags('Registro')
@Controller("registro")
@UseGuards(AuthThrottlerGuard)
@Public()
export class RegistroController {
    private readonly logger = new Logger(RegistroController.name);
    constructor(
        @Inject('REGISTRO_USE_CASE') private readonly registroUseCase: IRegistroUseCase,
        @InjectMetric('auth_register_attempts_total') private readonly registerAttemptsCounter: Counter<string>,
    ) { }

    @Get("check/:field")
    @Throttle(RATE_LIMITS.registroCheck)
    @ApiErrorResponse(429, 'Demasiadas comprobaciones desde la misma IP.')
    @ApiOperation({ summary: 'Comprueba si un campo (p. ej. username o correo) está disponible' })
    @ApiParam({ name: 'field', example: 'username' })
    @ApiQuery({ name: 'value', description: 'Valor a comprobar.' })
    @ApiOkResponse({ description: 'Disponibilidad del valor.', schema: { type: 'object', properties: { available: { type: 'boolean' }, message: { type: 'string', nullable: true } } } })
    async getRegistro(
        @Param("field") field: string,
        @Query("value") value: string,
        @Req() req: Request,
        @Res() res: Response
    ) {
        const startedAt = Date.now();
        const correlationId = req["correlationId"];
        this.logger.debug(`[START] getRegistro - CorrelationID: ${correlationId}, Field: ${field}, Value: ${maskIdentifier(value)}`);
        const respuesta = await this.registroUseCase.ExecuteValidateField(field, value)
        this.logger.debug(`[END] getRegistro - CorrelationID: ${correlationId}, Duration: ${Date.now() - startedAt}ms, Response: ${JSON.stringify(respuesta)}`);
        return res.status(200).json(respuesta);
    }

    @Post()
    @Throttle(RATE_LIMITS.registroCreate)
    @ApiErrorResponse(429, 'Demasiados registros desde la misma IP.')
    @ApiOperation({ summary: 'Registra un usuario; envía un código OTP al correo para verificarlo' })
    @ApiCreatedResponse({ description: 'Registro creado.', schema: { type: 'object', properties: { message: { type: 'string' }, email: { type: 'string' } } } })
    @ApiErrorResponse(400, 'Datos inválidos o usuario/correo ya registrado.')
    async createRegistro(
        @Body() body: FormRegisterDto,
        @Req() req: Request,
        @Res() res: Response
    ) {
        const startedAt = Date.now();
        const correlationId = req["correlationId"];
        // No registrar el cuerpo: incluye la contraseña en claro.
        this.logger.debug(`[START] createRegistro - CorrelationID: ${correlationId}, Email: ${maskEmail(body.email)}`);
        const result = await this.registroUseCase.executeCreateRegistro(FormRegisterDto.toDomain(body));
        if (!result.success) {
            this.logger.warn(`[FAIL] createRegistro - CorrelationID: ${correlationId}, Message: ${result.message ?? 'Error al crear el registro'}`);
            this.registerAttemptsCounter.inc({ result: 'failure' });
            return res.status(400).json({ message: result.message ?? "Error al crear el registro" });
        }
        this.registerAttemptsCounter.inc({ result: 'success' });
        this.logger.debug(`[END] createRegistro - CorrelationID: ${correlationId}, Duration: ${Date.now() - startedAt}ms`);
        return res.status(201).json({ message: "Registro creado exitosamente. Revisa tu correo para verificar tu cuenta.", email: body.email });
    }

    @Post("verificar-email")
    @HttpCode(200)
    @Throttle(RATE_LIMITS.verificarEmail)
    @ApiErrorResponse(429, 'Demasiados intentos (por IP o por correo).')
    @ApiOperation({ summary: 'Verifica el correo con el código OTP de 6 dígitos' })
    @ApiOkResponse({ description: 'Correo verificado; ya se puede iniciar sesión.' })
    @ApiErrorResponse(400, 'Código inválido o vencido.')
    async verificarEmail(
        @Body() body: VerificarEmailDto,
        @Req() req: Request,
        @Res() res: Response
    ) {
        const result = await this.registroUseCase.executeVerificarEmail(body.email, body.otp);
        if (!result.success) {
            return res.status(400).json({ message: result.message });
        }
        return res.status(200).json({ message: "Correo verificado correctamente. Ya puedes iniciar sesión." });
    }

    @Post("resend-otp")
    @HttpCode(200)
    @Throttle(RATE_LIMITS.resendOtp)
    @ApiErrorResponse(429, 'Demasiados reenvíos (por IP o por correo).')
    @ApiOperation({ summary: 'Reenvía el código OTP (respuesta genérica: no revela si el correo existe)' })
    @ApiOkResponse({ description: 'Solicitud aceptada.' })
    async resendOtp(
        @Body() body: ResendOtpDto,
        @Req() req: Request,
        @Res() res: Response
    ) {
        const result = await this.registroUseCase.executeResendOtp(body.email);
        if (!result.success) {
            return res.status(400).json({ message: result.message });
        }
        return res.status(200).json({ message: "Si el correo existe y no fue verificado, recibirás un nuevo código." });
    }

}
