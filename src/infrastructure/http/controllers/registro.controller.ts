import { Body, Controller, Get, HttpCode, Inject, Logger, Param, Post, Query, Req, Res } from '@nestjs/common';
import { Request, Response } from 'express';
import { Public } from '../decorators/public.decorator';
import { IRegistroUseCase } from 'src/core/domain/puertos/inbound/IRegistro.usecase.interface';
import { FormRegisterDto } from '../model/dto/formRegister.dto';
import { IsNotEmpty, IsString, Length, IsEmail } from 'class-validator';

class VerificarEmailDto {
    @IsEmail({}, { message: 'Debe ser un correo electrónico válido' })
    @IsNotEmpty()
    email: string;

    @IsString() @Length(6, 6, { message: 'El código debe tener exactamente 6 dígitos' })
    otp: string;
}

class ResendOtpDto {
    @IsEmail({}, { message: 'Debe ser un correo electrónico válido' })
    @IsNotEmpty()
    email: string;
}

@Controller("registro")
@Public()
export class RegistroController {
    private readonly logger = new Logger(RegistroController.name);
    constructor(
        @Inject('REGISTRO_USE_CASE') private readonly registroUseCase: IRegistroUseCase
    ) { }

    @Get("check/:field")
    async getRegistro(
        @Param("field") field: string,
        @Query("value") value: string,
        @Req() req: Request,
        @Res() res: Response
    ) {
        const startedAt = Date.now();
        const correlationId = req["correlationId"];
        this.logger.debug(`[START] getRegistro - CorrelationID: ${correlationId}, Field: ${field}, Value: ${value}`);
        const respuesta = await this.registroUseCase.ExecuteValidateField(field, value)
        this.logger.debug(`[END] getRegistro - CorrelationID: ${correlationId}, Duration: ${Date.now() - startedAt}ms, Response: ${JSON.stringify(respuesta)}`);
        return res.status(200).json(respuesta);
    }

    @Post()
    async createRegistro(
        @Body() body: FormRegisterDto,
        @Req() req: Request,
        @Res() res: Response
    ) {
        const startedAt = Date.now();
        const correlationId = req["correlationId"];
        this.logger.debug(`[START] createRegistro - CorrelationID: ${correlationId}, Body: ${JSON.stringify(body)}`);
        const result = await this.registroUseCase.executeCreateRegistro(FormRegisterDto.toDomain(body));
        if (!result.success) {
            this.logger.warn(`[FAIL] createRegistro - CorrelationID: ${correlationId}, Message: ${result.message ?? 'Error al crear el registro'}`);
            return res.status(400).json({ message: result.message ?? "Error al crear el registro" });
        }
        this.logger.debug(`[END] createRegistro - CorrelationID: ${correlationId}, Duration: ${Date.now() - startedAt}ms`);
        return res.status(201).json({ message: "Registro creado exitosamente. Revisa tu correo para verificar tu cuenta.", email: body.email });
    }

    @Post("verificar-email")
    @HttpCode(200)
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
