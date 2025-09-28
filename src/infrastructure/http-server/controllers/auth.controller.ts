/*
https://docs.nestjs.com/controllers#controllers
*/

import { Body, Controller, Get, Inject, Param, Post, Res, HttpStatus as NestHttpStatus, UseFilters } from '@nestjs/common';
import { IAuthAplication } from 'src/core/aplication/auth/authAplication.interface';
import { AUTH_APLICATION } from 'src/core/core.module';
import { LoginDto, RefreshDto } from '../model/dto/login.dto';
import { ApiResponse } from '../model/api-response.model';
import express, {Request, Response} from 'express';
import { CoreExceptionFilter } from 'src/infrastructure/exceptionFileter/contacto.filter';
import { Public } from '../decorators/public.decorator';


@Controller('auth')
@UseFilters(CoreExceptionFilter)
@Public() // Todas las rutas de auth son públicas
export class AuthController {

    constructor(@Inject(AUTH_APLICATION) private readonly authAplicationService: IAuthAplication) { }

    @Post('login')
    async login(@Body() loginDto: LoginDto, @Res() res: Response) {
        const result = await this.authAplicationService.login(loginDto);
        if (!result) {
            return res.status(NestHttpStatus.UNAUTHORIZED).json(new ApiResponse(NestHttpStatus.UNAUTHORIZED, 'Credenciales inválidas', null));
        }
        return res.status(NestHttpStatus.OK).json(new ApiResponse(NestHttpStatus.OK, 'Login exitoso', result));
    }

    @Post('refresh')
    async refresh(@Body() token: RefreshDto, @Res() res: Response){
        const result = await this.authAplicationService.refreshToken(token.refresh_token, token.userId, token.typeDevice);
        if (!result) {
            return res.status(NestHttpStatus.UNAUTHORIZED).json(new ApiResponse(NestHttpStatus.UNAUTHORIZED, 'Token inválido o expirado', null));
        }
        return res.status(NestHttpStatus.OK).json(new ApiResponse(NestHttpStatus.OK, 'Token refrescado', result));
    }

    @Get('validate/:token')
    async validate(@Param('token') token: string, @Res() res: Response) {
        const result = await this.authAplicationService.validateToken(token);
        if (!result) {
            return res.status(NestHttpStatus.UNAUTHORIZED).json(new ApiResponse(NestHttpStatus.UNAUTHORIZED, 'Token inválido o expirado', null));
        } else {
            return res.status(NestHttpStatus.OK).json(new ApiResponse(NestHttpStatus.OK, 'Token Válido', result));
        }
    }
}
