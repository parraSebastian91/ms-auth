import { Body, Controller, Get, HttpStatus, Inject, Param, ParseUUIDPipe, Put, Res, UseFilters, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiParam, ApiTags } from '@nestjs/swagger';
import { Response } from 'express';
import { USER_PROFILE_USE_CASE, IUserProfileUseCase } from '../../../core/domain/puertos/inbound/IUserProfile.usecase.interface';
import { CoreExceptionFilter } from '../../exceptionFileter/CoreException.filter';
import { CurrentUser } from '../decorators/current-user.decorator';
import { Permissions } from '../decorators/permissions.decorator';
import { Public } from '../decorators/public.decorator';
import { JwtAccessGuard } from '../guards/jwt-access.guard';
import { PermissionsGuard } from '../guards/permissions.guard';
import { toUpdateContactoData, UpdateUserProfileRequestDto, UserProfileDTO } from '../model/dto/userProfile.dto';
import { ApiEnvelopeResponse, ApiErrorResponse } from '../openapi/api-envelope';

/**
 * Perfil de usuario (identidad + contacto). @Public() solo desactiva el guard de sesión
 * global (cookie); la autenticación aquí es por JWT Bearer, igual que en ms-core.
 * Acceso: el propio usuario, o SUPER_ADMIN/ADMIN (ver UserProfileUseCase).
 */
@ApiTags('Perfil de usuario')
@ApiBearerAuth('bearer')
@Controller('usuario')
@Public()
@UseGuards(JwtAccessGuard, PermissionsGuard)
@UseFilters(CoreExceptionFilter)
export class UserProfileController {
    constructor(@Inject(USER_PROFILE_USE_CASE) private readonly useCase: IUserProfileUseCase) { }

    @Get('profile/:uuid')
    @Permissions('USR_VIEW')
    @ApiOperation({ summary: 'Perfil (identidad + contacto + roles) de un usuario', description: 'Permiso requerido: USR_VIEW. Solo el propio usuario o SUPER_ADMIN/ADMIN.' })
    @ApiParam({ name: 'uuid', format: 'uuid' })
    @ApiEnvelopeResponse({ description: 'Perfil del usuario.', message: 'Extraccion exitosa', type: UserProfileDTO })
    @ApiErrorResponse(400, 'uuid con formato inválido.')
    @ApiErrorResponse(401, 'Falta el JWT Bearer o es inválido/expirado.')
    @ApiErrorResponse(403, 'Falta el permiso USR_VIEW o el perfil es de otro usuario.')
    @ApiErrorResponse(404, 'Usuario no encontrado.')
    async getProfile(
        @Param('uuid', new ParseUUIDPipe()) uuid: string,
        @CurrentUser() user: any,
        @Res() res: Response,
    ) {
        const profile = await this.useCase.getProfile(uuid, { userUuid: user.userUuid, roles: user.roles });
        return res.status(HttpStatus.OK).json({ status: HttpStatus.OK, message: 'Extraccion exitosa', data: UserProfileDTO.builder(profile) });
    }

    @Put('profile/:uuid')
    @Permissions('USR_VIEW')
    @ApiOperation({ summary: 'Actualiza el contacto del usuario (parcial)', description: 'Solo se modifican los campos enviados. Permiso requerido: USR_VIEW. Solo el propio usuario (bajo RLS) o SUPER_ADMIN/ADMIN.' })
    @ApiParam({ name: 'uuid', format: 'uuid' })
    @ApiBody({ type: UpdateUserProfileRequestDto })
    @ApiEnvelopeResponse({ description: 'Perfil actualizado.', message: 'Actualizacion exitosa', type: UserProfileDTO })
    @ApiErrorResponse(400, 'uuid, correo o nombre inválidos.')
    @ApiErrorResponse(401, 'Falta el JWT Bearer o es inválido/expirado.')
    @ApiErrorResponse(403, 'Falta el permiso USR_VIEW o el perfil es de otro usuario.')
    @ApiErrorResponse(404, 'Usuario no encontrado.')
    async updateProfile(
        @Param('uuid', new ParseUUIDPipe()) uuid: string,
        @Body() body: any,
        @CurrentUser() user: any,
        @Res() res: Response,
    ) {
        const profile = await this.useCase.updateProfile(uuid, toUpdateContactoData(body), { userUuid: user.userUuid, roles: user.roles });
        return res.status(HttpStatus.OK).json({ status: HttpStatus.OK, message: 'Actualizacion exitosa', data: UserProfileDTO.builder(profile) });
    }
}
