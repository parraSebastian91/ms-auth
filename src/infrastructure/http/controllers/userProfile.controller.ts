import { Body, Controller, Get, HttpStatus, Inject, Param, ParseUUIDPipe, Put, Res, UseFilters, UseGuards } from '@nestjs/common';
import { Response } from 'express';
import { USER_PROFILE_USE_CASE, IUserProfileUseCase } from '../../../core/domain/puertos/inbound/IUserProfile.usecase.interface';
import { CoreExceptionFilter } from '../../exceptionFileter/CoreException.filter';
import { CurrentUser } from '../decorators/current-user.decorator';
import { Permissions } from '../decorators/permissions.decorator';
import { Public } from '../decorators/public.decorator';
import { JwtAccessGuard } from '../guards/jwt-access.guard';
import { PermissionsGuard } from '../guards/permissions.guard';
import { toUpdateContactoData, UserProfileDTO } from '../model/userProfile.dto';

/**
 * Perfil de usuario (identidad + contacto). @Public() solo desactiva el guard de sesión
 * global (cookie); la autenticación aquí es por JWT Bearer, igual que en ms-core.
 * Acceso: el propio usuario, o SUPER_ADMIN/ADMIN (ver UserProfileUseCase).
 */
@Controller('usuario')
@Public()
@UseGuards(JwtAccessGuard, PermissionsGuard)
@UseFilters(CoreExceptionFilter)
export class UserProfileController {
    constructor(@Inject(USER_PROFILE_USE_CASE) private readonly useCase: IUserProfileUseCase) { }

    @Get('profile/:uuid')
    @Permissions('USR_VIEW')
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
