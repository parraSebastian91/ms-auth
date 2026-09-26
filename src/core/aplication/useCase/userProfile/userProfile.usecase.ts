import { ForbiddenException } from '@nestjs/common';
import { UserNotFoundError } from '../../../domain/errors/UserNotFound.error';
import { ValidationError } from '../../../domain/errors/validation.error';
import { UpdateContactoData, UserProfileModel } from '../../../domain/model/userProfile.model';
import { IUserProfileUseCase, ProfileActor } from '../../../domain/puertos/inbound/IUserProfile.usecase.interface';
import { IUserProfileRepository } from '../../../domain/puertos/outbound/IUserProfileRepository.interface';

/** Roles que pueden ver/editar el perfil de otros usuarios. */
export const PROFILE_ADMIN_ROLES = ['SUPER_ADMIN', 'ADMIN'];

export class UserProfileUseCase implements IUserProfileUseCase {
    constructor(private readonly repository: IUserProfileRepository) { }

    async getProfile(uuid: string, actor: ProfileActor): Promise<UserProfileModel> {
        this.assertCanAccess(uuid, actor);
        const profile = await this.repository.findByUuid(uuid);
        if (!profile) throw new UserNotFoundError('Usuario no encontrado');
        return profile;
    }

    async updateProfile(uuid: string, data: UpdateContactoData, actor: ProfileActor): Promise<UserProfileModel> {
        this.assertCanAccess(uuid, actor);
        this.validate(data);
        const isOwner = actor.userUuid === uuid;
        const updated = await this.repository.updateContacto(uuid, data, isOwner ? uuid : undefined);
        if (!updated) throw new UserNotFoundError('Usuario no encontrado');
        return this.getProfile(uuid, actor);
    }

    private assertCanAccess(uuid: string, actor: ProfileActor): void {
        const isOwner = !!actor.userUuid && actor.userUuid === uuid;
        const isAdmin = (actor.roles ?? []).some(r => PROFILE_ADMIN_ROLES.includes(r));
        if (!isOwner && !isAdmin) {
            throw new ForbiddenException('Solo puedes acceder a tu propio perfil');
        }
    }

    private validate(data: UpdateContactoData): void {
        if (data.nombres !== undefined && data.nombres.trim() === '') {
            throw new ValidationError('El nombre no puede estar vacío');
        }
        if (data.correo !== undefined && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.correo)) {
            throw new ValidationError('El correo no es válido');
        }
    }
}
