import { UpdateContactoData, UserProfileModel } from '../../model/userProfile.model';

export const USER_PROFILE_USE_CASE = 'USER_PROFILE_USE_CASE';

/** Quien hace la llamada, según el JWT de acceso. */
export interface ProfileActor {
    userUuid: string;
    roles: string[];
}

export interface IUserProfileUseCase {
    getProfile(uuid: string, actor: ProfileActor): Promise<UserProfileModel>;
    updateProfile(uuid: string, data: UpdateContactoData, actor: ProfileActor): Promise<UserProfileModel>;
}
