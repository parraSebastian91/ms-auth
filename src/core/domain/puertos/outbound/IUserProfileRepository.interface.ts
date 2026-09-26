import { UpdateContactoData, UserProfileModel } from '../../model/userProfile.model';

export const USER_PROFILE_REPOSITORY = 'USER_PROFILE_REPOSITORY';

export interface IUserProfileRepository {
    findByUuid(uuid: string): Promise<UserProfileModel | null>;
    /**
     * Actualiza el contacto del usuario. Si `rlsUserUuid` viene, la transacción fija
     * `app.user_uuid` para que la RLS de identity.contacto acote la escritura a ese usuario.
     * Devuelve false si el usuario no existe.
     */
    updateContacto(uuid: string, data: UpdateContactoData, rlsUserUuid?: string): Promise<boolean>;
}
