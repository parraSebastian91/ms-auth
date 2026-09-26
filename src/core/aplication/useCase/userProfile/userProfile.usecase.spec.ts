import { ForbiddenException } from '@nestjs/common';
import { UserNotFoundError } from '../../../domain/errors/UserNotFound.error';
import { ValidationError } from '../../../domain/errors/validation.error';
import { UserProfileModel } from '../../../domain/model/userProfile.model';
import { IUserProfileRepository } from '../../../domain/puertos/outbound/IUserProfileRepository.interface';
import { UserProfileUseCase } from './userProfile.usecase';

const OWNER = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';

function makeRepo(profile: UserProfileModel | null = UserProfileModel.fromData({ usuario_uuid: OWNER, nombres: 'Ana' })) {
    const repo: jest.Mocked<IUserProfileRepository> = {
        findByUuid: jest.fn().mockResolvedValue(profile),
        updateContacto: jest.fn().mockResolvedValue(true),
    };
    return repo;
}

describe('UserProfileUseCase', () => {
    describe('acceso al perfil', () => {
        it('el propietario puede ver su perfil', async () => {
            const uc = new UserProfileUseCase(makeRepo());
            await expect(uc.getProfile(OWNER, { userUuid: OWNER, roles: ['CLIENTE_CEDENTE'] })).resolves.toBeDefined();
        });

        it('un usuario sin rol de administración NO puede ver el perfil de otro', async () => {
            const repo = makeRepo();
            const uc = new UserProfileUseCase(repo);
            await expect(uc.getProfile(OTHER, { userUuid: OWNER, roles: ['CLIENTE_CEDENTE'] })).rejects.toBeInstanceOf(ForbiddenException);
            expect(repo.findByUuid).not.toHaveBeenCalled();
        });

        it.each(['ADMIN', 'SUPER_ADMIN'])('%s puede ver el perfil de otro', async (role) => {
            const uc = new UserProfileUseCase(makeRepo());
            await expect(uc.getProfile(OTHER, { userUuid: OWNER, roles: [role] })).resolves.toBeDefined();
        });

        it('un actor sin uuid nunca es propietario', async () => {
            const uc = new UserProfileUseCase(makeRepo());
            await expect(uc.getProfile(OWNER, { userUuid: '', roles: [] })).rejects.toBeInstanceOf(ForbiddenException);
        });

        it('devuelve UserNotFoundError si el usuario no existe', async () => {
            const uc = new UserProfileUseCase(makeRepo(null));
            await expect(uc.getProfile(OWNER, { userUuid: OWNER, roles: [] })).rejects.toBeInstanceOf(UserNotFoundError);
        });
    });

    describe('actualización', () => {
        it('el propietario actualiza y la escritura queda acotada por RLS a su uuid', async () => {
            const repo = makeRepo();
            const uc = new UserProfileUseCase(repo);
            await uc.updateProfile(OWNER, { nombres: 'Ana María' }, { userUuid: OWNER, roles: [] });
            expect(repo.updateContacto).toHaveBeenCalledWith(OWNER, { nombres: 'Ana María' }, OWNER);
        });

        it('un administrador que edita a otro NO fija la RLS (no es su contacto)', async () => {
            const repo = makeRepo();
            const uc = new UserProfileUseCase(repo);
            await uc.updateProfile(OTHER, { direccion: 'X' }, { userUuid: OWNER, roles: ['ADMIN'] });
            expect(repo.updateContacto).toHaveBeenCalledWith(OTHER, { direccion: 'X' }, undefined);
        });

        it('un usuario común NO puede editar a otro y no se toca la BD', async () => {
            const repo = makeRepo();
            const uc = new UserProfileUseCase(repo);
            await expect(uc.updateProfile(OTHER, { nombres: 'Hack' }, { userUuid: OWNER, roles: ['CLIENTE_CEDENTE'] }))
                .rejects.toBeInstanceOf(ForbiddenException);
            expect(repo.updateContacto).not.toHaveBeenCalled();
        });

        it('rechaza nombre vacío y correo inválido antes de tocar la BD', async () => {
            const repo = makeRepo();
            const uc = new UserProfileUseCase(repo);
            const actor = { userUuid: OWNER, roles: [] };
            await expect(uc.updateProfile(OWNER, { nombres: '  ' }, actor)).rejects.toBeInstanceOf(ValidationError);
            await expect(uc.updateProfile(OWNER, { correo: 'no-es-correo' }, actor)).rejects.toBeInstanceOf(ValidationError);
            expect(repo.updateContacto).not.toHaveBeenCalled();
        });

        it('UserNotFoundError si el repositorio no encontró el contacto', async () => {
            const repo = makeRepo();
            repo.updateContacto.mockResolvedValue(false);
            const uc = new UserProfileUseCase(repo);
            await expect(uc.updateProfile(OWNER, { nombres: 'A' }, { userUuid: OWNER, roles: [] })).rejects.toBeInstanceOf(UserNotFoundError);
        });
    });
});
