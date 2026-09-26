import { DataSource } from 'typeorm';
import { UserProfileRepositoryAdapter } from './userProfileRepository.adapter';

function setup(queryImpl: jest.Mock) {
    const qr = {
        connect: jest.fn(), startTransaction: jest.fn(), commitTransaction: jest.fn(),
        rollbackTransaction: jest.fn(), release: jest.fn(), query: queryImpl,
    };
    const ds = { createQueryRunner: () => qr, query: jest.fn() } as unknown as DataSource;
    return { qr, repo: new UserProfileRepositoryAdapter(ds) };
}

describe('UserProfileRepositoryAdapter.updateContacto', () => {
    it('devuelve false cuando el UPDATE no afectó filas (p. ej. la RLS lo acotó)', async () => {
        const { repo } = setup(jest.fn().mockResolvedValue({ records: [], affected: 0 }));
        await expect(repo.updateContacto('u', { nombres: 'A' })).resolves.toBe(false);
    });

    it('devuelve true cuando el UPDATE afectó una fila', async () => {
        const { repo } = setup(jest.fn().mockResolvedValue({ records: [{ contacto_id: 1 }], affected: 1 }));
        await expect(repo.updateContacto('u', { nombres: 'A' })).resolves.toBe(true);
    });

    it('pide resultado estructurado (sin él TypeORM devuelve [filas, n] y length siempre > 0)', async () => {
        const query = jest.fn().mockResolvedValue({ records: [], affected: 0 });
        const { repo } = setup(query);
        await repo.updateContacto('u', { nombres: 'A' });
        const updateCall = query.mock.calls.find(c => String(c[0]).includes('UPDATE identity.contacto'));
        expect(updateCall?.[2]).toBe(true);
    });

    it('fija app.user_uuid en la transacción solo cuando se pasa rlsUserUuid', async () => {
        const a = setup(jest.fn().mockResolvedValue({ records: [], affected: 0 }));
        await a.repo.updateContacto('u', {}, 'owner-uuid');
        expect(a.qr.query).toHaveBeenCalledWith(expect.stringContaining("set_config('app.user_uuid'"), ['owner-uuid']);

        const b = setup(jest.fn().mockResolvedValue({ records: [], affected: 0 }));
        await b.repo.updateContacto('u', {});
        expect(b.qr.query).not.toHaveBeenCalledWith(expect.stringContaining('set_config'), expect.anything());
    });

    it('hace rollback y libera la conexión si el UPDATE falla', async () => {
        const { repo, qr } = setup(jest.fn().mockRejectedValue(new Error('boom')));
        await expect(repo.updateContacto('u', { nombres: 'A' })).rejects.toThrow('boom');
        expect(qr.rollbackTransaction).toHaveBeenCalled();
        expect(qr.release).toHaveBeenCalled();
        expect(qr.commitTransaction).not.toHaveBeenCalled();
    });
});
