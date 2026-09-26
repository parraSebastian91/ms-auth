import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { UpdateContactoData, UserProfileModel } from '../../core/domain/model/userProfile.model';
import { IUserProfileRepository } from '../../core/domain/puertos/outbound/IUserProfileRepository.interface';

@Injectable()
export class UserProfileRepositoryAdapter implements IUserProfileRepository {
    constructor(@InjectDataSource() private readonly dataSource: DataSource) { }

    async findByUuid(uuid: string): Promise<UserProfileModel | null> {
        const rows = await this.dataSource.query(
            `SELECT u.username,
                    u.usuario_uuid,
                    u.created_at AS ingreso,
                    u.activo,
                    c.nombres, c.apellido_paterno, c.apellido_materno,
                    c.direccion, c.celular, c.correo, c.fecha_nacimiento,
                    c.redes_sociales, c.tipo_documento, c.numero_documento,
                    tc.nombre AS tipo_contacto,
                    COALESCE(ARRAY_AGG(r.codigo ORDER BY r.codigo) FILTER (WHERE r.codigo IS NOT NULL), '{}'::text[]) AS roles
               FROM identity.usuario u
               LEFT JOIN identity.contacto c       ON c.contacto_id = u.contacto_id
               LEFT JOIN identity.tipo_contacto tc ON tc.tipo_contacto_id = c.tipo_contacto_id
               LEFT JOIN identity.usuario_rol ur   ON ur.usuario_id = u.usuario_id
               LEFT JOIN identity.rol r            ON r.rol_id = ur.rol_id
              WHERE u.usuario_uuid = $1
              GROUP BY u.username, u.usuario_uuid, u.created_at, u.activo,
                       c.nombres, c.apellido_paterno, c.apellido_materno, c.direccion, c.celular,
                       c.correo, c.fecha_nacimiento, c.redes_sociales, c.tipo_documento,
                       c.numero_documento, tc.nombre`,
            [uuid],
        );
        return rows.length ? UserProfileModel.fromData(rows[0]) : null;
    }

    async updateContacto(uuid: string, data: UpdateContactoData, rlsUserUuid?: string): Promise<boolean> {
        const qr = this.dataSource.createQueryRunner();
        await qr.connect();
        await qr.startTransaction();
        try {
            if (rlsUserUuid) {
                await qr.query(`SELECT set_config('app.user_uuid', $1, true)`, [rlsUserUuid]);
            }
            // useStructuredResult: sin él, TypeORM devuelve [filas, afectadas] y length siempre > 0
            const result = await qr.query(
                `UPDATE identity.contacto
                    SET nombres          = COALESCE($1, nombres),
                        apellido_paterno = COALESCE($2, apellido_paterno),
                        apellido_materno = COALESCE($3, apellido_materno),
                        direccion        = COALESCE($4, direccion),
                        celular          = COALESCE($5, celular),
                        correo           = COALESCE($6, correo)
                  WHERE contacto_id = (SELECT contacto_id FROM identity.usuario WHERE usuario_uuid = $7)
              RETURNING contacto_id`,
                [
                    data.nombres ?? null, data.apellido_paterno ?? null, data.apellido_materno ?? null,
                    data.direccion ?? null, data.celular ?? null, data.correo ?? null, uuid,
                ],
                true,
            );
            await qr.commitTransaction();
            return (result.records?.length ?? 0) > 0;
        } catch (e) {
            await qr.rollbackTransaction();
            throw e;
        } finally {
            await qr.release();
        }
    }
}
