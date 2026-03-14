import { ContactoEntity } from 'src/infrastructure/database/entities/contacto.entity';
import { RefreshSessionEntity } from 'src/infrastructure/database/entities/RefreshSession.entity';
import { RolEntity } from 'src/infrastructure/database/entities/rol.entity';
import { UsuarioEntity } from 'src/infrastructure/database/entities/usuario.entity';
import { Entity } from '../../share/entity';
import { Id } from '../../share/valueObject/id.valueObject';

export class UsuarioModel extends Entity<UsuarioModel> {
    uuid: string;
    userName: string;
    password: string;
    creacion: Date;
    activo: boolean;
    update?: Date | null;
    contacto?: ContactoEntity | null;
    rol: RolEntity[];
    refreshSessions?: RefreshSessionEntity[];

    constructor() {
        super();
        this.rol = [];
    }

    equalsTo(entity: UsuarioModel): boolean {
        return this.id.getValue() === entity.id.getValue();
    }

    static create(usuario: UsuarioEntity): UsuarioModel {
        const model = new UsuarioModel();
        model.id = new Id(usuario.id);
        model.uuid = usuario.usuarioUuid;
        model.userName = usuario.userName;
        model.password = usuario.password;
        model.creacion = usuario.creacion;
        model.activo = usuario.activo;
        model.update = usuario.update ?? null;
        model.contacto = usuario.contacto ?? null;
        model.rol = usuario.rol ?? [];
        model.refreshSessions = usuario.refreshSessions ?? [];
        return model;
    }

    static toEntity(usuario: UsuarioModel): Partial<UsuarioEntity> {
        return {
            id: usuario.id?.getValue(),
            usuarioUuid: usuario.uuid,
            userName: usuario.userName,
            password: usuario.password,
            creacion: usuario.creacion,
            activo: usuario.activo,
            update: usuario.update ?? null,
            contacto: usuario.contacto ?? null,
            rol: usuario.rol ?? [],
            refreshSessions: usuario.refreshSessions ?? [],
        };
    }
}