import { UsuarioModel } from 'src/core/domain/model/usuario.model';
import { UsuarioEntity } from '../database/entities/usuario.entity';

export class UsuarioMapper {
    static toDomain(entity: UsuarioEntity): UsuarioModel {
        return UsuarioModel.create(entity);
    }

    static toDomainList(entities: UsuarioEntity[]): UsuarioModel[] {
        return entities.map(entity => this.toDomain(entity));
    }

    static toEntity(model: UsuarioModel): Partial<UsuarioEntity> {
        return UsuarioModel.toEntity(model);
    }
}