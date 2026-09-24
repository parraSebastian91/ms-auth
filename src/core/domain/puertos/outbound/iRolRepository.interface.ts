import { RolEntity } from "src/infrastructure/database/entities/rol.entity";
import { rolEnum } from "../../model/constantes.model";

export interface IRolRepository {
    getAll(): Promise<RolEntity[]>
    getById(id: number): Promise<RolEntity>
    setRolInicial(idUsuario: number, tipoUsuario: rolEnum): Promise<boolean>;
}