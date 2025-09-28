import { RolEntity } from "src/infrastructure/database/entities/rol.entity";

export interface IRolRepository {
    getAll(): Promise<RolEntity[]>
    getById(id: number): Promise<RolEntity>
}