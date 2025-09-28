import { RolModel } from "src/core/domain/model/rol.model"

export interface IRolAplicationService {
    getAll(): Promise<RolModel[]>
    getById(id: number): Promise<RolModel>
}