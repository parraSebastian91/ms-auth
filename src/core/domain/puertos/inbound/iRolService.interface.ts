
import { RolModel } from "../../model/rol.model"

export interface IRolService {
    getAll(): Promise<RolModel[]>
    getById(id: number): Promise<RolModel>
}