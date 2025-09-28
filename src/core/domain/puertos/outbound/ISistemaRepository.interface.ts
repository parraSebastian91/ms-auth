import { FromEntitySistemaDTO } from "../../DTO/sistema.dto";

export interface ISistemaRepository {
    getSistemaByUsername(username: string): Promise<FromEntitySistemaDTO[] | null>;
}