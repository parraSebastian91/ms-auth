import { SistemaDTO } from "src/core/domain/DTO/sistema.dto";

export interface ISistemaAplicationService {
    getSistemaByUsername(username: string): Promise<SistemaDTO | null>;
}
