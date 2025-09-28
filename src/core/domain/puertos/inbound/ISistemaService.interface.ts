import { SistemaDTO } from "../../DTO/sistema.dto";

export interface ISistemaService {
    // Define the methods that the service should implement
    getSistemaByUsername(username: string): Promise<SistemaDTO | null>;
}
