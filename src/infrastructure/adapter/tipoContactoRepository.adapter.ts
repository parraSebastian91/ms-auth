import { InjectRepository } from "@nestjs/typeorm";

import { TipoContactoEntity } from "../database/entities/tipoContacto.entity";
import { Repository } from "typeorm";
import { ITipoContactoRepository } from "src/core/domain/puertos/outbound/iTipoContactoRepository.interface";

export class TipoContactoRepositoryAdapter implements ITipoContactoRepository {

    constructor(@InjectRepository(TipoContactoEntity) private tipoContactoRepository: Repository<TipoContactoEntity>) {
    }
    /**
     * Retrieves all TipoContacto entities from the database.
     * @returns A promise that resolves to an array of TipoContactoEntity.
     */
    getAllTipoContacto(): Promise<TipoContactoEntity[]> {
        return this.tipoContactoRepository.find();
    }

   
}