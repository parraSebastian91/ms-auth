import { IRolRepository } from "src/core/domain/puertos/outbound/iRolRepository.interface";
import { RolEntity } from "../database/entities/rol.entity";
import { Inject } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";


export class RolRepositoryAdapter implements IRolRepository {

    constructor(@InjectRepository(RolEntity) private rolRepository: Repository<RolEntity>) { }

    getAll(): Promise<RolEntity[]> {
        return this.rolRepository.find();
    }
    getById(id: number): Promise<RolEntity> {
        return this.rolRepository.findOne({
            where: { id }
        })
    }
}