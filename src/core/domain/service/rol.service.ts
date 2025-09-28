import { RolEntity } from "src/infrastructure/database/entities/rol.entity";
import { IRolService } from "../puertos/inbound/iRolService.interface";
import { IRolRepository } from "../puertos/outbound/iRolRepository.interface";
import { RolModel } from "../model/rol.model";

export class RolService implements IRolService {

    constructor(private readonly rolRepository: IRolRepository) { }

    async getAll(): Promise<RolModel[]> {
        const rolEntity = await this.rolRepository.getAll();
        return rolEntity.map(r => RolModel.create(r))
    }
    async getById(id: number): Promise<RolModel> {
        const rolEntity = await this.rolRepository.getById(id);
        return RolModel.create(rolEntity);
    }


}