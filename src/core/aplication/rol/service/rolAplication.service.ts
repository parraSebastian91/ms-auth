import { RolModel } from "src/core/domain/model/rol.model";
import { IRolAplicationService } from "../iRolAplication.interface";
import { IRolService } from "src/core/domain/puertos/inbound/iRolService.interface";

export class RolAplicationService implements IRolAplicationService{

    constructor(private readonly rolService: IRolService){}

    getAll(): Promise<RolModel[]> {
        return this.rolService.getAll();
    }
    getById(id: number): Promise<RolModel> {
        return this.rolService.getById(id);
    }
}