import { ITipoContactoService } from "src/core/domain/puertos/inbound/iTipoContacto.interface";
import { ITipoContactoAplication } from "../iTipoContactoAplication.interface";
import { TipoContactoModel } from "src/core/domain/model/tipoContacto.model";


export class TipoContactoAplicationService implements ITipoContactoAplication {

    constructor(private readonly tipoContactoService: ITipoContactoService) { }

    async getAllTipoContacto(): Promise<TipoContactoModel[]> {
        return await this.tipoContactoService.getAllTipoContacto();
    }
}