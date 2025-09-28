import { EntityNotFoundError } from "src/core/share/errors/usuarioNotFound.error";
import { TipoContactoModel } from "../model/tipoContacto.model";
import { ITipoContactoService } from "../puertos/inbound/iTipoContacto.interface";
import { ITipoContactoRepository } from "../puertos/outbound/iTipoContactoRepository.interface";


export class TipoContactoService implements ITipoContactoService {

    constructor(private readonly tipoContactoRepository: ITipoContactoRepository) { }

    async getAllTipoContacto(): Promise<TipoContactoModel[]> {
        const tipoContactos = await this.tipoContactoRepository.getAllTipoContacto();
        if (!tipoContactos || tipoContactos.length === 0) {
            throw new EntityNotFoundError("No contact types found");
        }
        return tipoContactos.map(tipo => TipoContactoModel.create(tipo));
    }
}