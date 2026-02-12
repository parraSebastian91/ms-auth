import { UsuarioDTO } from "src/infrastructure/http-server/model/dto/usuario.dto";

import { IUsuarioAplication } from "../iUsuarioAplication.interface";
import { IUsuarioService } from "src/core/domain/puertos/inbound/iUsuarioService.interface";
import { UsuarioModel } from "src/core/domain/model/usuario.model";

export class UsuarioAplicationService implements IUsuarioAplication {

    constructor(private readonly usuarioService: IUsuarioService) { }

    async findById(id: string): Promise<UsuarioModel | null> {
        return this.usuarioService.getUsuarioById(id);
    }

}