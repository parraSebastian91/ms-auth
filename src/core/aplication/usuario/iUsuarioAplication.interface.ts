
import { UsuarioModel } from "../../domain/model/usuario.model";

export interface IUsuarioAplication {
    findById(id: string): Promise<UsuarioModel | null>;
}