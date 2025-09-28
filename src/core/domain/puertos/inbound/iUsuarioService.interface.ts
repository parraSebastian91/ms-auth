import { UsuarioDTO } from "src/infrastructure/http-server/model/dto/usuario.dto";
import { UsuarioModel } from "../../model/usuario.model";

export interface IUsuarioService {
    getAllUsuarios(): Promise<UsuarioModel[]>;
    getUsuarioById(id: string): Promise<UsuarioModel>;
    getUsuarioByUsername(username: string): Promise<UsuarioModel>;
    createUsuario(data: UsuarioDTO): Promise<UsuarioModel>;
    updateUsuario(id: string, data: UsuarioModel): Promise<UsuarioModel>;
    deleteUsuario(id: string): Promise<void>;
}