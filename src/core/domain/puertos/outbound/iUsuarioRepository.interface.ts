import { UsuarioEntity } from "src/infrastructure/database/entities/usuario.entity";
import { UsuarioModel } from "../../model/usuario.model";

export interface IUsuarioRepository {
    getValidId(): Promise<number> ;
    getAllUsuarios(): Promise<UsuarioModel[]>;
    getUsuarioById(id: number): Promise<UsuarioModel>;
    getUsuarioByUsername(username: string): Promise<UsuarioModel>;
    createUsuario(data: UsuarioModel): Promise<UsuarioModel>;
    updateUsuario(id: number, data: UsuarioModel): Promise<UsuarioModel>;
    deleteUsuario(id: number): Promise<void>;
    getSystemsByUsername(username: string): Promise<any[]>;
}