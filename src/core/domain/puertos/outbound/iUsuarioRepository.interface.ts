import { UsuarioEntity } from "src/infrastructure/database/entities/usuario.entity";

export interface IUsuarioRepository {
    getValidId(): Promise<number> ;
    getAllUsuarios(): Promise<UsuarioEntity[]>;
    getUsuarioById(id: number): Promise<UsuarioEntity>;
    getUsuarioByUsername(username: string): Promise<UsuarioEntity>;
    createUsuario(data: UsuarioEntity): Promise<UsuarioEntity>;
    updateUsuario(id: number, data: UsuarioEntity): Promise<UsuarioEntity>;
    deleteUsuario(id: number): Promise<void>;
}