import { UsuarioEntity } from "src/infrastructure/database/entities/usuario.entity";
import { UsuarioModel } from "../../model/usuario.model";
import { RegistroUsuarioModel } from "../../model/registroUsuario.model";

export interface IUsuarioRepository {
    getValidId(): Promise<number> ;
    getAllUsuarios(): Promise<UsuarioModel[]>;
    getUsuarioById(id: number): Promise<UsuarioModel>;
    getUsuarioByUsername(username: string): Promise<UsuarioModel>;
    createUsuario(data: RegistroUsuarioModel): Promise<{ usuarioUuid: string }>;
    updateUsuario(id: number, data: UsuarioModel): Promise<UsuarioModel>;
    updatePassword(id: number, passwordHash: string): Promise<void>;
    deleteUsuario(id: number): Promise<void>;
    getSystemsByUsername(username: string): Promise<any[]>;
    validateField(field: string, value: string): Promise<{ available: boolean; message?: string }>;
    marcarEmailVerificado(userUuid: string): Promise<void>;
    getUsuarioByEmail(email: string): Promise<{ id: number; uuid: string; emailVerificado: boolean; nombres: string } | null>;
    
}