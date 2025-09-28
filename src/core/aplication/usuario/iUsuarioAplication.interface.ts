import { UsuarioDTO } from "../../../infrastructure/http-server/model/dto/usuario.dto";
import { UsuarioModel } from "../../domain/model/usuario.model";

export interface IUsuarioAplication {
    findAll(): Promise<UsuarioModel[] | null>;
    findById(id: string): Promise<UsuarioModel | null>;
    findByUsername(username: string): Promise<UsuarioModel | null>;
    create(data: UsuarioDTO): Promise<UsuarioModel>;
    update(id: string, data: UsuarioModel): Promise<UsuarioModel>;
    delete(id: string): Promise<void>;
}