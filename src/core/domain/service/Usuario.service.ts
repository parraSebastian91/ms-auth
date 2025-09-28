import { UsuarioEntity } from "src/infrastructure/database/entities/usuario.entity";
import { UsuarioModel } from "../model/usuario.model";
import { IUsuarioService } from "../puertos/inbound/iUsuarioService.interface";
import { IUsuarioRepository } from "../puertos/outbound/iUsuarioRepository.interface";
import { InsertError } from "../../share/errors/Insert.error";
import { UsuarioDTO } from "src/infrastructure/http-server/model/dto/usuario.dto";
import { EntityNotFoundError } from "src/core/share/errors/usuarioNotFound.error";
import { IContactoRepository } from "../puertos/outbound/iContactoRepository.interface";
import { IRolRepository } from "../puertos/outbound/iRolRepository.interface";
import { UserExistError } from "src/core/share/errors/usuarioExistError.error";
import { Id } from "src/core/share/valueObject/id.valueObject";


export class UsuarioService implements IUsuarioService {
    constructor(
        private usuarioRepository: IUsuarioRepository,
        private ContactoRepository: IContactoRepository,
        private rolRepository: IRolRepository
    ) { }

    async getAllUsuarios(): Promise<UsuarioModel[]> {
        const usuarios = await this.usuarioRepository.getAllUsuarios();
        if (!usuarios || usuarios.length === 0) {
            return [];
        }
        return usuarios.map(usuario => {
            const usuarioModel = UsuarioModel.create(usuario);
            return usuario ? usuarioModel : null;
        });
    }

    async getUsuarioById(id: string): Promise<UsuarioModel> {
        const usuario = await this.usuarioRepository.getUsuarioById(Number(id));
        if (!usuario) {
            throw new EntityNotFoundError("Usuario not found");
        }
        return UsuarioModel.create(usuario);
    }

    async getUsuarioByUsername(username: string): Promise<UsuarioModel> {
        const usuario = await this.usuarioRepository.getUsuarioByUsername(username);
        if (!usuario) {
            throw new EntityNotFoundError("Usuario not found");
        }
        return UsuarioModel.create(usuario);
    }

    async createUsuario(data: UsuarioDTO): Promise<UsuarioModel> {
        const usuarioExist = await this.usuarioRepository.getUsuarioByUsername(data.userName);
        if (usuarioExist) {
            throw new UserExistError("Usuario ya existe");
        }

        const newId = await this.usuarioRepository.getValidId();
    
        const consultas = await Promise.all([this.rolRepository.getById(1), this.ContactoRepository.findById(Number(data.contactoId))])
        const usuarioModel = UsuarioModel.fromDTO(data, consultas[1], null);
        usuarioModel.id = new Id(newId);
        const usuarioEntity: UsuarioEntity = UsuarioModel.toEntity(usuarioModel);

        const createdUsuario = await this.usuarioRepository.createUsuario(usuarioEntity);
        createdUsuario.rol = [consultas[0]];
        createdUsuario.contacto = consultas[1];

        this.usuarioRepository.createUsuario(usuarioEntity);

        if (!createdUsuario) {
            throw new InsertError("Error creating usuario");
        }
        return UsuarioModel.create(createdUsuario);
    }

    async updateUsuario(id: string, data: UsuarioModel): Promise<UsuarioModel> {
        const usuarioEntity = UsuarioModel.toEntity(data);
        const updatedUsuario = await this.usuarioRepository.updateUsuario(Number(id), usuarioEntity);
        if (!updatedUsuario) {
            throw new InsertError("Error updating usuario");
        }
        return UsuarioModel.create(updatedUsuario);
    }

    async deleteUsuario(id: string): Promise<void> {
        await this.usuarioRepository.deleteUsuario(Number(id));
    }
}