import { InjectRepository } from "@nestjs/typeorm";
import { UsuarioEntity } from "../database/entities/usuario.entity";
import { Repository } from "typeorm";
import { IUsuarioRepository } from "../../core/domain/puertos/outbound/iUsuarioRepository.interface";
import { Injectable } from "@nestjs/common";
import { UsuarioModel } from "src/core/domain/model/usuario.model";

@Injectable()
export class UsuarioRepositoryAdapter implements IUsuarioRepository {
    constructor(
        @InjectRepository(UsuarioEntity) private readonly usuarioRepository: Repository<UsuarioEntity>,
    ) { }

    getValidId(): Promise<number> {
        return this.usuarioRepository.count().then(count => count + 1);
    }

    getAllUsuarios(): Promise<UsuarioModel[]> {
        const usuariosEntity = this.usuarioRepository.find({
            relations: ['rol', 'contacto', 'contacto.tipoContacto'],
        });
        return usuariosEntity.then(usuarios => usuarios.map((usuario: UsuarioEntity) => {
            const usuarioModel: UsuarioModel = UsuarioModel.create(usuario);
            return usuarioModel;
        }));
    }
    
    getUsuarioById(id: number): Promise<UsuarioModel> {
        return this.usuarioRepository
            .createQueryBuilder('usuario')
            .leftJoinAndSelect('usuario.rol', 'rol')
            .leftJoinAndSelect('usuario.contacto', 'contacto')
            .leftJoinAndSelect('contacto.tipoContacto', 'tipoContacto')
            .leftJoinAndSelect('rol.permisos', 'permisos', 'permisos.activo = :activo', { activo: true })
            .where('usuario.id = :id', { id })
            .getOne().then(usuario => UsuarioModel.create(usuario));
    }

    async getUsuarioByUsername(username: string): Promise<UsuarioModel> {
        const usuario = await this.usuarioRepository
            .createQueryBuilder('usuario')
            .leftJoinAndSelect('usuario.rol', 'rol')
            .leftJoinAndSelect('usuario.contacto', 'contacto')
            .leftJoinAndSelect('contacto.tipoContacto', 'tipoContacto')
            .leftJoinAndSelect('rol.permisos', 'permisos', 'permisos.activo = :activo', { activo: true })
            .where('usuario.userName = :username', { username })
            .getOne();
        return usuario ? UsuarioModel.create(usuario) : null;
    }

    async getSystemsByUsername(username: string) {
        const usuario = await this.usuarioRepository
            .createQueryBuilder('usuario')
            .leftJoinAndSelect('usuario.rol', 'rol')
            .leftJoinAndSelect('rol.modulos', 'modulos')
            .leftJoinAndSelect('modulos.sistema', 'sistema')
            .where('usuario.userName = :username', { username })
            .andWhere('usuario.activo = :usuarioActivo', { usuarioActivo: true })
            .andWhere('sistema.activo = :sistemaActivo', { sistemaActivo: true })
            .getOne();

        // Deduplicar sistemas en memoria
        if (!usuario) return [];
        const sistemasUnicos = Array.from(
            new Map(
                usuario.rol
                    .flatMap(r => r.modulos.map(m => m.sistema))
                    .map(s => [s.id, s])
            ).values()
        );
        return sistemasUnicos;
    }

    createUsuario(data: UsuarioModel): Promise<UsuarioModel> {
        const newUsuario = this.usuarioRepository.create(UsuarioModel.toEntity(data));
        return this.usuarioRepository.save(newUsuario).then(savedUsuario => UsuarioModel.create(savedUsuario));
    }
    updateUsuario(id: number, data: UsuarioModel): Promise<UsuarioModel> {
        return this.usuarioRepository.save({ ...UsuarioModel.toEntity(data), id }).then(savedUsuario => UsuarioModel.create(savedUsuario));
    }
    deleteUsuario(id: number): Promise<void> {
        return this.usuarioRepository.delete(id).then(() => { });
    }

}