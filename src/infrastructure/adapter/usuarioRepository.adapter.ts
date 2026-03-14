import { InjectRepository } from "@nestjs/typeorm";
import { UsuarioEntity } from "../database/entities/usuario.entity";
import { Repository } from "typeorm";
import { IUsuarioRepository } from "../../core/domain/puertos/outbound/iUsuarioRepository.interface";
import { Injectable } from "@nestjs/common";
import { UsuarioModel } from "src/core/domain/model/usuario.model";
import { UsuarioMapper } from "src/infrastructure/mapper/usuario.mapper";

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
        return usuariosEntity.then(usuarios => UsuarioMapper.toDomainList(usuarios));
    }

    getUsuarioById(id: number): Promise<UsuarioModel> {
        return this.usuarioRepository
            .createQueryBuilder('usuario')
            .leftJoinAndSelect('usuario.rol', 'rol')
            .leftJoinAndSelect('usuario.contacto', 'contacto')
            .leftJoinAndSelect('contacto.tipoContacto', 'tipoContacto')
            .leftJoinAndSelect('rol.permisos', 'permisos', 'permisos.activo = :activo', { activo: true })
            .where('usuario.id = :id', { id })
            .getOne().then(usuario => usuario ? UsuarioMapper.toDomain(usuario) : null);
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
        return usuario ? UsuarioMapper.toDomain(usuario) : null;
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
        const newUsuario = this.usuarioRepository.create(UsuarioMapper.toEntity(data));
        return this.usuarioRepository.save(newUsuario).then(savedUsuario => UsuarioMapper.toDomain(savedUsuario));
    }

    updateUsuario(id: number, data: UsuarioModel): Promise<UsuarioModel> {
        return this.usuarioRepository.save({ ...UsuarioMapper.toEntity(data), id })
            .then(savedUsuario => UsuarioMapper.toDomain(savedUsuario))
            .catch(() => {throw new Error('Error updating usuario');});
    }

    async updatePassword(id: number, passwordHash: string): Promise<void> {
        await this.usuarioRepository
            .createQueryBuilder()
            .update()
            .set({ password: passwordHash })
            .where('id = :id', { id })
            .execute();
    }

    deleteUsuario(id: number): Promise<void> {
        return this.usuarioRepository.delete(id).then(() => { });
    }

}