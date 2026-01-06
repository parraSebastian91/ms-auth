import { InjectRepository } from "@nestjs/typeorm";
import { UsuarioEntity } from "../database/entities/usuario.entity";
import { Repository } from "typeorm";
import { IUsuarioRepository } from "../../core/domain/puertos/outbound/iUsuarioRepository.interface";
import { Injectable } from "@nestjs/common";

@Injectable()
export class UsuarioRepositoryAdapter implements IUsuarioRepository {
    constructor(
        @InjectRepository(UsuarioEntity) private readonly usuarioRepository: Repository<UsuarioEntity>,
    ) { }

    getValidId(): Promise<number> {
        return this.usuarioRepository.count().then(count => count + 1);
    }

    getAllUsuarios(): Promise<UsuarioEntity[]> {
        return this.usuarioRepository.find({
            relations: ['rol', 'contacto', 'contacto.tipoContacto'],
        });
    }
    getUsuarioById(id: number): Promise<UsuarioEntity> {
        return this.usuarioRepository
            .createQueryBuilder('usuario')
            .leftJoinAndSelect('usuario.rol', 'rol')
            .leftJoinAndSelect('usuario.contacto', 'contacto')
            .leftJoinAndSelect('contacto.tipoContacto', 'tipoContacto')
            .leftJoinAndSelect('rol.permisos', 'permisos', 'permisos.activo = :activo', { activo: true })
            .where('usuario.id = :id', { id })
            .getOne();
    }

    async getUsuarioByUsername(username: string): Promise<UsuarioEntity> {
        const usuario = await this.usuarioRepository
            .createQueryBuilder('usuario')
            .leftJoinAndSelect('usuario.rol', 'rol')
            .leftJoinAndSelect('usuario.contacto', 'contacto')
            .leftJoinAndSelect('contacto.tipoContacto', 'tipoContacto')
            .leftJoinAndSelect('rol.permisos', 'permisos', 'permisos.activo = :activo', { activo: true })
            .where('usuario.userName = :username', { username })
            .getOne();
        return usuario;
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

    createUsuario(data: UsuarioEntity): Promise<UsuarioEntity> {
        const newUsuario = this.usuarioRepository.create(data);
        return this.usuarioRepository.save(newUsuario);
    }
    updateUsuario(id: number, data: UsuarioEntity): Promise<UsuarioEntity> {
        return this.usuarioRepository.save({ ...data, id });
    }
    deleteUsuario(id: number): Promise<void> {
        return this.usuarioRepository.delete(id).then(() => { });
    }

}