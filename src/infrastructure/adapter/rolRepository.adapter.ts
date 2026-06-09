import { IRolRepository } from "src/core/domain/puertos/outbound/iRolRepository.interface";
import { RolEntity } from "../database/entities/rol.entity";
import { Inject, Injectable, Logger } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { rolEnum } from "src/core/domain/model/constantes.model";

@Injectable()
export class RolRepositoryAdapter implements IRolRepository {
    private readonly logger = new Logger(RolRepositoryAdapter.name);
    constructor(@InjectRepository(RolEntity) private rolRepository: Repository<RolEntity>) { }

    getAll(): Promise<RolEntity[]> {
        return this.rolRepository.find();
    }
    getById(id: number): Promise<RolEntity> {
        return this.rolRepository.findOne({
            where: { id }
        })
    }

    async setRolInicial(idUsuario: number, tipoUsuario: rolEnum): Promise<boolean> {
        const RolCedente = [3, 5, 6];
        // const RolCedenteAdm = [3, 5, 9];
        const RolEjecutivo = [3, 5, 7];
        const usuarioEstandar = [3, 5];
        // const RolEjecutivoAdm = [3, 5, 8];
        let query = `
        INSERT INTO core.usuario_rol (usuario_id, rol_id) VALUES `
        switch (tipoUsuario) {
            case rolEnum.CEDENTE:
                RolCedente.forEach(rolId => {
                    query += `(${idUsuario}, ${rolId}),`;
                });
                break;
            case rolEnum.EJECUTIVO:
                RolEjecutivo.forEach(rolId => {
                    query += `(${idUsuario}, ${rolId}),`;
                });
                break;
            default:
                usuarioEstandar.forEach(rolId => {
                    query += `(${idUsuario}, ${rolId}),`;
                });
                break;
        }
        query = query.slice(0, -1) + ';';
        try {
            await this.rolRepository.query(query);
            return true;
        } catch (error) {
            this.logger.error('Error setting initial roles for user', error);
            throw new Error('Failed to set initial roles for user');
        }

    }
}