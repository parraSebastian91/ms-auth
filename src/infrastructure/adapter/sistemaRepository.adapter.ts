/*
https://docs.nestjs.com/providers#services
*/

import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { SistemaEntity } from '../database/entities/sistema.entity';
import { FromEntitySistemaDTO, SistemaDTO } from 'src/core/domain/DTO/sistema.dto';
import { ISistemaRepository } from 'src/core/domain/puertos/outbound/ISistemaRepository.interface';

@Injectable()
export class SistemaRepositoryAdapter implements ISistemaRepository {

    constructor(@InjectRepository(SistemaEntity) private sistemaRepository: Repository<SistemaEntity>) { }


    async getSistemaByUsername(username: string): Promise<FromEntitySistemaDTO[] | null> {

        const sistemas = await this.sistemaRepository
            .createQueryBuilder('s')
            .leftJoinAndSelect('s.modulos', 'm')
            .leftJoinAndSelect('m.funcionalidades', 'f')
            .leftJoin('s.organicaciones', 'org')
            .leftJoin('org.contactos', 'c')
            .leftJoin('c.usuario', 'u')
            .leftJoin('u.contacto', 'uc')
            .leftJoin('uc.organizaciones', 'o')
            .where('u.userName = :username', { username })
            .andWhere('s.activo = :activo', { activo: true })
            .andWhere('m.activo = :moduloActivo', { moduloActivo: true })
            .andWhere('f.activo = :funcionalidadActivo', { funcionalidadActivo: true })
            .select([
                'u.userName as username',
                'uc.nombre as nombre',
                'o.razon_social as razon_social',
                's.id as sistemaId',
                's.nombre as sistemaNombre',
                's.path as sistemaPath',
                'm.id as moduloId',
                'm.nombre as moduloNombre',
                'm.path as moduloPath',
                'f.id as funcionalidadId',
                'f.nombre as funcionalidadNombre',
                'f.path as funcionalidadPath',
            ])
            .getRawMany();

        if (!sistemas || sistemas.length === 0) {
            return null;
        }
        
        return sistemas;
    }
}
