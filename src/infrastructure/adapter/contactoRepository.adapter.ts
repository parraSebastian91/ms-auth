import { In, Repository } from "typeorm";

import { ContactoEntity } from "../database/entities/contacto.entity";
import { InjectRepository } from "@nestjs/typeorm";
import { IContactoRepository } from "src/core/domain/puertos/outbound/iContactoRepository.interface";
import { Injectable } from "@nestjs/common";
import { RegistroContactoModel } from "src/core/domain/model/registroContacto.model";

@Injectable()
export class ContactoRepositoryAdapter implements IContactoRepository {

    constructor(@InjectRepository(ContactoEntity) private contactoRepository: Repository<ContactoEntity>) {
    }

    findById(id: number): Promise<ContactoEntity | null> {
        return this.contactoRepository.findOne({
            where: { id },
            relations: ["tipoContacto"]
        });
    }
    findAll(): Promise<ContactoEntity[] | null> {
        return this.contactoRepository.find({
            relations: ["tipoContacto"]
        });
    }

    async create(data: RegistroContactoModel): Promise<number> {
        let sql = `
        INSERT INTO core.contacto (nombres, apellido_paterno, apellido_materno, direccion, celular, correo, tipo_documento, numero_documento, pais_emision, fecha_nacimiento, redes_sociales, tipo_contacto_id, created_at, updated_at, activo, eliminado_at) 
        VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9::bpchar, $10, '{}'::jsonb, $11, now(), now(), true, NULL)
        RETURNING contacto_id;
        `;
        
        try {
            const result = await this.contactoRepository.query(sql, [
                data.nombres,
                data.apellidoPaterno,
                data.apellidoMaterno,
                data.direccion,
                data.celular,
                data.correo,
                data.tipoDocumento,
                data.numeroDocumento,
                data.pais_emision,
                data.fechaNacimiento.toISOString().split('T')[0],
                data.tipoContacto,
            ]);
            return Number(result[0].contacto_id);
        } catch (error) {
            console.error('Error executing query:', error);
            throw new Error('Failed to create contacto');
        }
    }

    update(id: number, data: ContactoEntity): Promise<ContactoEntity> {
        return this.contactoRepository.update(id, data)
            .then(() => this.contactoRepository.findOne({ where: { id }, relations: ["tipoContacto"] }))
            .then((contacto) => {
                if (!contacto) {
                    throw new Error(`Contacto with id ${id} not found`);
                }
                return contacto;
            });
    }

    delete(id: number): Promise<void> {
        return this.contactoRepository.delete(id)
            .then((result) => {
                if (result.affected === 0) {
                    throw new Error(`Contacto with id ${id} not found`);
                }
            });
    }

    async findByCorreo(correo: string): Promise<ContactoEntity | null> {
        return this.contactoRepository.findOne({
            where: { correo },
            relations: ["usuario"]
        });
    }
}