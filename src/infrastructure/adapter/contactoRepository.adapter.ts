import { In, Repository } from "typeorm";

import { ContactoEntity } from "../database/entities/contacto.entity";
import { InjectRepository } from "@nestjs/typeorm";
import { IContactoRepository } from "src/core/domain/puertos/outbound/iContactoRepository.interface";


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
            relations:["tipoContacto"]
        });
    }
    create(data: ContactoEntity): Promise<ContactoEntity> {
        return this.contactoRepository.save(data);
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

    
    
}