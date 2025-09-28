
import { Logger } from "@nestjs/common";
import { IContactoService } from "../puertos/inbound/iContactoService.interface";
import { IContactoRepository } from "../puertos/outbound/iContactoRepository.interface";
import { ContactoModel } from "../model/contacto.model";
import { EntityNotFoundError } from "src/core/share/errors/usuarioNotFound.error";
import { TipoContactoEntity } from "src/infrastructure/database/entities/tipoContacto.entity";
import { ContactoDTO } from "src/infrastructure/http-server/model/dto/contacto.dto";
import { ContactoEntity } from "src/infrastructure/database/entities/contacto.entity";
import { InsertError } from "src/core/share/errors/Insert.error";


export class ContactoService implements IContactoService {

    constructor(private readonly contactoRepository: IContactoRepository) { }

    async findById(id: string): Promise<ContactoModel | null> {
        // Implementation for finding a contact by ID
        const contacto = await this.contactoRepository.findById(Number(id));
        const contactoEntity = contacto ? ContactoModel.create(contacto) : null;
        if (!contacto) {
            throw new EntityNotFoundError(`Contacto with id ${id} not found`);
        }
        Logger.log(`Contacto with id ${id} found successfully`);
        return contactoEntity; // Placeholder
    }

    async findAll(): Promise<ContactoModel[] | null> {
        // Implementation for finding all contacts
        const contactos = await this.contactoRepository.findAll();
        if (!contactos || contactos.length === 0) {
            throw new EntityNotFoundError(`No contacts found in the system`);
        }
        Logger.log(`Found ${contactos.length} contacts`);
        return contactos.map(contacto => ContactoModel.create(contacto)); // Convert to Contacto entities    
    }

    async create(data: ContactoDTO): Promise<ContactoModel> {
        const tipoContacto: TipoContactoEntity = {
            id: Number(data.tipoContactoId),
            nombre: "",
            descripcion: ""
        }
        const contacto: ContactoEntity = {
            id: null,
            nombre: data.nombre,
            direccion: data.direccion,
            celular: data.celular,
            correo: data.correo,
            rrss: data.rrss,
            url: data.url,
            imgBase64: data.imgBase64,
            tipoContacto: tipoContacto,
            organizaciones:null,
            usuario: null
        }
        const createdContacto: ContactoModel = await this.contactoRepository
            .create(contacto)
            .then((created) => {
                Logger.log(`Contacto created successfully with id ${created.id}`);
                return ContactoModel.create(created);
            }).catch((error) => {
                throw new InsertError(`Error creating contact: ${error.message}`);
            });
        return createdContacto;
    }

    async update(id: string, data: ContactoDTO): Promise<ContactoModel> {
        const tipoContacto: TipoContactoEntity = {
            id: Number(data.tipoContactoId),
            nombre: "",
            descripcion: ""
        }
        const contacto: ContactoEntity = {
            id: Number(id),
            nombre: data.nombre,
            direccion: data.direccion,
            celular: data.celular,
            correo: data.correo,
            rrss: data.rrss,
            url: data.url,
            imgBase64: data.imgBase64,
            tipoContacto: tipoContacto,
            organizaciones:null,
            usuario: null
        }
        delete contacto.id; // Remove id to avoid conflict with update method
        const updatedContacto: ContactoModel = await this.contactoRepository
            .update(Number(id), contacto)
            .then((updated) => {
                Logger.log(`Contacto with id ${id} updated successfully`);
                return ContactoModel.create(updated);
            }).catch((error) => {
                throw new InsertError(`Error updating contact: ${error.message}`);
            });
        return updatedContacto; // Placeholder
    }

    async delete(id: string): Promise<void> {
        const contacto = await this.contactoRepository.findById(Number(id));
        if (!contacto) {
            throw new EntityNotFoundError(`Contacto with id ${id} not found`);
        }
        await this.contactoRepository.delete(Number(id))
            .then(() => {
                Logger.log(`Contacto with id ${id} deleted successfully`);
            })
            .catch((error) => {
                throw new InsertError(`Error deleting contact: ${error.message}`);
            });
    }
}