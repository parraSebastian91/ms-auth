
import { ContactoModel } from "src/core/domain/model/contacto.model";

import { IContactoAplication } from "../iContactoAplication.interface";
import { IContactoService } from "src/core/domain/puertos/inbound/iContactoService.interface";


export class ContactoAplicationService implements IContactoAplication {
    constructor(private readonly contactoService: IContactoService) {}

    async findById(id: string): Promise<ContactoModel | null> {
        return await this.contactoService.findById(id);
    }

    async findAll(): Promise<ContactoModel[] | null> {
        return await this.contactoService.findAll();
    }

    async create(data: any): Promise<ContactoModel> {
        return await this.contactoService.create(data);
    }

    async update(id: string, data: any): Promise<ContactoModel> {
        return await this.contactoService.update(id, data);
    }

    async delete(id: string): Promise<void> {
        return await this.contactoService.delete(id);
    }
}