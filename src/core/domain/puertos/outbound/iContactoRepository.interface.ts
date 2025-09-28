import { ContactoEntity } from "src/infrastructure/database/entities/contacto.entity";

export interface IContactoRepository  {
    findById(id: number): Promise<ContactoEntity | null>;
    findAll(): Promise<ContactoEntity[] | null>;
    create(data: ContactoEntity): Promise<ContactoEntity>;
    update(id: number, data: ContactoEntity): Promise<ContactoEntity>;
    delete(id: number): Promise<void>;
}