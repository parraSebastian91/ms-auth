import { ContactoEntity } from "src/infrastructure/database/entities/contacto.entity";
import { RegistroContactoModel } from "../../model/registroContacto.model";

export interface IContactoRepository  {
    findById(id: number): Promise<ContactoEntity | null>;
    findByCorreo(correo: string): Promise<ContactoEntity | null>;
    findAll(): Promise<ContactoEntity[] | null>;
    create(data: RegistroContactoModel): Promise<number>;
    update(id: number, data: ContactoEntity): Promise<ContactoEntity>;
    delete(id: number): Promise<void>;
}