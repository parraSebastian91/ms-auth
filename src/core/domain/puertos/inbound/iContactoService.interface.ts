import { ContactoDTO } from "src/infrastructure/http-server/model/dto/contacto.dto";
import { ContactoModel } from "../../model/contacto.model";


export interface IContactoService {
    findById(id: string): Promise<ContactoModel | null>;
    findAll(): Promise<ContactoModel[] | null>;
    create(data: ContactoDTO): Promise<any>;
    update(id: string, data: ContactoDTO): Promise<ContactoModel>;
    delete(id: string): Promise<void>;
}