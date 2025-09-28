import { TipoContactoModel } from "../../model/tipoContacto.model";


export interface ITipoContactoService {
   
    getAllTipoContacto(): Promise<TipoContactoModel[]>;
    
}