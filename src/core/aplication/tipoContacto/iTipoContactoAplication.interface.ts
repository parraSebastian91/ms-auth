import { TipoContactoModel } from "src/core/domain/model/tipoContacto.model";
export interface ITipoContactoAplication {
    getAllTipoContacto(): Promise<TipoContactoModel[]>;
}