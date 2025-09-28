import { TipoContactoEntity } from "src/infrastructure/database/entities/tipoContacto.entity";


export interface ITipoContactoRepository {
    getAllTipoContacto(): Promise<TipoContactoEntity[]>;
}