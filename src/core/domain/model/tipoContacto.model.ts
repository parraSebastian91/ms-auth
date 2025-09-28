import { TipoContactoEntity } from "src/infrastructure/database/entities/tipoContacto.entity";

import { Id } from "../../share/valueObject/id.valueObject";
import { Entity } from "../../share/entity";


export class TipoContactoModel extends Entity<TipoContactoModel> {
    
    nombre: string;
    descripcion: string;

    constructor() {
        super();
    }

    equalsTo(entity: TipoContactoModel): boolean {
        return this.id.getValue() === entity.id.getValue();
    }

    static create(tipoContacto: TipoContactoEntity): TipoContactoModel {
        const { id, nombre, descripcion } = tipoContacto;

        return new TipoContactoModel.TipoContactoBuilder()
            .id(id)
            .nombre(nombre)
            .descripcion(descripcion)
            .build();
    }

    static toEntity(tipoContactoModel: TipoContactoModel): TipoContactoEntity {
        const { id, nombre, descripcion } = tipoContactoModel;
        return {
            id: Number(id.getValue()),
            nombre,
            descripcion
        };
    }

    private static TipoContactoBuilder = class {

        private tipoContacto: TipoContactoModel = new TipoContactoModel();

        constructor() { }

        public id(id: number) {
            this.tipoContacto.id = new Id(id);
            return this;
        }

        nombre(nombre: string) {
            this.tipoContacto.nombre = nombre;
            return this;
        }

        descripcion(descripcion: string) {
            this.tipoContacto.descripcion = descripcion;
            return this;
        }

        build(): TipoContactoModel {
            return this.tipoContacto;
        }
    }
}