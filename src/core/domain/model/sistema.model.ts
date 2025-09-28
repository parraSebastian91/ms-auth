import { Entity } from "../../share/entity";
import { Id } from "../../share/valueObject/id.valueObject";
import { ModuloModel } from "./modulo.model";
import { OrganizacionModel } from "./organizacion.entity";


export class SistemaModel extends Entity<SistemaModel> {

    nombre: string;
    descripcion: string;
    activo: boolean;
    modulos: ModuloModel[]; // Assuming ModuloModel is defined elsewhere
    organicaciones: OrganizacionModel[]; // Assuming OrganizacionModel is defined elsewhere

    constructor() {
        super();
    }

    equalsTo(entity: SistemaModel): boolean {
        return this.id.getValue() === entity.id.getValue();
    }

    static create(sistema: any): SistemaModel {
        const { id, nombre, descripcion, activo } = sistema;

        return new SistemaModel.SistemaBuilder()
            .id(id)
            .nombre(nombre)
            .descripcion(descripcion)
            .activo(activo)
            .modulos(sistema.modulos.map(m => ModuloModel.create(m)))
            .organicaciones(sistema.organicaciones.map(o => OrganizacionModel.create(o)))
            .build();
    }

    static toEntity(sistemaModel: SistemaModel): any {
        const { id, nombre, descripcion, activo, modulos, organicaciones } = sistemaModel;
        return {
            id: Number(id.getValue()),
            nombre,
            descripcion,
            activo,
            modulos: modulos.map(m => ModuloModel.toEntity(m)),
            organicaciones: organicaciones.map(o => OrganizacionModel.toEntity(o))
        };
    }

    private static SistemaBuilder = class {
        private sistema: SistemaModel = new SistemaModel();

        constructor() { }

        public id(id: number) {
            this.sistema.id = new Id(id);
            return this;
        }

        nombre(nombre: string) {
            this.sistema.nombre = nombre;
            return this;
        }

        descripcion(descripcion: string) {
            this.sistema.descripcion = descripcion;
            return this;
        }

        activo(activo: boolean) {
            this.sistema.activo = activo;
            return this;
        }

        modulos(modulos: ModuloModel[]) {
            this.sistema.modulos = modulos;
            return this;
        }

        organicaciones(organicaciones: OrganizacionModel[]) {
            this.sistema.organicaciones = organicaciones;
            return this;
        }

        build(): SistemaModel {
            return this.sistema;
        }
    }
}