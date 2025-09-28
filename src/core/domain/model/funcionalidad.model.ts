import { FuncionalidadEntity } from "src/infrastructure/database/entities/funcionalidad.entity";
import { Entity } from "../../share/entity";
import { ModuloModel } from "./modulo.model";
import { Id } from "src/core/share/valueObject/id.valueObject";

export class FuncionalidadModel extends Entity<FuncionalidadModel> {


    nombre: string;
    descripcion: string;
    path: string;
    moduloId: number;
    activo: boolean;
    modulo: ModuloModel;

    constructor() { super()}

    equalsTo(entity: FuncionalidadModel): boolean {
        if (!entity) return false;
        return this.id === entity.id &&
            this.nombre === entity.nombre &&
            this.descripcion === entity.descripcion &&
            this.path === entity.path &&
            this.moduloId === entity.moduloId &&
            this.activo === entity.activo;
    }

    public static create(funcionalidad: FuncionalidadEntity): FuncionalidadModel {
        const { id, nombre, descripcion, path, moduloId, activo, modulo } = funcionalidad;
        return new FuncionalidadModel.FuncionalidadBuilder()
            .id(new Id(id).getValue())
            .nombre(nombre)
            .descripcion(descripcion)
            .path(path)
            .moduloId(moduloId)
            .activo(activo)
            .modulo(ModuloModel.create(modulo))
            .build();
    }

    public static toEntity(funcionalidadModel: FuncionalidadModel): FuncionalidadEntity {
        const { id, nombre, descripcion, path, moduloId, activo, modulo } = funcionalidadModel;
        const funcionalidadEntity: FuncionalidadEntity = {
            id: Number(id.getValue()),
            nombre,
            descripcion,
            path,
            moduloId,
            activo,
            modulo: ModuloModel.toEntity(modulo)
        };
        return funcionalidadEntity;
    }

    private static FuncionalidadBuilder = class {
        private funcionalidad: FuncionalidadModel = new FuncionalidadModel();

        constructor() { }

        public id(id: number) {
            this.funcionalidad.id = new Id(id);
            return this;
        }

        public nombre(nombre: string) {
            this.funcionalidad.nombre = nombre;
            return this;
        }

        public descripcion(descripcion: string) {
            this.funcionalidad.descripcion = descripcion;
            return this;
        }

        public path(path: string) {
            this.funcionalidad.path = path;
            return this;
        }

        public moduloId(moduloId: number) {
            this.funcionalidad.moduloId = moduloId;
            return this;
        }

        public activo(activo: boolean) {
            this.funcionalidad.activo = activo;
            return this;
        }

        public modulo(modulo: ModuloModel) {
            this.funcionalidad.modulo = modulo;
            return this;
        }

        public build() {
            return this.funcionalidad;
        }
    }

}