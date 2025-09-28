import { ModuloEntity } from "src/infrastructure/database/entities/modulo.entity";
import { Entity } from "../../share/entity";
import { Id } from "../../share/valueObject/id.valueObject";
import { SistemaModel } from "./sistema.model";
import { PermisoModel } from "./permisos.model";
import { RolModel } from "./rol.model";
import { FuncionalidadModel } from "./funcionalidad.model";

export class ModuloModel extends Entity<ModuloModel> {

    nombre: string;
    descripcion: string;
    activo: boolean;
    sistema: SistemaModel;
    path: string;
    permisos: PermisoModel[]; // Define the type of permisos if available
    roles: RolModel[]; // Define the type of roles if available
    funcionalidades: FuncionalidadModel[]; // Define the type of funcionalidades if available

    constructor() {
        super();
    }

    equalsTo(entity: ModuloModel): boolean {
        throw new Error("Method not implemented.");
    }

    public static create(modulo: ModuloEntity): ModuloModel {
        const { id, nombre, descripcion, activo, sistema, permisos, roles, funcionalidades } = modulo;
        return new ModuloModel.ModuloBuilder()
            .id(id)
            .nombre(nombre)
            .descripcion(descripcion)
            .activo(activo)
            .sistema(SistemaModel.create(sistema))
            .permisos(permisos.map(permiso => PermisoModel.create(permiso)))
            .roles(roles.map(rol => RolModel.create(rol)))
            .funcionalidades(funcionalidades.map(funcionalidad => FuncionalidadModel.create(funcionalidad)))
            .build();
    }

    public static toEntity(moduloModel: ModuloModel): ModuloEntity {
        const { id, nombre, path, descripcion, activo, sistema } = moduloModel;
        const moduloEntity: ModuloEntity = {
            id: Number(id.getValue()),
            nombre,
            descripcion,
            path,
            activo,
            sistema: SistemaModel.toEntity(sistema),
            permisos: [], // Ajusta esto según cómo quieras mapear los permisos
            roles: [],     // Ajusta esto según cómo quieras mapear los roles
            funcionalidades: [] // Ajusta esto según cómo quieras mapear las funcionalidades
        };
        return moduloEntity;
    }

    private static ModuloBuilder = class {
        private modulo: ModuloModel = new ModuloModel();

        constructor() { }

        public id(id: number) {
            this.modulo.id = new Id(id);
            return this;
        }

        nombre(nombre: string) {
            this.modulo.nombre = nombre;
            return this;
        }

        descripcion(descripcion: string) {
            this.modulo.descripcion = descripcion;
            return this;
        }

        activo(activo: boolean) {
            this.modulo.activo = activo;
            return this;
        }

        sistema(sistema: SistemaModel) {
            this.modulo.sistema = sistema;
            return this;
        }

        permisos(permisos: PermisoModel[]) {
            this.modulo.permisos = permisos;
            return this;
        }

        roles(roles: RolModel[]) {
            this.modulo.roles = roles;
            return this;
        }

        funcionalidades(funcionalidades: FuncionalidadModel[]) {
            this.modulo.funcionalidades = funcionalidades;
            return this;
        }

        build() {
            return this.modulo;
        }
    }

}