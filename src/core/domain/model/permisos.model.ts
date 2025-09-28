import { PermisoEntity } from "src/infrastructure/database/entities/permisos.entity";
import { Entity } from "../../share/entity";
import { Id } from "../../share/valueObject/id.valueObject";
import { RolModel } from "./rol.model";
import { ModuloModel } from "./modulo.model";

export class PermisoModel extends Entity<PermisoModel> {

    nombre: string;
    descripcion: string;
    codigo: string;
    activo: boolean;

    roles: RolModel[]
    Modulos: ModuloModel[];

    constructor() {
        super();
    }

    equalsTo(entity: PermisoModel): boolean {
        if (!entity) return false;
        return this.id === entity.id
    }

    static create(permisos: PermisoEntity): PermisoModel {
        const { id, nombre, descripcion, codigo, activo, modulos, rol } = permisos;
        return new this.permisosModelBuilder()
            .setId(id)
            .setNombre(nombre)
            .setDescripcion(descripcion)
            .setCodigo(codigo)
            .setActivo(activo)
            .setModulos(modulos ? modulos.map(modulo => ModuloModel.create(modulo)) : [])
            .setRoles(rol ? rol.map(rol => RolModel.create(rol)): [])
            .build();
    }

    static toEntity(permisosModel: PermisoModel): PermisoEntity {
        const { id, nombre, descripcion, codigo, activo, roles, Modulos } = permisosModel;

        const permisoEntity: PermisoEntity = {
            id: Number(id.getValue()),
            nombre,
            descripcion,
            codigo,
            activo,
            rol: roles.map(rol => RolModel.toEntity(rol)),
            modulos: Modulos.map(modulo => ModuloModel.toEntity(modulo))
        };

        return permisoEntity;
    }

    private static permisosModelBuilder = class {

        PermisosModel: PermisoModel = new PermisoModel();

        setId(id: number) {
            this.PermisosModel.id = new Id(id);
            return this;
        }

        setNombre(nombre: string) {
            this.PermisosModel.nombre = nombre;
            return this;
        }

        setDescripcion(descripcion: string) {
            this.PermisosModel.descripcion = descripcion;
            return this;
        }

        setCodigo(codigo: string) {
            this.PermisosModel.codigo = codigo;
            return this;
        }

        setActivo(activo: boolean) {
            this.PermisosModel.activo = activo;
            return this;
        }

        setRoles(roles: RolModel[]) {
            this.PermisosModel.roles = roles;
            return this;
        }

        setModulos(modulos: ModuloModel[]) {
            this.PermisosModel.Modulos = modulos;
            return this;
        }

        build() {
            return this.PermisosModel
        }
    }
}