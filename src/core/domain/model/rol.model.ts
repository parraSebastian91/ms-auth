import { RolEntity } from "src/infrastructure/database/entities/rol.entity";
import { Entity } from "../../share/entity";
import { Id } from "../../share/valueObject/id.valueObject";
import { PermisoModel } from "./permisos.model";
import { ModuloModel } from "./modulo.model";
import { UsuarioModel } from "./usuario.model";
import { PermisoEntity } from "src/infrastructure/database/entities/permisos.entity";
import { ModuloEntity } from "src/infrastructure/database/entities/modulo.entity";
import { UsuarioEntity } from "src/infrastructure/database/entities/usuario.entity";

export class RolModel extends Entity<RolModel>{

    nombre: string;
    codigo: string;
    descripcion: string;
    permisos: PermisoModel[];
    modulos: ModuloModel[];
    usuarios: UsuarioModel[];

    constructor() {
        super();
    }

    static create(rol: RolEntity): RolModel {
        const { id, codigo, nombre, descripcion, permisos, modulos, usuarios } = rol;
        const rolModel = new this.rolModelBuilder()
            .setId(Number(id))
            .setCodigo(codigo)
            .setNombre(nombre)
            .setDescripcion(descripcion)
            .setPermisos(permisos)
            .setModulos(modulos)
            .setUsuarios(usuarios)
            .build();
            if(rolModel.permisos.length === 0) delete rolModel.permisos;
            if(rolModel.modulos.length === 0) delete rolModel.modulos;
            if(rolModel.usuarios.length === 0) delete rolModel.usuarios;  
        return rolModel
    }

    static toEntity(rolModel: RolModel): RolEntity {
        const { id, codigo, nombre, descripcion, permisos, modulos, usuarios } = rolModel;
        const rolEntity = {
            id: Number(id.getValue()),
            codigo,
            nombre,
            descripcion,
            permisos: permisos? permisos.map(p => PermisoModel.toEntity(p)): [],
            modulos: modulos? modulos.map(m => ModuloModel.toEntity(m)): [],
            usuarios: usuarios? usuarios.map(u => UsuarioModel.toEntity(u)): []
        };
        return rolEntity;
    }

    private static rolModelBuilder = class {
        
        RolModel: RolModel = new RolModel();

        setId(id: number) {
            this.RolModel.id = new Id(id);
            return this;
        }

        setNombre(nombre: string) {
            this.RolModel.nombre = nombre? nombre : '';
            return this;
        }

        setCodigo(codigo: string) {
            this.RolModel.codigo = codigo? codigo : '';
            return this;
        }

        setDescripcion(descripcion: string) {
            this.RolModel.descripcion = descripcion? descripcion : '';
            return this;
        }

        setPermisos(permisos: PermisoEntity[]) {
            this.RolModel.permisos = permisos ? permisos.map(p => PermisoModel.create(p)) : [];
            return this;
        }

        setModulos(modulos: ModuloEntity[]) {
            this.RolModel.modulos = modulos? modulos.map(m => ModuloModel.create(m)) : [];
            return this;
        }

        setUsuarios(usuarios: UsuarioEntity[]) {
            this.RolModel.usuarios = usuarios? usuarios.map(u => UsuarioModel.create(u)) : [];
            return this;
        }

        build() {
            return this.RolModel;
        }
    };

    equalsTo(entity: RolModel): boolean {
        throw new Error("Method not implemented.");
    }

}