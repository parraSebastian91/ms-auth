import { UsuarioEntity } from "src/infrastructure/database/entities/usuario.entity";
import { ContactoModel } from "./contacto.model";
import { RolModel } from "./rol.model";
import { Id } from "../../share/valueObject/id.valueObject";
import { Entity } from "../../share/entity";
import { ContactoEntity } from "src/infrastructure/database/entities/contacto.entity";
import { RolEntity } from "src/infrastructure/database/entities/rol.entity";
import { UsuarioDTO } from "src/infrastructure/http-server/model/dto/usuario.dto";
import * as crypto from "crypto";
import * as bcrypt from "bcrypt";


export class UsuarioModel extends Entity<UsuarioModel> {

    userName: string;
    password: string;
    creacion: Date;
    activo: boolean;
    update: Date;
    contacto: ContactoModel;
    rol: RolModel[];

    constructor() {
        super();
    }

    equalsTo(entity: UsuarioModel): boolean {
        if (!entity) return false;
        return this.id === entity.id
    }


    static create(usuario: UsuarioEntity): UsuarioModel {
        const { id, userName, password, creacion, activo, update, contacto, rol } = usuario;
        return new this.usuarioModelBuilder()
            .setId(Number(id))
            .setUserName(userName)
            .setPassword(password)
            .setCreacion(creacion)
            .setActivo(activo)
            .setUpdate(update)
            .setContacto(contacto)
            .setRol(rol)
            .build();
    }

    static toEntity(usuarioModel: UsuarioModel): UsuarioEntity {
        const { userName, password, creacion, activo, update, contacto, rol } = usuarioModel;

        return {
            id: Number(usuarioModel.id.getValue()),
            userName,
            password,
            creacion,
            activo,
            update,
            contacto: ContactoModel.toEntity(contacto),
            rol: rol.map(r => RolModel.toEntity(r))
        };;
    }

    static fromDTO(DTO: UsuarioDTO, contacto: ContactoEntity, rol: RolEntity[]): UsuarioModel{
        const saltRounds = 10;
        const hashedPassword = bcrypt.hashSync(DTO.password, saltRounds);

        return new this.usuarioModelBuilder()
            .setId(null)
            .setUserName(DTO.userName)
            .setPassword(hashedPassword)
            .setCreacion(new Date())
            .setActivo(true)
            .setUpdate(new Date())
            .setContacto(contacto)
            .setRol(rol)
            .build();
    }

    private static usuarioModelBuilder = class {

        UsuarioModel: UsuarioModel = new UsuarioModel();

        setId(id: number) {
            this.UsuarioModel.id = new Id(id);
            return this;
        }

        setUserName(userName: string) {
            this.UsuarioModel.userName = userName;
            return this;
        }

        setPassword(password: string) {
            this.UsuarioModel.password = password;
            return this;
        }

        setCreacion(creacion: Date) {
            this.UsuarioModel.creacion = creacion;
            return this;
        }

        setActivo(activo: boolean) {
            this.UsuarioModel.activo = activo;
            return this;
        }

        setUpdate(update: Date) {
            this.UsuarioModel.update = update;
            return this;
        }

        setContacto(contacto: ContactoEntity) {
            this.UsuarioModel.contacto = contacto ? ContactoModel.create(contacto) : null;
            return this;
        }

        setRol(rol: RolEntity[]) {
            this.UsuarioModel.rol = rol ? rol.map(r => RolModel.create(r)) : [];
            return this;
        }

        build() {
            return this.UsuarioModel;
        }
    }
}