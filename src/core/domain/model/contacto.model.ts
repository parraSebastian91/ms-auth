
import { Correo } from "./valueObject/correo.ValueObject";
import { Celular } from "./valueObject/celular.valueObject";
import { Entity } from "../../share/entity";
import { ContactoEntity } from "src/infrastructure/database/entities/contacto.entity";
import { EntityBuildError } from "../../share/errors/EntityBuild.error";
import { Id } from "../../share/valueObject/id.valueObject";
import { TipoContactoModel } from "./tipoContacto.model";
import { UsuarioModel } from "./usuario.model";
import { UsuarioEntity } from "src/infrastructure/database/entities/usuario.entity";
import { OrganizacionModel } from "./organizacion.entity";
import { OrganizacionEntity } from "src/infrastructure/database/entities/organizacion.entity";
import { json } from "stream/consumers";
import { commandUpdateUserProfile } from "src/core/aplication/auth/command/updateProfile.command";

export class ContactoModel extends Entity<ContactoModel> {

    nombre: string;
    direccion: string;
    celular: Celular;
    correo: Correo;
    rrss: string;
    url: string;
    avatarData: string;
    tipoContacto: TipoContactoModel;
    usuario: UsuarioModel;
    organizaciones: OrganizacionModel[];

    constructor() {
        super();
    }

    equalsTo(entity: ContactoModel): boolean {
        return this.id.getValue() === entity.id.getValue();
    }
    
    static create(contacto: ContactoEntity): ContactoModel {
        const { id, nombre, direccion, celular, correo, rrss, url, avatarData, tipoContacto, organizaciones } = contacto;
        const tipoContactoEntity = tipoContacto ? TipoContactoModel.create(tipoContacto) : null;
        const celularValueObject = new Celular(celular);
        return new ContactoModel.ContactoBuilder()
            .id(id)
            .nombre(nombre)
            .direccion(direccion)
            .celular(celularValueObject)
            .correo(new Correo(correo))
            .rrss(rrss)
            .url(url)
            .avatarData(JSON.stringify(avatarData))
            .tipoContacto(tipoContactoEntity)
            .organizaciones(organizaciones)
            .build();
    }


    static toEntity(contactoModel: ContactoModel): ContactoEntity {
        const { id, nombre, direccion, celular, correo, rrss, url, avatarData, tipoContacto,usuario, organizaciones} = contactoModel;
        const contactoEntity: ContactoEntity = {
            id: Number(id.getValue()),
            nombre,
            direccion,
            celular: celular.getValue(),
            correo: correo.getValue(),
            rrss,
            url,
            avatarData: JSON.parse(avatarData),
            tipoContacto: tipoContacto ? TipoContactoModel.toEntity(tipoContacto) : null,
            usuario: usuario ? UsuarioModel.toEntity(usuario): null,
            organizaciones: organizaciones? organizaciones.map(o => OrganizacionModel.toEntity(o)): null
        };
        return contactoEntity;
    }
    private static ContactoBuilder = class {

        private contacto: ContactoModel = new ContactoModel();

        constructor() { }

        public id(id: number) {
            this.contacto.id = new Id(id);
            return this;
        }

        nombre(nombre: string) {
            this.contacto.nombre = nombre;
            return this;
        }

        direccion(direccion: string) {
            this.contacto.direccion = direccion;
            return this;
        }

        celular(celular: Celular) {
            this.contacto.celular = celular;
            return this;
        }

        correo(correo: Correo) {
            this.contacto.correo = correo;
            return this;
        }

        rrss(rrss: string) {
            this.contacto.rrss = rrss;
            return this;
        }

        url(url: string) {
            this.contacto.url = url;
            return this;
        }

        avatarData(avatarData: string) {
            this.contacto.avatarData = avatarData;
            return this;
        }

        tipoContacto(tipoContactoId: TipoContactoModel) {
            this.contacto.tipoContacto = tipoContactoId;
            return this;
        }

        organizaciones(organizaciones: OrganizacionEntity[]){
            this.contacto.organizaciones = organizaciones? organizaciones.map(o => OrganizacionModel.create(o)): null;
            return this;
        }

        updateProfile(command: commandUpdateUserProfile, contacto: ContactoModel) {
            this.contacto.nombre = command.nombre;
            this.contacto.direccion = command.direccion;
            this.contacto.celular = new Celular(command.celular);
            this.contacto.correo = new Correo(command.correo);
            this.contacto.rrss = command.rrss;
            this.contacto.url = command.url;
            this.contacto.tipoContacto = contacto.tipoContacto;
            this.contacto.usuario = contacto.usuario;
            this.contacto.organizaciones = contacto.organizaciones;
            return this;
        }

        build(): ContactoModel {
            if (!this.contacto.id) {
                throw new EntityBuildError("Id is required");
            }
            if (!this.contacto.nombre) {
                throw new EntityBuildError("Nombre is required");
            }
            if (!this.contacto.direccion) {
                throw new EntityBuildError("Direccion is required");
            }
            if (!this.contacto.celular) {
                throw new EntityBuildError("Celular is required");
            }
            if (!this.contacto.correo) {
                throw new EntityBuildError("Correo is required");
            }
            if (!this.contacto.tipoContacto) {
                throw new EntityBuildError("TipoContactoId is required");
            }
            return this.contacto;
        }
    }

}

