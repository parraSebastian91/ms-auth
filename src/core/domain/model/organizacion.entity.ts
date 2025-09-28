import { OrganizacionEntity } from "src/infrastructure/database/entities/organizacion.entity";
import { Entity } from "../../share/entity";
import { Id } from "../../share/valueObject/id.valueObject";
import { ContactoModel } from "./contacto.model";
import { SistemaModel } from "./sistema.model";
import { CuentaBancariaModel } from "./cuentaBancaria.model";

export class OrganizacionModel extends Entity<OrganizacionModel> {

    razonSocial: string;
    rut: string;
    dv: string;
    giro: string;
    logoBase64?: string;
    contacto: ContactoModel[];
    sistemas: SistemaModel[]; // Define the type for sistemas if available
    cuentasBancarias: CuentaBancariaModel[]; // Define the type for cuentasBancarias if


    constructor() {
        super();
    }

    equalsTo(entity: OrganizacionModel): boolean {
        if (!entity) return false;
        return this.id === entity.id;
    }

    static create(organizacion: OrganizacionEntity): OrganizacionModel {
        const { id, razonSocial, rut, dv, giro, logoBase64, contactos } = organizacion;
        const contactoEntity = contactos ? contactos.map((c: any) => ContactoModel.create(c)) : [];
        return new this.OrganizacionModelBuilder()
            .id(id)
            .razonSocial(razonSocial)
            .rut(rut)
            .dv(dv)
            .giro(giro)
            .logoBase64(logoBase64)
            .contacto(contactoEntity)
            .build();
    }

    static toEntity(organizacionModel: OrganizacionModel): OrganizacionEntity {
        const { id, razonSocial, rut, dv, giro, logoBase64, contacto, sistemas,cuentasBancarias } = organizacionModel;

        const organizacionEntity: OrganizacionEntity = {
            id: Number(id.getValue()),
            razonSocial,
            rut,
            dv,
            giro,
            logoBase64,
            contactos: contacto.map(c => ContactoModel.toEntity(c)),
            contactoId: null, // Asignar valor adecuado si está disponible
            sistemas: sistemas ? sistemas.map(s => SistemaModel.toEntity(s)) : [],
            cuentasBancarias: cuentasBancarias ? cuentasBancarias.map(cb => CuentaBancariaModel.toEntity(cb)) : []
        };
        return organizacionEntity;
    }

    private static OrganizacionModelBuilder = class {
        private organizacion: OrganizacionModel = new OrganizacionModel();

        constructor() { }

        public id(id: number) {
            this.organizacion.id = new Id(id);
            return this;
        }

        razonSocial(razonSocial: string) {
            this.organizacion.razonSocial = razonSocial;
            return this;
        }

        rut(rut: string) {
            this.organizacion.rut = rut;
            return this;
        }

        dv(dv: string) {
            this.organizacion.dv = dv;
            return this;
        }

        giro(giro: string) {
            this.organizacion.giro = giro;
            return this;
        }

        logoBase64(logoBase64: string) {
            this.organizacion.logoBase64 = logoBase64;
            return this;
        }

        contacto(contacto: ContactoModel[]) {
            this.organizacion.contacto = contacto;
            return this;
        }

        build(): OrganizacionModel {
            if (!this.organizacion.id) {
                throw new Error("Id is required");
            }
            return this.organizacion;
        }
    }
}