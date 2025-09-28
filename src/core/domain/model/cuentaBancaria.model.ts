import { CuentaBancariaEntity } from "src/infrastructure/database/entities/cuentaBancaria.entity";
import { Entity } from "../../share/entity";
import { EntityBuildError } from "../../share/errors/EntityBuild.error";
import { Id } from "../../share/valueObject/id.valueObject";
import { OrganizacionModel } from "./organizacion.entity";

export class CuentaBancariaModel extends Entity<CuentaBancariaModel> {

    nombreTitular: string;  
    banco: string;
    numero: string;
    correoContacto: string;
    rutTitular: string;
    organizacion: OrganizacionModel;

    constructor(
    ) {
       super()
    }

    static create(cuentaBancaria: CuentaBancariaEntity): CuentaBancariaModel {
        const { id, nombreTitular, banco, numero, correoContacto, rutTitular, organizacion } = cuentaBancaria;
        return new CuentaBancariaModel.CuentaBancariaBuilder()
            .id(id)
            .nombreTitular(nombreTitular)
            .banco(banco)
            .numero(numero)
            .correoContacto(correoContacto)
            .rutTitular(rutTitular)
            .organizacionId(OrganizacionModel.create(organizacion))
            .build();
    }

    static toEntity(cuentaBancariaModel: CuentaBancariaModel): CuentaBancariaEntity {
        const { id, nombreTitular, banco, numero, correoContacto, rutTitular, organizacion } = cuentaBancariaModel;
        const cuentaBancariaEntity: CuentaBancariaEntity = {
            id: Number(id.getValue()),
            nombreTitular,
            banco,
            numero,
            correoContacto,
            rutTitular,
            organizacion: OrganizacionModel.toEntity(organizacion),
            organizacionId: Number(organizacion.id.getValue())
        };
        return cuentaBancariaEntity;
    }

    equalsTo(entity: CuentaBancariaModel): boolean {
        throw new Error("Method not implemented.");
    }

    private static CuentaBancariaBuilder = class {
        private cuentaBancaria: CuentaBancariaModel = new CuentaBancariaModel();

        constructor() { }

        public id(id: number) {
            this.cuentaBancaria.id = new Id(id);
            return this;
        }

        nombreTitular(nombreTitular: string) {
            this.cuentaBancaria.nombreTitular = nombreTitular;
            return this;
        }

        banco(banco: string) {
            this.cuentaBancaria.banco = banco;
            return this;
        }

        numero(numero: string) {
            this.cuentaBancaria.numero = numero;
            return this;
        }

        correoContacto(correoContacto: string) {
            this.cuentaBancaria.correoContacto = correoContacto;
            return this;
        }

        rutTitular(rutTitular: string) {
            this.cuentaBancaria.rutTitular = rutTitular;
            return this;
        }

        organizacionId(organizacionId: OrganizacionModel) {
            this.cuentaBancaria.organizacion = organizacionId;
            return this;
        }

        build(): CuentaBancariaModel {
            if (!this.cuentaBancaria.id) {
                throw new EntityBuildError("Id is required");
            }
            return this.cuentaBancaria;
        }
    };


}