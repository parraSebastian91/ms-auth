
import { Column, Entity, JoinTable, ManyToMany, OneToMany, PrimaryGeneratedColumn } from "typeorm";
import { SistemaEntity } from "./sistema.entity";
import { CuentaBancariaEntity } from "./cuentaBancaria.entity";
import { ContactoEntity } from "./contacto.entity";

@Entity({ name: 'organizacion' })
export class OrganizacionEntity {

    @PrimaryGeneratedColumn({ type: "bigint", name: 'organizacion_id' })
    id: number;

    @Column({ type: "character varying", name: 'razon_social' })
    razonSocial: string;

    @Column({ type: "character varying", name: 'rut' })
    rut: string;

    @Column({ type: "character", name: 'dv', length: 1 })
    dv: string;

    @Column({ type: "character varying", name: 'giro' })
    giro: string;

    @Column({ type: "text", name: 'logo_base64', nullable: true })
    logoBase64?: string;

    @Column({ type: "bigint", name: 'contacto_id' })
    contactoId: number;

    @ManyToMany(() => ContactoEntity, organizacion => organizacion.id, { onDelete: 'NO ACTION', onUpdate: 'NO ACTION' })
    @JoinTable({
        name: 'organizacion_contacto',
        joinColumn: {
            name: 'organizacion_id',
            referencedColumnName: 'id',
        },
        inverseJoinColumn: {
            name: 'contacto_id',
            referencedColumnName: 'id',
        },
    })
    contactos: ContactoEntity[];

    @ManyToMany(() => SistemaEntity,
        sistemas => sistemas.organicaciones,
        {
            onDelete: 'NO ACTION', onUpdate: 'NO ACTION'

        })
    @JoinTable({
        name: 'organizacion_sistema',
        joinColumn: {
            name: 'organizacion_id',
            referencedColumnName: 'id',
        },
        inverseJoinColumn: {
            name: 'sistema_id',
            referencedColumnName: 'id',
        },
    })
    sistemas: SistemaEntity[];

    @OneToMany(
        () => CuentaBancariaEntity,
        cuentaBancaria => cuentaBancaria.organizacion, //optional
        { onDelete: 'NO ACTION', onUpdate: 'NO ACTION' },
    )
    cuentasBancarias: CuentaBancariaEntity[];
}