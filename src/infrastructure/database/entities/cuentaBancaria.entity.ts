import { OrganizacionEntity } from "./organizacion.entity"
import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: 'cuenta_bancaria' })
export class CuentaBancariaEntity {

    @PrimaryGeneratedColumn({ type: "bigint", name: 'cuenta_id' })
    id: number;

    @Column({ type: "character varying", name: 'nombre_titular' })
    nombreTitular: string;  

    @Column({ type: "character varying", name: 'banco' })
    banco: string;

    @Column({ type: "character varying", name: 'numero' })
    numero: string;

    @Column({ type: "character varying", name: 'correo_contacto' })
    correoContacto: string;

    @Column({ type: "character varying", name: 'rut_titular' })
    rutTitular: string;

    @Column({ type: "bigint", name: 'organizacion_id' })
    organizacionId: number; 

    @ManyToOne(() => OrganizacionEntity, organizacion => organizacion.cuentasBancarias)
    @JoinColumn([{ name: 'organizacion_id', referencedColumnName: 'id' }])
    organizacion: OrganizacionEntity;


}