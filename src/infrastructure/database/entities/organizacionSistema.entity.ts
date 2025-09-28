
import { Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from "typeorm";
import { OrganizacionEntity } from "./organizacion.entity";
import { SistemaEntity } from "./sistema.entity";

@Entity({ name: 'organizacion_sistema' })
export class OrganizacionSistemaEntity {

    @PrimaryGeneratedColumn({ type: "bigint", name: 'organizacion_id' })
    organizacionId: number;

    @PrimaryGeneratedColumn({ type: "bigint", name: 'sistema_id' })
    sistemaId: number;

    @ManyToOne(() => OrganizacionEntity, organizacion => organizacion.id)
    @JoinColumn([{ name: 'organizacion_id', referencedColumnName: 'id' }])
    organizacion: OrganizacionEntity;

    @ManyToOne(() => SistemaEntity, sistema => sistema.id)
    @JoinColumn([{ name: 'sistema_id', referencedColumnName: 'id' }])
    sistema: SistemaEntity;
}