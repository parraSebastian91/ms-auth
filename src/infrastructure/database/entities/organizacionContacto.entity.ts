
import { Entity, JoinColumn, ManyToOne, PrimaryColumn } from "typeorm";
import { OrganizacionEntity } from "./organizacion.entity";
import { ContactoEntity } from "./contacto.entity";

@Entity({ name: 'organizacion_contacto' })
export class OrganizacionContactoEntity {   
    
    @PrimaryColumn({ type: "bigint", name: 'contacto_id' })
    contactoId: number;

    @PrimaryColumn({ type: "bigint", name: 'organizacion_id' })
    organizacionId: number;

    @ManyToOne(() => OrganizacionEntity, organizacion => organizacion.contactos)
    @JoinColumn([{ name: 'organizacion_id', referencedColumnName: 'id' }])
    organizacion: OrganizacionEntity;

    @ManyToOne(() => ContactoEntity, contacto => contacto.organizaciones)
    @JoinColumn([{ name: 'contacto_id', referencedColumnName: 'id' }])
    contacto: ContactoEntity;
}   