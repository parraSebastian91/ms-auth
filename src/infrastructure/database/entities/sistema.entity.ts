import { Column, Entity, ManyToMany, OneToMany, PrimaryGeneratedColumn } from "typeorm";
import { ModuloEntity } from "./modulo.entity";
import { OrganizacionEntity } from "./organizacion.entity";


@Entity({ name: 'sistema' })
export class SistemaEntity {

    @PrimaryGeneratedColumn({ name: 'sistema_id' })
    id: number;

    @Column({ type: "character varying", name: 'nombre' })
    nombre: string;

    @Column({ type: "character varying", name: 'path'})
    path: string;

    @Column({ type: "character varying", name: 'descripcion' })
    descripcion: string;

    @Column({ type: "boolean", name: 'activo' })
    activo: boolean;

    @OneToMany(
        () => ModuloEntity,
        modulo => modulo.sistema, //optional
        { onDelete: 'NO ACTION', onUpdate: 'NO ACTION' },
    )
    modulos: ModuloEntity[];

    @ManyToMany(() => OrganizacionEntity,
        organizacion => organizacion.sistemas,
        {
            onDelete: 'NO ACTION', onUpdate: 'NO ACTION'

        })
    organicaciones: OrganizacionEntity[];

}