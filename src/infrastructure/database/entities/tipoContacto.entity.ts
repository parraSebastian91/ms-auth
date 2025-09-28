import { Entity, PrimaryGeneratedColumn, Column, PrimaryColumn, OneToMany } from "typeorm";


@Entity({ name: 'tipo_contacto' })
export class TipoContactoEntity {
    @PrimaryGeneratedColumn({ name: 'tipo_contacto_id' })
    id: number;

    @Column({ name: 'nombre', type: 'varchar', length: 50 })
    nombre: string;

    @Column({ name: 'descripcion', type: 'varchar', length: 50, nullable: true })
    descripcion?: string;
}