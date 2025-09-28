import { Entity, PrimaryGeneratedColumn, Column, OneToOne, PrimaryColumn, ManyToOne, JoinColumn, ManyToMany, JoinTable } from "typeorm";
import { TipoContactoEntity } from "./tipoContacto.entity";
import { OrganizacionEntity } from "./organizacion.entity";
import { UsuarioEntity } from "./usuario.entity";

@Entity({ name: 'contacto' })
export class ContactoEntity {

    @PrimaryGeneratedColumn({ name: 'contacto_id' })
    id: number;

    @Column({ type: 'varchar', length: 50, name: 'nombre' })
    nombre: string;

    @Column({ type: 'varchar', length: 50, name: 'direccion' })
    direccion: string;

    @Column({ type: 'varchar', length: 50, name: 'celular' })
    celular: string;

    @Column({ type: 'varchar', length: 50, name: 'correo' })
    correo: string;

    @Column({ type: 'text', name: 'redes_sociales' })
    rrss: string;

    @Column({ type: 'text', name: 'url' })
    url: string;

    @Column({ type: "character varying", name: 'imagen_base64' })
    imgBase64: string;

    @OneToOne(() => UsuarioEntity, usuario => usuario.contacto)
    usuario: UsuarioEntity;

    @ManyToOne(() => TipoContactoEntity)
    @JoinColumn({ name: 'tipo_contacto_id' })
    tipoContacto: TipoContactoEntity;

    @ManyToMany(() => OrganizacionEntity,
        organizacion => organizacion.contactos,
        {
            onDelete: 'NO ACTION', onUpdate: 'NO ACTION'

        })
    @JoinTable({
        name: 'organizacion_contacto',
        joinColumn: {
            name: 'contacto_id',
            referencedColumnName: 'id',
        },
        inverseJoinColumn: {
            name: 'organizacion_id',
            referencedColumnName: 'id',
        },
    })
    organizaciones: OrganizacionEntity[];


}

