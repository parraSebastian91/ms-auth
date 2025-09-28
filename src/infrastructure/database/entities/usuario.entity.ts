import { Column, Entity, JoinColumn, JoinTable, ManyToMany, ManyToOne, OneToOne, PrimaryColumn, PrimaryGeneratedColumn, Table } from "typeorm"
import { RolEntity } from "./rol.entity";
import { ContactoEntity } from "./contacto.entity";

@Entity({ name: 'usuario' })
export class UsuarioEntity {

    @PrimaryGeneratedColumn({ type: "bigint", name: 'usuario_id' })
    id: number;

    @Column({ type: "character varying", name: 'username' })
    userName: string;

    @Column({ type: "character varying", name: 'password_hash' })
    password: string;

    @Column({ type: "date", name: 'fecha_creacion' })
    creacion: Date;

    @Column({ type: "boolean", name: 'activo', default: true })
    activo: boolean;

    @Column({ type: "date", name: 'fecha_actualizacion', nullable: true })
    update: Date;

    // Relación inversa
    @OneToOne(() => ContactoEntity, contacto => contacto.usuario)
    @JoinColumn({ name: 'contacto_id' }) // Asegúrate que el nombre de la columna coincida con la FK real
    contacto: ContactoEntity;

    @ManyToMany(() => RolEntity, rol => rol.usuarios)
    @JoinTable({
            name: 'usuario_rol',
            joinColumn: {
                name: 'usuario_id',
                referencedColumnName: 'id',
            },
            inverseJoinColumn: {
                name: 'rol_id',
                referencedColumnName: 'id',
            },
        })
    rol: RolEntity[];

}