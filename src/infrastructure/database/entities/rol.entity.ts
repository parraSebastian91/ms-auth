import { Column, Entity, JoinTable, ManyToMany, PrimaryGeneratedColumn } from "typeorm";
import { PermisoEntity } from "./permisos.entity";
import { UsuarioEntity } from "./usuario.entity";
import { ModuloEntity } from "./modulo.entity";


@Entity({ name: 'rol', schema: 'identity' })
export class RolEntity {

    @PrimaryGeneratedColumn({ name: 'rol_id' })
    id: number;

    @Column({ type: "character varying", name: 'codigo', unique: true })
    codigo: string;

    @Column({ type: "character varying", name: 'nombre' })
    nombre: string;

    @Column({ type: "character varying", name: 'descripcion' })
    descripcion: string;

    @ManyToMany(
        () => PermisoEntity,
        { onDelete: 'NO ACTION', onUpdate: 'NO ACTION' })
    @JoinTable({
        name: 'rol_modulo_permiso',
        schema: 'identity',
        joinColumn: {
            name: 'rol_id',
            referencedColumnName: 'id',
        },
        inverseJoinColumn: {
            name: 'permiso_id',
            referencedColumnName: 'id',
        },
    })
    permisos: PermisoEntity[];

    @ManyToMany(
        () => ModuloEntity,
        modulo => modulo.roles, //optional
        { onDelete: 'NO ACTION', onUpdate: 'NO ACTION' })
    @JoinTable({
        name: 'rol_modulo_permiso',
        schema: 'identity',
        joinColumn: {
            name: 'rol_id',
            referencedColumnName: 'id',
        },
        inverseJoinColumn: {
            name: 'modulo_id',
            referencedColumnName: 'id',
        },
    })
    modulos: ModuloEntity[];

    @ManyToMany(() => UsuarioEntity, usuario => usuario.rol)
    @JoinTable({
        name: 'usuario_rol',
        schema: 'identity',
        joinColumn: {
            name: 'rol_id',
            referencedColumnName: 'id',
        },
        inverseJoinColumn: {
            name: 'usuario_id',
            referencedColumnName: 'id',
        },
    })
    usuarios: UsuarioEntity[];
}
