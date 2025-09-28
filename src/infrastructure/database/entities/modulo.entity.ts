import { Column, Entity, JoinTable, ManyToMany, ManyToOne, OneToMany, PrimaryGeneratedColumn, JoinColumn } from "typeorm";
import { SistemaEntity } from "./sistema.entity";
import { PermisoEntity } from "./permisos.entity";
import { RolEntity } from "./rol.entity";
import { FuncionalidadEntity } from "./funcionalidad.entity";

@Entity({ name: 'modulo', schema: 'core' }) 
export class ModuloEntity {

    @PrimaryGeneratedColumn({ name: 'modulo_id', type: 'bigint' })
    id: number;

    @Column({ type: "varchar", name: 'nombre' })
    nombre: string;

    @Column({ type: "varchar", name: 'path' })
    path: string;

    @Column({ type: "varchar", name: 'descripcion' })
    descripcion: string;

    @Column({ type: "boolean", name: 'activo', default: true })
    activo: boolean;

    @ManyToOne(
        () => SistemaEntity,
        sistema => sistema.modulos,
        { onDelete: 'NO ACTION', onUpdate: 'NO ACTION' },
    )
    @JoinColumn({ name: 'sistema_id' })
    sistema: SistemaEntity;

    @ManyToMany(
        () => PermisoEntity,
        permisoEntity => permisoEntity.modulos,
        { onDelete: 'NO ACTION', onUpdate: 'NO ACTION' },
    )
    @JoinTable({
        name: 'rol_modulo_permiso',
        joinColumn: {
            name: 'modulo_id',
            referencedColumnName: 'id',
        },
        inverseJoinColumn: {
            name: 'permiso_id',
            referencedColumnName: 'id',
        },
    })
    permisos: PermisoEntity[];

    @ManyToMany(
        () => RolEntity,
        rol => rol.modulos, //optional
        { onDelete: 'NO ACTION', onUpdate: 'NO ACTION' },
    )
    @JoinTable({
        name: 'rol_modulo_permiso',
        joinColumn: {
            name: 'modulo_id',
            referencedColumnName: 'id',
        },
        inverseJoinColumn: {
            name: 'rol_id',
            referencedColumnName: 'id',
        },
    })
    roles: RolEntity[];

    @OneToMany(
        () => FuncionalidadEntity,
        funcionalidad => funcionalidad.modulo, //optional
        { onDelete: 'NO ACTION', onUpdate: 'NO ACTION' },
    )
    funcionalidades: FuncionalidadEntity[];
}