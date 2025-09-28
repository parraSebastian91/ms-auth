import { Column, Entity, JoinTable, ManyToMany, PrimaryGeneratedColumn } from "typeorm";
import { RolEntity } from "./rol.entity";
import { ModuloEntity } from "./modulo.entity";

@Entity({ name: 'permiso', schema: 'core' })
export class PermisoEntity {

    @PrimaryGeneratedColumn({ name: 'permiso_id', type: 'bigint' })
    id: number;

    @Column({ type: "varchar", name: 'per_nombre' })
    nombre: string;

    @Column({ type: "varchar", name: 'per_desc' })
    descripcion: string;

    @Column({ type: "varchar", name: 'per_cod' })
    codigo: string;

    @Column({ type: "boolean", name: 'per_activo', default: true })
    activo: boolean;

    @ManyToMany(
        () => RolEntity,
        RolEntity => RolEntity.permisos,
        { onDelete: 'NO ACTION', onUpdate: 'NO ACTION', },
    )
    @JoinTable({
                name: 'rol_modulo_permiso',
                joinColumn: {
                    name: 'permiso_id',
                    referencedColumnName: 'id',
                },
                inverseJoinColumn: {
                    name: 'rol_id',
                    referencedColumnName: 'id',
                },
            })
    rol: RolEntity[];

    @ManyToMany(
        () => ModuloEntity,
        moduloEntity => moduloEntity.permisos,
        { onDelete: 'NO ACTION', onUpdate: 'NO ACTION', },
    )
     @JoinTable({
                name: 'rol_modulo_permiso',
                joinColumn: {
                    name: 'permiso_id',
                    referencedColumnName: 'id',
                },
                inverseJoinColumn: {
                    name: 'modulo_id',
                    referencedColumnName: 'id',
                },
            })
    modulos: ModuloEntity[];

}
