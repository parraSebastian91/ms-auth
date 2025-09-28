import { Column, Entity, ManyToOne, PrimaryGeneratedColumn, JoinColumn } from "typeorm"
import { ModuloEntity } from "./modulo.entity";


@Entity({ name: 'funcionalidad', schema: 'core' })
export class FuncionalidadEntity {

    @PrimaryGeneratedColumn({ name: 'funcionalidad_id', type: 'bigint' })
    id: number;

    @Column({ type: "varchar", name: 'nombre', nullable: true })
    nombre: string;

    @Column({ type: "varchar", name: 'descripcion', nullable: true })
    descripcion: string;

    @Column({ type: "varchar", name: 'path', nullable: true, comment: 'ruta de frontend Angular' })
    path: string;

    @Column({ type: "bigint", name: 'modulo_id' })
    moduloId: number;

    @Column({ type: "boolean", name: 'activo', default: true })
    activo: boolean;

    @ManyToOne(
        () => ModuloEntity,
        modulo => modulo.funcionalidades,
        { onDelete: 'NO ACTION', onUpdate: 'NO ACTION' },
    )
    @JoinColumn({ name: 'modulo_id' })
    modulo: ModuloEntity;

}