import { Entity, JoinColumn, ManyToOne, PrimaryColumn } from "typeorm";
import { RolEntity } from "./rol.entity";
import { PermisoEntity } from "./permisos.entity";
import { ModuloEntity } from "./modulo.entity";

@Entity({ name: 'rol_modulo_permiso' })
export class RolModuloPermisoEntity {

    @PrimaryColumn({ name: 'rol_id' })
    rolId: number;

    @PrimaryColumn({ name: 'modulo_id' })
    moduloId: number;

    @PrimaryColumn({ name: 'permiso_id' })
    permisoId: number;

    @ManyToOne(() => RolEntity, rol => rol.permisos)
    @JoinColumn([{ name: 'rol_id', referencedColumnName: 'id' }])
    rol: RolEntity;

    @ManyToOne(() => ModuloEntity)
    @JoinColumn([{ name: 'modulo_id', referencedColumnName: 'id' }])
    modulo: ModuloEntity;

    @ManyToOne(() => PermisoEntity, permiso => permiso.rol)
    @JoinColumn([{ name: 'permiso_id', referencedColumnName: 'id' }])
    permiso: PermisoEntity;
}