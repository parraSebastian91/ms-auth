import { Entity, JoinColumn, ManyToOne, PrimaryColumn } from "typeorm"
import { UsuarioEntity } from "./usuario.entity";
import { RolEntity } from "./rol.entity";

@Entity({ name: 'usuario_rol' })
export class UsuarioRolEntity {
    @PrimaryColumn({ name: 'usuario_id' })
    usuarioId: number;
    @PrimaryColumn({ name: 'rol_id' })
    rol_id: number;

    @ManyToOne(() => UsuarioEntity, usuario => usuario.rol)
    @JoinColumn([{ name: 'usuario_id', referencedColumnName: 'id' }])
    usuario: UsuarioEntity;

    @ManyToOne(() => RolEntity, rol => rol.usuarios)
    @JoinColumn([{ name: 'rol_id', referencedColumnName: 'id' }])
    rol: RolEntity;

}
