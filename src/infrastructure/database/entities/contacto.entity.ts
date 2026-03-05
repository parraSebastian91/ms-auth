import { Entity, PrimaryGeneratedColumn, Column, OneToOne, PrimaryColumn, ManyToOne, JoinColumn, ManyToMany, JoinTable } from "typeorm";
import { TipoContactoEntity } from "./tipoContacto.entity";
import { OrganizacionEntity } from "./organizacion.entity";
import { UsuarioEntity } from "./usuario.entity";

/**
 * Estructura para cada dimensión de la imagen
 */
export interface AvatarImageData {
    url: string;          // URL completa para acceder a la imagen en Minio
    key: string;          // Key/path en el bucket de Minio
    size: number;         // Tamaño del archivo en bytes
    width: number;        // Ancho de la imagen en píxeles
    height: number;       // Alto de la imagen en píxeles
}

/**
 * Estructura completa del avatar con 4 dimensiones
 */
export interface AvatarData {
    thumbnail: AvatarImageData;  // Thumbnail muy pequeño (ej: 64x64)
    sm: AvatarImageData;         // Imagen pequeña (ej: 150x150)
    md: AvatarImageData;         // Imagen mediana (ej: 400x400)
    lg: AvatarImageData;         // Imagen grande (ej: 800x800)
    mimetype: 'image/webp';      // Formato de las imágenes
    uploadedAt: string;          // Fecha de carga ISO 8601
    uploadedBy?: string;         // UUID del usuario que subió la imagen (opcional)
}

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

    @Column({ type: "jsonb", name: 'avatar_data', nullable: true }) 
    avatarData: AvatarData | null;

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

