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

    @Column({ type: 'varchar', length: 80, name: 'nombres' })
    nombres: string;

    @Column({ type: 'varchar', length: 80, name: 'apellido_paterno' })
    apellidoPaterno: string;

    @Column({ type: 'varchar', length: 80, name: 'apellido_materno' })
    apellidoMaterno: string;

    @Column({ type: 'varchar', name: 'direccion' })
    direccion: string;

    @Column({ type: 'varchar', length: 20, name: 'celular' })
    celular: string;

    @Column({ type: 'varchar', length: 255, name: 'correo', unique: true })
    correo: string;

    @Column({ type: 'varchar', length: 20, name: 'tipo_documento' })
    tipoDocumento: string;

    @Column({ type: 'varchar', length: 30, name: 'numero_documento' })
    numeroDocumento: string;

    @Column({ type: 'char', length: 2, name: 'pais_emision', default: 'CL' })
    paisEmision: string;

    @Column({ type: 'date', name: 'fecha_nacimiento' })
    fechaNacimiento: Date;

    @Column({ type: 'jsonb', name: 'redes_sociales' })
    rrss: string;

    @Column({ type: 'jsonb', name: 'logo_metadata' })
    logoMetadata: string;

    @Column({ type: 'date', name: 'created_at' })
    createdAt: Date;

    @Column({ type: 'date', name: 'updated_at', nullable: true })
    updatedAt: Date;

    @Column({ type: 'date', name: 'eliminado_at', nullable: true })
    eliminadoAt: Date;

    @Column({ type: 'boolean', name: 'activo', default: true })
    activo: boolean;

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

