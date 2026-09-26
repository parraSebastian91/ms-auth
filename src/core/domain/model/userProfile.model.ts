export class UserProfileModel {
    usuario_uuid: string;
    username: string;
    ingreso: Date;
    activo: boolean;
    nombres: string;
    apellido_paterno: string;
    apellido_materno: string;
    direccion: string;
    celular: string;
    correo: string;
    fecha_nacimiento: Date;
    redes_sociales: string;
    tipo_documento: string;
    numero_documento: string;
    tipo_contacto: string;
    roles: string[];

    static fromData(row: any): UserProfileModel {
        const p = new UserProfileModel();
        p.usuario_uuid = row.usuario_uuid;
        p.username = row.username;
        p.ingreso = row.ingreso;
        p.activo = row.activo;
        p.nombres = row.nombres;
        p.apellido_paterno = row.apellido_paterno;
        p.apellido_materno = row.apellido_materno;
        p.direccion = row.direccion;
        p.celular = row.celular;
        p.correo = row.correo;
        p.fecha_nacimiento = row.fecha_nacimiento;
        p.redes_sociales = row.redes_sociales;
        p.tipo_documento = row.tipo_documento;
        p.numero_documento = row.numero_documento;
        p.tipo_contacto = row.tipo_contacto;
        p.roles = Array.isArray(row.roles) ? row.roles : [];
        return p;
    }
}

/** Campos de contacto que el propio usuario puede editar. `undefined` = no tocar. */
export interface UpdateContactoData {
    nombres?: string;
    apellido_paterno?: string;
    apellido_materno?: string;
    direccion?: string;
    celular?: string;
    correo?: string;
}
