import { UpdateContactoData, UserProfileModel } from '../../../core/domain/model/userProfile.model';
import { ValidationError } from '../../../core/domain/errors/validation.error';

/** Respuesta de GET/PUT /usuario/profile/:uuid (mismo contrato que tenía ms-core). */
export class UserProfileDTO {
    static builder(p: UserProfileModel) {
        return {
            usuario_uuid: p.usuario_uuid,
            username: p.username,
            ingreso: p.ingreso,
            activo: p.activo,
            nombres: p.nombres,
            apellido_paterno: p.apellido_paterno,
            apellido_materno: p.apellido_materno,
            direccion: p.direccion,
            celular: p.celular,
            correo: p.correo,
            fecha_nacimiento: p.fecha_nacimiento,
            redes_sociales: p.redes_sociales,
            tipo_documento: p.tipo_documento,
            numero_documento: p.numero_documento,
            tipo_contacto: p.tipo_contacto,
            roles: p.roles ?? [],
        };
    }
}

/**
 * Cuerpo de PUT (mismo formato que ms-core):
 * { nombre: { nombres, apellidoPaterno, apellidoMaterno }, datosContacto: { correo, telefono, ubicacion } }
 * Solo se actualizan los campos presentes.
 */
export function toUpdateContactoData(body: any): UpdateContactoData {
    if (!body || typeof body !== 'object') throw new ValidationError('Cuerpo inválido');
    const str = (v: any) => (v === undefined || v === null ? undefined : String(v));
    return {
        nombres: str(body.nombre?.nombres),
        apellido_paterno: str(body.nombre?.apellidoPaterno),
        apellido_materno: str(body.nombre?.apellidoMaterno),
        correo: str(body.datosContacto?.correo),
        celular: str(body.datosContacto?.telefono),
        direccion: str(body.datosContacto?.ubicacion),
    };
}
