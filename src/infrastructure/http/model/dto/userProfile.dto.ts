import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { UpdateContactoData, UserProfileModel } from '../../../../core/domain/model/userProfile.model';
import { ValidationError } from '../../../../core/domain/errors/validation.error';

/** Respuesta de GET/PUT /usuario/profile/:uuid (mismo contrato que tenía ms-core). */
export class UserProfileDTO {
    @ApiProperty({ format: 'uuid' }) usuario_uuid: string;
    @ApiProperty() username: string;
    @ApiProperty({ format: 'date-time', description: 'Fecha de alta.' }) ingreso: Date;
    @ApiProperty() activo: boolean;
    @ApiProperty() nombres: string;
    @ApiProperty() apellido_paterno: string;
    @ApiProperty() apellido_materno: string;
    @ApiProperty({ nullable: true }) direccion: string;
    @ApiProperty({ nullable: true }) celular: string;
    @ApiProperty() correo: string;
    @ApiProperty({ nullable: true, format: 'date' }) fecha_nacimiento: Date;
    @ApiProperty({ nullable: true, type: 'object', additionalProperties: true }) redes_sociales: any;
    @ApiProperty({ nullable: true, example: 'RUT' }) tipo_documento: string;
    @ApiProperty({ nullable: true }) numero_documento: string;
    @ApiProperty({ nullable: true }) tipo_contacto: string;
    @ApiProperty({ type: [String], example: ['CLIENTE_CEDENTE'] }) roles: string[];

    static builder(p: UserProfileModel): UserProfileDTO {
        const dto = new UserProfileDTO();
        dto.usuario_uuid = p.usuario_uuid;
        dto.username = p.username;
        dto.ingreso = p.ingreso;
        dto.activo = p.activo;
        dto.nombres = p.nombres;
        dto.apellido_paterno = p.apellido_paterno;
        dto.apellido_materno = p.apellido_materno;
        dto.direccion = p.direccion;
        dto.celular = p.celular;
        dto.correo = p.correo;
        dto.fecha_nacimiento = p.fecha_nacimiento;
        dto.redes_sociales = p.redes_sociales;
        dto.tipo_documento = p.tipo_documento;
        dto.numero_documento = p.numero_documento;
        dto.tipo_contacto = p.tipo_contacto;
        dto.roles = p.roles ?? [];
        return dto;
    }
}

class NombreDto {
    @ApiPropertyOptional() nombres?: string;
    @ApiPropertyOptional() apellidoPaterno?: string;
    @ApiPropertyOptional() apellidoMaterno?: string;
}

class DatosContactoDto {
    @ApiPropertyOptional({ example: 'ana@correo.cl' }) correo?: string;
    @ApiPropertyOptional() telefono?: string;
    @ApiPropertyOptional() ubicacion?: string;
}

/** Cuerpo de PUT /usuario/profile/:uuid. Actualización parcial: solo se modifican los campos enviados. */
export class UpdateUserProfileRequestDto {
    @ApiPropertyOptional({ type: NombreDto }) nombre?: NombreDto;
    @ApiPropertyOptional({ type: DatosContactoDto }) datosContacto?: DatosContactoDto;
}

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
