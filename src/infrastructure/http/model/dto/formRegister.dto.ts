import { PAISES, rolEnum, tipoDocumentoEnum } from "src/core/domain/model/constantes.model";
import { formRegistroData } from "src/core/domain/model/dataRegistro.model";
import { Celular } from "src/core/domain/model/valueObject/celular.valueObject";
import { Correo } from "src/core/domain/model/valueObject/correo.ValueObject";
import { NumeroDocumento } from "src/core/domain/model/valueObject/numeroDocumento.valueObject";
import { Password } from "src/core/domain/model/valueObject/password.valueObject";
import { TipoDocumento } from "src/core/domain/model/valueObject/TipoDocumento.valueObject";
import { ApiProperty } from "@nestjs/swagger";
import { IsDateString, IsEmail, IsEnum, IsIn, IsNotEmpty, IsString, Length, MinLength } from "class-validator";

export class FormRegisterDto {
    @ApiProperty({ enum: rolEnum, description: 'Rol inicial solicitado (el rol efectivo se asigna al verificar el correo).' })
    @IsEnum(rolEnum, { message: 'El rol debe ser CEDENTE o EJECUTIVO' })
    rol: rolEnum;

    @ApiProperty({ example: 'ana@correo.cl' })
    @IsEmail({}, { message: 'El correo electrónico no tiene un formato válido' })
    email: string;

    @ApiProperty({ minLength: 3, example: 'ana.perez' })
    @IsString({ message: 'El username debe ser un texto' })
    @MinLength(3, { message: 'El username debe tener al menos 3 caracteres' })
    username: string;

    @ApiProperty({ minLength: 2 })
    @IsString({ message: 'El nombre debe ser un texto' })
    @MinLength(2, { message: 'El nombre debe tener al menos 2 caracteres' })
    nombres: string;

    @ApiProperty({ minLength: 2 })
    @IsString({ message: 'El apellido paterno debe ser un texto' })
    @MinLength(2, { message: 'El apellido paterno debe tener al menos 2 caracteres' })
    apellidoPaterno: string;

    @ApiProperty({ minLength: 2 })
    @IsString({ message: 'El apellido materno debe ser un texto' })
    @MinLength(2, { message: 'El apellido materno debe tener al menos 2 caracteres' })
    apellidoMaterno: string;

    @ApiProperty({ minLength: 7, maxLength: 20, example: '+56912345678' })
    @IsString({ message: 'El teléfono debe ser un texto' })
    @Length(7, 20, { message: 'El teléfono debe tener entre 7 y 20 caracteres' })
    telefono: string;

    @ApiProperty({ enum: tipoDocumentoEnum })
    @IsEnum(tipoDocumentoEnum, { message: 'El tipo de documento debe ser DNI, RUT o PASAPORTE' })
    tipoDocumento: tipoDocumentoEnum;

    @ApiProperty({ example: '12345678-9' })
    @IsString({ message: 'El número de documento debe ser un texto' })
    @IsNotEmpty({ message: 'El número de documento es obligatorio' })
    numeroDocumento: string;

    @ApiProperty({ minLength: 2, maxLength: 2, example: 'CL', description: 'Código ISO de 2 letras.' })
    @IsString({ message: 'El país debe ser un texto' })
    @Length(2, 2, { message: 'El país debe tener exactamente 2 caracteres' })
    @IsIn(PAISES.map((pais) => pais.code), { message: 'El país debe ser un código válido dentro de PAISES' })
    pais: string;

    @ApiProperty({ format: 'date', example: '1990-05-31' })
    @IsDateString({}, { message: 'La fecha de nacimiento debe tener formato ISO válido (YYYY-MM-DD)' })
    fechaNacimiento: string;

    @ApiProperty({ minLength: 5 })
    @IsString({ message: 'La dirección debe ser un texto' })
    @MinLength(5, { message: 'La dirección debe tener al menos 5 caracteres' })
    direccion: string;

    @ApiProperty({ minLength: 8, format: 'password' })
    @IsString({ message: 'La contraseña debe ser un texto' })
    @MinLength(8, { message: 'La contraseña debe tener al menos 8 caracteres' })
    password: string;

    static toDomain(data: FormRegisterDto): formRegistroData {
        return {
            rol: data.rol,
            email: new Correo(data.email),
            username: data.username,
            nombres: data.nombres,
            apellidoPaterno: data.apellidoPaterno,
            apellidoMaterno: data.apellidoMaterno,
            telefono: new Celular(data.telefono),
            tipoDocumento: new TipoDocumento(data.tipoDocumento),
            numeroDocumento: NumeroDocumento.createForTipo(data.tipoDocumento, data.numeroDocumento),
            pais: data.pais.toUpperCase(),
            fechaNacimiento: new Date(data.fechaNacimiento),
            direccion: data.direccion,
            password: new Password(data.password),
        };
    }
} 