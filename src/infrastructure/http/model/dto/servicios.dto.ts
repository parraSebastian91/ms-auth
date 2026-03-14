import { IsString, IsOptional, ValidateNested } from 'class-validator';
import { Type, Transform } from 'class-transformer';


export class ServicioDto {
    @IsString() metodo: string;
    @IsString() ruta: string;
    @IsOptional() body?: any;
}

export class ServiciosDTO {
    // transforma el objeto { servicio1: {...}, servicio2: {...} } a un array para validar cada valor
    @Transform(({ value }) => Object.values(value || {}))
    @ValidateNested({ each: true })
    @Type(() => ServicioDto)
    servicios: ServicioDto[];
}