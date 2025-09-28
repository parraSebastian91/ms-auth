import { IsBase64, IsEmpty, isEmpty, IsNotEmpty, IsNumber, IsUrl } from "class-validator";


export class ContactoDTO {

    @IsEmpty()
    id: string;

    @IsNotEmpty({ message: "El nombre es obligatorio" })
    nombre: string;

    @IsNotEmpty({ message: "La dirección es obligatoria" })
    direccion: string;

    @IsNotEmpty({ message: "El celular es obligatorio" })
    celular: string;

    @IsNotEmpty({ message: "El correo es obligatorio" })
    correo: string;

    @IsUrl({}, { message: "La red social debe ser una URL válida" })
    rrss: string;

    @IsUrl({},{ message: "La URL debe ser una URL válida" })
    url: string;

    @IsBase64({},{ message: "La imagen debe ser una cadena Base64 válida" })
    imgBase64: string;

    @IsNotEmpty({ message: "El tipo de contacto es obligatorio" })
    @IsNumber({},{ message: "El tipo de contacto debe ser un número" })
    tipoContactoId: string;
}