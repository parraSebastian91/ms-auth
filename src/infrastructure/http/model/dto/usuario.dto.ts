import { IsEmpty, IsNotEmpty } from "class-validator";

export class UsuarioDTO {

    @IsNotEmpty({ message: 'El nombre de usuario es obligatorio' })
    userName: string;
    @IsNotEmpty({ message: 'La contraseña es obligatoria' })
    password: string;
    @IsNotEmpty({ message: 'El Id de contacto es obligatorio' })
    contactoId: string;
}