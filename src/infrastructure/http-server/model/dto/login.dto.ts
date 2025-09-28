import { IsNotEmpty } from "class-validator";

export class LoginDto {
    @IsNotEmpty({ message: "El nombre de usuario es obligatorio" })
    username: string;
    @IsNotEmpty({ message: "La contraseña es obligatoria" })
    password: string;
    @IsNotEmpty({ message: "El tipo de dispositivo es obligatorio" })
    typeDevice: string;
}
  

export class RefreshDto {
    @IsNotEmpty({ message: "El token es obligatorio" })
    refresh_token: string;
    @IsNotEmpty({ message: "El token es obligatorio" })
    userId: string;
    @IsNotEmpty({ message: "El tipo de dispositivo es obligatorio" })
    typeDevice: string;
}
