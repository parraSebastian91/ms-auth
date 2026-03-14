import { IsEnum, IsNotEmpty } from "class-validator";

export enum DeviceType {
  WEB = 'WEB',
  DESKTOP = 'DESKTOP',
  MOBILE = 'MOBILE',
  POSTMAN = 'POSTMAN',
}

export class LoginDto {
  @IsNotEmpty({ message: "El nombre de usuario es obligatorio" })
  username: string;
  @IsNotEmpty({ message: "La contraseña es obligatoria" })
  password: string;
  @IsNotEmpty({ message: "El código de desafío es obligatorio" })
  code_challenge: string;
  @IsNotEmpty({ message: "El tipo de dispositivo es obligatorio" })
  @IsEnum(DeviceType, { message: "typeDevice debe ser uno de: WEB, DESKTOP, MOBILE, POSTMAN" })
  typeDevice: DeviceType;

  sessionId: string;
}

export class CallBackDTO {
  @IsNotEmpty({ message: "El código es obligatorio" })
  code: string;
  @IsNotEmpty({ message: "El tipo de dispositivo es obligatorio" })
  typeDevice: DeviceType;
  @IsNotEmpty({ message: "El código de verificación es obligatorio" })
  codeVerifier: string; 
}


export class RefreshDto {
  @IsNotEmpty({ message: "El token es obligatorio" })
  refresh_token: string;
  @IsNotEmpty({ message: "El token es obligatorio" })
  userId: string;
  @IsNotEmpty({ message: "El tipo de dispositivo es obligatorio" })
  typeDevice: string;
}
