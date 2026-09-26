import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { IsEnum, IsNotEmpty, IsOptional, IsString } from "class-validator";

export enum DeviceType {
  WEB = 'WEB',
  DESKTOP = 'DESKTOP',
  MOBILE = 'MOBILE',
  POSTMAN = 'POSTMAN',
}

/** POST /security/authorize */
export class AuthorizeRequestDto {
  @ApiProperty({ example: 'sparra' })
  @IsNotEmpty({ message: "El nombre de usuario es obligatorio" })
  username: string;
  @ApiProperty({ format: 'password' })
  @IsNotEmpty({ message: "La contraseña es obligatoria" })
  password: string;
  @ApiProperty({ description: 'PKCE: BASE64URL(SHA256(code_verifier)), método S256.' })
  @IsNotEmpty({ message: "El código de desafío es obligatorio" })
  code_challenge: string;
  @ApiProperty({ enum: DeviceType })
  @IsNotEmpty({ message: "El tipo de dispositivo es obligatorio" })
  @IsEnum(DeviceType, { message: "typeDevice debe ser uno de: WEB, DESKTOP, MOBILE, POSTMAN" })
  typeDevice: DeviceType;
  @ApiProperty({ description: 'Id de correlación de este intento; debe repetirse como `cid` en /security/token.' })
  @IsNotEmpty({ message: "El CorrelationId es obligatorio" })
  CorrelationId: string;
}

/** POST /security/token */
export class TokenRequestDto {
  @ApiProperty({ description: 'Código de autorización devuelto por /security/authorize (un solo uso).' })
  @IsNotEmpty({ message: "El código es obligatorio" })
  code: string;

  @ApiProperty({ enum: DeviceType, description: 'Debe coincidir con el usado en /security/authorize.' })
  @IsNotEmpty({ message: "El tipo de dispositivo es obligatorio" })
  @IsEnum(DeviceType, { message: "typeDevice debe ser uno de: WEB, DESKTOP, MOBILE, POSTMAN" })
  typeDevice: DeviceType;

  @ApiProperty({ description: 'PKCE: el code_verifier original cuyo hash se envió como code_challenge.' })
  @IsNotEmpty({ message: "El código de verificación es obligatorio" })
  codeVerifier: string;
  @ApiProperty({ description: 'CorrelationId enviado en /security/authorize.' })
  @IsNotEmpty({ message: "El sessionId es obligatorio" })
  cid: string
}

/** POST /security/session/refresh */
export class RefreshSessionRequestDto {
  @ApiPropertyOptional({ example: 'WEB', description: 'Solo informativo (se usa en logs).' })
  @IsOptional()
  @IsString()
  typeDevice?: string;
}
