import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class RequestPasswordResetDto {
  @ApiProperty({ example: 'ana@correo.cl' })
  @IsEmail()
  @IsNotEmpty()
  correo: string;
}

export class ValidateResetTokenDto {
  @ApiProperty({ description: 'Token del enlace de restablecimiento.' })
  @IsString()
  @IsNotEmpty()
  token: string;
  @ApiProperty({ description: 'Uuid del token de restablecimiento (parámetro `uuid` del enlace).' })
  @IsString()
  @IsNotEmpty()
  uuid: string;
}

export class ResetPasswordDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  token: string;

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  uuid: string;

  @ApiProperty({ minLength: 8, format: 'password' })
  @IsString()
  @MinLength(8)
  @IsNotEmpty()
  newPassword: string;

  @ApiProperty({ minLength: 8, format: 'password', description: 'Debe ser igual a newPassword.' })
  @IsString()
  @MinLength(8)
  @IsNotEmpty()
  confirmPassword: string;
}