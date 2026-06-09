import { rolEnum } from "./constantes.model";
import { Celular } from "./valueObject/celular.valueObject";
import { Correo } from "./valueObject/correo.ValueObject";
import { NumeroDocumento } from "./valueObject/numeroDocumento.valueObject";
import { Password } from "./valueObject/password.valueObject";
import { TipoDocumento } from "./valueObject/TipoDocumento.valueObject";

export class formRegistroData {
    rol: rolEnum;
    email: Correo;
    username: string;
    nombres: string;
    apellidoPaterno: string;
    apellidoMaterno: string;
    telefono: Celular;
    tipoDocumento: TipoDocumento;
    numeroDocumento: NumeroDocumento;
    pais: string;
    fechaNacimiento: Date;
    direccion: string;
    password: Password;
} 