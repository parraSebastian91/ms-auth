import { UsuarioModel } from "../../model/usuario.model";

export interface IAuthService {
    refreshToken(token: string, userId: string, typeDevice: string): Promise<{ access_token: string, refresh_token: string } | null>;
    validateToken(token: string): Promise<string | null>;
    login(username: string, password: string, typeDevice: string): Promise<{ access_token: string, refresh_token: string } | null>;
}
