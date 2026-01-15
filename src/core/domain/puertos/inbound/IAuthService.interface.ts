import { UsuarioModel } from "../../model/usuario.model";

export interface IAuthService {
    refreshToken(token: string, userId: string, typeDevice: string): Promise<{ access_token: string, refresh_token: string } | null>;
    validateToken(token: string): Promise<string | null>;
    authetication(username: string, password: string, typeDevice: string, code_challenge: string): Promise<{ code: string, url: string }[] | null | null>;
    exchangeCodeForToken(code: string, typeDevice: string): Promise<{ access_token: string, refresh_token: string } | null>;
}
    