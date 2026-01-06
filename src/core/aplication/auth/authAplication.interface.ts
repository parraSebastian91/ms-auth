import { LoginDto } from "src/infrastructure/http-server/model/dto/login.dto";


export interface IAuthAplication {
    refreshToken(token: string, userId: string, typeDevice: string): Promise<{ access_token: string, refresh_token: string } | null>;
    validateToken(token: string): Promise<string | null>;
    authetication(loginDto: LoginDto): Promise<string[] | null>;
    exchangeCodeForToken(code: string, typeDevice: string): Promise<{ access_token: string, refresh_token: string } | null>;
}