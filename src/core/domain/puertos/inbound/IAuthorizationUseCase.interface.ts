import { AuthorizeCommand, TokenCommand } from 'src/core/aplication/useCase/auth/command/AuthCommand.interface';

export const AUTHORIZATION_USE_CASE = 'AUTHORIZATION_USE_CASE';

/** Flujo Authorization Code + PKCE. */
export interface IAuthorizationUseCase {
    /** Valida credenciales y emite un código de autorización ligado al code_challenge. */
    ExecuteAuthorize(command: AuthorizeCommand): Promise<{ code: string, url: string }[]>;
    /** Canjea el código (+ code_verifier) por access/refresh token. */
    ExecuteToken(command: TokenCommand): Promise<{ accessToken: string, refreshToken: string }>;
}
