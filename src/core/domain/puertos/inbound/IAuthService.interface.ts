import { RefreshSession } from "../../model/RefreshSession.model";
import { UsuarioModel } from "../../model/usuario.model";

export interface IAuthService {
    refreshToken(token: string, userId: string, typeDevice: string): Promise<{ accessToken: string, refreshToken: string } | null>;
    validateToken(token: string): Promise<string | null>;
    authetication(username: string, password: string, typeDevice: string, code_challenge: string, sessionId: string): Promise<{ code: string, url: string }[] | null | null>;
    exchangeCodeForToken(code: string, codeVerifier: string, typeDevice: string, sessionId: string): Promise<{ accessToken: string, refreshToken: string } | null>;
    revokeUserSessions(session: RefreshSession): Promise<number>;

    requestPasswordReset(
        email: string,
        ipAddress?: string,
        userAgent?: string
    ): Promise<{ message: string }>;

    validateResetToken(token: string): Promise<{ valid: boolean; email?: string }>

    resetPassword(
        token: string,
        newPassword: string,
        confirmPassword: string
    ): Promise<{ message: string }>;
}
    