import { RefreshSession } from "src/core/domain/model/RefreshSession.model";
import { LoginDto } from "src/infrastructure/http-server/model/dto/login.dto";


export interface IAuthAplication {
    refreshToken(token: string, userId: string, typeDevice: string): Promise<{ accessToken: string, refreshToken: string } | null>;
    validateToken(token: string): Promise<string | null>;
    authetication(loginDto: LoginDto): Promise<{ code: string, url: string }[] | null>;
    exchangeCodeForToken(code: string, codeVerifier: string, typeDevice: string, sessionId: string): Promise<{ accessToken: string, refreshToken: string } | null>;
    revokeUserSessions(session: RefreshSession): Promise<number>;
    requestPasswordReset(
        email: string,
        ipAddress?: string,
        userAgent?: string
    ): Promise<{ message: string }>

    validateResetToken(
        token: string,
        uuid?: string
    ): Promise<{ valid: boolean }>

    resetPassword(
        token: string,
        uuid: string,
        newPassword: string,
        confirmPassword: string
    ): Promise<{ message: string }>
}