import { RefreshSession } from "src/core/domain/model/RefreshSession.model";
import { authorizationCommand, LoginCommand, refreshSessionCommand, RequestPasswordResetCommand, ResetPasswordCommand, validateResetTokenCommand } from "./command/AuthCommand.interface";


export interface IAuthAplication {
    refreshSession(commnand: refreshSessionCommand): Promise<{ accessToken: string, refreshToken: string } | null>;
    validateToken(token: string): Promise<string | null>;
    authetication(command: LoginCommand): Promise<{ code: string, url: string }[] | null>;
    exchangeCodeForToken(command: authorizationCommand): Promise<{ accessToken: string, refreshToken: string } | null>;
    revokeUserSessions(session: RefreshSession): Promise<number>;
    requestPasswordReset(command: RequestPasswordResetCommand): Promise<{ message: string }>
    validateResetToken(command: validateResetTokenCommand): Promise<{ valid: boolean }>
    resetPassword(command: ResetPasswordCommand): Promise<{ message: string }>
}