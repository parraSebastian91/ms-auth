
import { AuthenticationCommand, authorizationCommand, refreshSessionCommand, RequestPasswordResetCommand, ResetPasswordCommand, validateResetTokenCommand } from "src/core/aplication/useCase/auth/command/AuthCommand.interface";
import { validateQuery } from "src/core/aplication/useCase/auth/query/validate.query";

export interface IAuthUseCase {
    ExcuteAuthentication(command: AuthenticationCommand): Promise<{ code: string, url: string }[] | null>;
    ExecuteAuthorization(command: authorizationCommand): Promise<{ accessToken: string, refreshToken: string } | null>;
    ExecuteValidateSession(command: validateQuery): Promise<boolean>;
    ExecuteRefreshSession(command: refreshSessionCommand): Promise<{ accessToken: string, refreshToken: string } | null>;
    ExecuteLogout(sessionId: string): Promise<void>;
    ExecuteRequestPasswordRequest(command: RequestPasswordResetCommand): Promise<{ message: string }>
    ExecuteRequestPasswordValidation(command: validateResetTokenCommand): Promise<{ valid: boolean; email?: string }>
    ExecuteResetPassword(command: ResetPasswordCommand): Promise<{ message: string }>
}