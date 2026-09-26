import { RequestPasswordResetCommand, ResetPasswordCommand, validateResetTokenCommand } from 'src/core/aplication/useCase/auth/command/AuthCommand.interface';

export const PASSWORD_RESET_USE_CASE = 'PASSWORD_RESET_USE_CASE';

export interface IPasswordResetUseCase {
    ExecuteRequestReset(command: RequestPasswordResetCommand): Promise<{ message: string }>;
    ExecuteValidateResetToken(command: validateResetTokenCommand): Promise<{ valid: boolean; email?: string }>;
    ExecuteResetPassword(command: ResetPasswordCommand): Promise<{ message: string }>;
}
