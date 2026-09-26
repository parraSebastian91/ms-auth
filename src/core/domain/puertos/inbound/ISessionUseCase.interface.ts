import { refreshSessionCommand } from 'src/core/aplication/useCase/auth/command/AuthCommand.interface';
import { validateQuery } from 'src/core/aplication/useCase/auth/query/validate.query';

export const SESSION_USE_CASE = 'SESSION_USE_CASE';

/** Ciclo de vida de la sesión: validar, refrescar (rotar) y cerrar. */
export interface ISessionUseCase {
    ExecuteValidateSession(query: validateQuery): Promise<boolean>;
    ExecuteRefreshSession(command: refreshSessionCommand): Promise<{ accessToken: string, refreshToken: string }>;
    ExecuteLogout(sessionId: string): Promise<void>;
}
