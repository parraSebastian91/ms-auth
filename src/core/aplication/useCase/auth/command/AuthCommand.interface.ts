import { RefreshSessionModel } from "src/core/domain/model/RefreshSession.model";

export interface AuthenticationCommand {
    username: string,
    password: string,
    typeDevice: string,
    code_challenge: string,
    CorrelationId: string,
    requestId?: string
}

export interface RequestPasswordResetCommand {
    correo: string;
    ip: string;
    userAgent: string;
    requestId?: string;
}

export interface ResetPasswordCommand {
    token: string,
    uuid: string,
    newPassword: string,
    confirmPassword: string
    requestId?: string
}

export interface authorizationCommand {
    code: string,
    codeVerifier: string,
    typeDevice: string,
    sessionId: string,
    CorrelationId: string,
    requestId?: string
}

export interface validateResetTokenCommand {
    token: string;
    uuid?: string;
    requestId?: string;
}

export interface refreshSessionCommand {
    tokens: Record<string, any>,
    typeDevice: string,
    requestId?: string
}

export interface revokeUserSessionCommand {
    session: RefreshSessionModel
}