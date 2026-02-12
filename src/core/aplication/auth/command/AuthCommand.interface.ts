import { RefreshSession } from "src/core/domain/model/RefreshSession.model";

export interface LoginCommand {
    username: string,
    password: string,
    typeDevice: string,
    code_challenge: string,
    sessionId: string
}

export interface RequestPasswordResetCommand {
    correo: string;
    ip: string;
    userAgent: string;
}

export interface ResetPasswordCommand {
    token: string,
    uuid: string,
    newPassword: string,
    confirmPassword: string
}

export interface authorizationCommand {
    code: string,
    codeVerifier: string,
    typeDevice: string,
    sessionId: string
}

export interface validateResetTokenCommand {
    token: string;
    uuid?: string;
}

export interface refreshSessionCommand {
    tokens: Record<string, any>, 
    typeDevice: string
}

export interface revokeUserSessionCommand {
    session: RefreshSession
}