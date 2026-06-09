export interface ICacheRepository {
    setAuthCode(code: string, authCode: AuthCodeStored): Promise<void>;
    getAuthCode(code: string): Promise<AuthCodeStored | null>;
    deleteAuthCode(code: string): Promise<void>;
    setAccessToken(sessionId: string, token: string): Promise<void>;
    getAccessToken(sessionId: string): Promise<string | null>;
    deleteAccessToken(sessionId: string): Promise<void>;
    /** Guarda el código de verificación de email (TTL 10 min) */
    setEmailVerificationCode(userUuid: string, codeHash: string): Promise<void>;
    /** Recupera el hash del código de verificación */
    getEmailVerificationCode(userUuid: string): Promise<string | null>;
    /** Elimina el código tras verificarlo */
    deleteEmailVerificationCode(userUuid: string): Promise<void>;
}