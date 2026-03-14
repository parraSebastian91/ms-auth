export interface ICacheRepository {
    setAuthCode(code: string, authCode: AuthCodeStored): Promise<void>;
    getAuthCode(code: string): Promise<AuthCodeStored | null>;
    deleteAuthCode(code: string): Promise<void>;
    setAccessToken(sessionId: string, token: string): Promise<void>;
    getAccessToken(sessionId: string): Promise<string | null>;
    deleteAccessToken(sessionId: string): Promise<void>;
}