

export interface AccessTokenPayload {
    userId: number;
    username: string;
    userUuid: string;
    sessionUuid: string;
    sessionId: string;
    roles: string[];
    permissions: string[];
    typeDevice: string;
}