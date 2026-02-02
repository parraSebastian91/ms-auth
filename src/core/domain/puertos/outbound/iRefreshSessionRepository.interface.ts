import { RefreshSession } from "../../model/RefreshSession.model";

export interface IRefreshSessionRepository {
  create(session: RefreshSession): Promise<RefreshSession>;
  findById(sessionUuid: string): Promise<RefreshSession | null>;
  findByUserAndDevice(userUuid: string, deviceType: string): Promise<RefreshSession | null>;
  revokeById(sessionUuid: string): Promise<void>;
  rotate(oldSession: RefreshSession, newSession: RefreshSession): Promise<RefreshSession>;
  revokeAllUserSessions(userId: string): Promise<number>;
  revokeUserSessions(sessionUuid: string, deviceType?: string): Promise<number>;
  deleteExpired(now?: Date): Promise<number>;
  getSessionsByUserId(userId: string): Promise<RefreshSession[]>;
}