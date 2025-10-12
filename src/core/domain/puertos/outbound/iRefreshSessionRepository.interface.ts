import { RefreshSession } from "../../model/RefreshSession.model";

export interface IRefreshSessionRepository {
  create(session: RefreshSession): Promise<RefreshSession>;
  findById(id: number): Promise<RefreshSession | null>;
  findByUserAndDevice(userId: number, deviceType: string): Promise<RefreshSession | null>;
  revokeById(id: number): Promise<void>;
  rotate(oldSession: RefreshSession, newSession: RefreshSession): Promise<RefreshSession>;
  revokeAllUserSessions(userId: number, deviceType?: string): Promise<number>;
  deleteExpired(now?: Date): Promise<number>;
}