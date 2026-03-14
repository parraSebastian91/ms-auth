import { RefreshSessionModel } from "../../model/RefreshSession.model";

export interface IRefreshSessionRepository {
  create(session: RefreshSessionModel): Promise<RefreshSessionModel>;
  findById(sessionUuid: string): Promise<RefreshSessionModel | null>;
  findByUserAndDevice(userUuid: string, deviceType: string): Promise<RefreshSessionModel | null>;
  revokeById(sessionUuid: string): Promise<void>;
  rotate(oldSession: RefreshSessionModel, newSession: RefreshSessionModel): Promise<RefreshSessionModel>;
  revokeAllUserSessions(userId: string): Promise<number>;
  revokeUserSessions(sessionUuid: string, deviceType?: string): Promise<number>;
  deleteExpired(now?: Date): Promise<number>;
  getSessionsByUserId(userId: string): Promise<RefreshSessionModel[]>;
}