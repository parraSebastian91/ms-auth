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
  /** ¿Existe una sesión creada al rotar esta (rotation_parent_id = id)? Distingue "rotado" de "cerrado por logout". */
  hasRotationChild(sessionRowId: number): Promise<boolean>;
  /** Revoca TODAS las sesiones activas de una cadena de rotación (mismo session_id y usuario). Devuelve cuántas. */
  revokeFamily(sessionId: string, userId: number): Promise<number>;
}