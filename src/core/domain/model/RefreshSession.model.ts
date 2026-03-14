import { UsuarioModel } from "./usuario.model";

export class RefreshSessionModel {
  constructor(
    public readonly id: number | null,
    public readonly sessionUuid: string | null,
    public readonly sessionId: string,
    public readonly userId: number,
    public readonly userUuid: string,
    public readonly deviceType: string,
    public readonly refreshTokenHash: string,
    public readonly expiresAt: Date,
    public readonly deviceFingerprint?: string | null,
    public readonly ip?: string | null,
    public readonly userAgent?: string | null,
    public readonly lastUsedAt?: Date | null,
    public readonly revokedAt?: Date | null,
    public readonly rotationParentId?: number | null,
    public readonly createdAt?: Date | null,
    public readonly updatedAt?: Date | null,
  ) {}

  isActive(now: Date = new Date()): boolean {
    return !this.revokedAt && this.expiresAt > now;
  }

  revoke(at: Date = new Date()): RefreshSessionModel {
    return new RefreshSessionModel(
      this.id,
      this.sessionUuid,
      this.sessionId,
      this.userId,
      this.userUuid,
      this.deviceType,
      this.refreshTokenHash,
      this.expiresAt,
      this.deviceFingerprint,
      this.ip,
      this.userAgent,
      at,
      at,
      this.rotationParentId,
      this.createdAt,
      this.updatedAt,
    );
  }

  static create(params: {
    id?: number | null;
    sessionUuid?: string | null;
    sessionId: string;
    userId: number;
    userUuid: string;
    deviceType: string;
    refreshTokenHash: string;
    expiresAt: Date;
    deviceFingerprint?: string | null;
    ip?: string | null;
    userAgent?: string | null;
    lastUsedAt?: Date | null;
    revokedAt?: Date | null;
    rotationParentId?: number | null;
    createdAt?: Date | null;
    updatedAt?: Date | null;
  }): RefreshSessionModel {
    return new RefreshSessionModel(
      params.id ?? null,
      params.sessionUuid ?? null,
      params.sessionId,
      params.userId,
      params.userUuid,
      params.deviceType,
      params.refreshTokenHash,
      params.expiresAt,
      params.deviceFingerprint ?? null,
      params.ip ?? null,
      params.userAgent ?? null,
      params.lastUsedAt ?? null,
      params.revokedAt ?? null,
      params.rotationParentId ?? null,
      params.createdAt ?? null,
      params.updatedAt ?? null,
    );
  }
}