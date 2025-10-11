import { UsuarioEntity } from "src/infrastructure/database/entities/usuario.entity";

export class RefreshSession {
  id?: number;
  user: UsuarioEntity;
  deviceType: string;
  deviceFingerprint?: string;
  refreshTokenHash: string;
  ip?: string;
  userAgent?: string;
  expiresAt: Date;
  lastUsedAt?: Date;
  revokedAt?: Date;
  rotationParentId?: number;
  createdAt?: Date;
  updatedAt?: Date;
}