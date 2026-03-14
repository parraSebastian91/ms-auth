import { RefreshSessionModel } from 'src/core/domain/model/RefreshSession.model';
import { RefreshSessionEntity } from '../database/entities/RefreshSession.entity';

export class RefreshSessionMapper {
  static toDomain(entity: RefreshSessionEntity): RefreshSessionModel {
    return RefreshSessionModel.create({
      id: entity.id,
      sessionUuid: entity.sessionUuid,
      sessionId: entity.sessionId,
      userId: entity.user.id,
      userUuid: entity.user.usuarioUuid,
      deviceType: entity.deviceType,
      refreshTokenHash: entity.refreshTokenHash,
      expiresAt: entity.expiresAt,
      deviceFingerprint: entity.deviceFingerprint,
      ip: entity.ip,
      userAgent: entity.userAgent,
      lastUsedAt: entity.lastUsedAt,
      revokedAt: entity.revokedAt,
      rotationParentId: entity.rotationParentId,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
    });
  }

  static toEntity(model: RefreshSessionModel): Partial<RefreshSessionEntity> {
    return {
      id: model.id ?? undefined,
      sessionUuid: model.sessionUuid ?? undefined,
      sessionId: model.sessionId,
      deviceType: model.deviceType,
      deviceFingerprint: model.deviceFingerprint ?? undefined,
      refreshTokenHash: model.refreshTokenHash,
      ip: model.ip ?? undefined,
      userAgent: model.userAgent ?? undefined,
      expiresAt: model.expiresAt,
      lastUsedAt: model.lastUsedAt ?? undefined,
      revokedAt: model.revokedAt ?? undefined,
      rotationParentId: model.rotationParentId ?? undefined,
      createdAt: model.createdAt ?? undefined,
      updatedAt: model.updatedAt ?? undefined,
      user: {
        id: model.userId,
      } as any,
    };
  }

  static toDomainList(entities: RefreshSessionEntity[]): RefreshSessionModel[] {
    return entities.map(entity => this.toDomain(entity));
  }
}