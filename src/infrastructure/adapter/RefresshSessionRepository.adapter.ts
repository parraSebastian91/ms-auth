import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource, Repository, MoreThan, IsNull } from 'typeorm';
import { Injectable } from '@nestjs/common';
import { IRefreshSessionRepository } from 'src/core/domain/puertos/outbound/iRefreshSessionRepository.interface';
import { RefreshSessionEntity } from '../database/entities/RefreshSession.entity';
import { RefreshSessionModel } from 'src/core/domain/model/RefreshSession.model';
import { RefreshSessionMapper } from '../mapper/refreshSession.mapper';

@Injectable()
export class RefreshSessionRepositoryAdapter implements IRefreshSessionRepository {
  private readonly repo: Repository<RefreshSessionEntity>;

  constructor(@InjectDataSource() private readonly dataSource: DataSource) {
    this.repo = this.dataSource.getRepository(RefreshSessionEntity);
  }

  async create(session: RefreshSessionModel): Promise<RefreshSessionModel> {
    const entity = this.repo.create(RefreshSessionMapper.toEntity(session));
    const saved = await this.repo.save(entity);

    const reloaded = await this.repo.findOne({
      where: { id: saved.id },
      relations: ['user'],
    });

    if (!reloaded) {
      throw new Error('Refresh session not found after save');
    }

    return RefreshSessionMapper.toDomain(reloaded);
  }

  async findById(sessionUuid: string): Promise<RefreshSessionModel | null> {
    const found = await this.repo.findOne({
      where: { sessionUuid },
      relations: ['user'],
    });

    return found ? RefreshSessionMapper.toDomain(found) : null;
  }

  async findByUserAndDevice(userUuid: string, deviceType: string): Promise<RefreshSessionModel | null> {
    const found = await this.repo.findOne({
      where: {
        user: { usuarioUuid: userUuid },
        deviceType,
        revokedAt: IsNull(),
        expiresAt: MoreThan(new Date()),
      },
      relations: ['user'],
    });

    return found ? RefreshSessionMapper.toDomain(found) : null;
  }

  async revokeById(sessionUuid: string): Promise<void> {
    await this.repo.update({ sessionUuid }, { revokedAt: new Date() });
  }

  async rotate(oldSession: RefreshSessionModel, newSession: RefreshSessionModel): Promise<RefreshSessionModel> {
    return this.dataSource.transaction(async manager => {
      await manager.update(
        RefreshSessionEntity,
        { sessionUuid: oldSession.sessionUuid! },
        { revokedAt: new Date(), lastUsedAt: new Date() },
      );

      const created = manager.create(
        RefreshSessionEntity,
        RefreshSessionMapper.toEntity(newSession),
      );

      const saved = await manager.save(created);

      const reloaded = await manager.findOne(RefreshSessionEntity, {
        where: { id: saved.id },
        relations: ['user'],
      });

      if (!reloaded) {
        throw new Error('Rotated session not found after save');
      }

      return RefreshSessionMapper.toDomain(reloaded);
    });
  }

  async revokeAllUserSessions(userId: string): Promise<number> {
    const res = await this.repo.createQueryBuilder()
      .update()
      .set({ revokedAt: () => 'now()' })
      .where('user_id = :userId', { userId })
      .andWhere('revoked_at IS NULL')
      .execute();

    return res.affected ?? 0;
  }

  async revokeUserSessions(sessionUuid: string, deviceType?: string): Promise<number> {
    const qb = this.repo.createQueryBuilder()
      .update()
      .set({ revokedAt: () => 'now()' })
      .where('session_uuid = :sessionUuid', { sessionUuid })
      .andWhere('revoked_at IS NULL');

    if (deviceType) {
      qb.andWhere('device_type = :deviceType', { deviceType });
    }

    const res = await qb.execute();
    return res.affected ?? 0;
  }

  async deleteExpired(now: Date = new Date()): Promise<number> {
    const res = await this.repo.createQueryBuilder()
      .delete()
      .where('expires_at < :now', { now })
      .execute();

    return res.affected ?? 0;
  }

  async getSessionsByUserId(userId: string): Promise<RefreshSessionModel[]> {
    const found = await this.repo.find({
      where: {
        user: { id: Number(userId) },
        revokedAt: IsNull(),
      },
      relations: ['user'],
    });

    return RefreshSessionMapper.toDomainList(found);
  }
}