import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource, Repository, Raw, MoreThan, IsNull } from 'typeorm';
import { Injectable } from '@nestjs/common';
import { IRefreshSessionRepository } from 'src/core/domain/puertos/outbound/iRefreshSessionRepository.interface';
import { RefreshSessionEntity } from '../database/entities/RefreshSession.entity';
import { RefreshSession } from 'src/core/domain/model/RefreshSession.model';

@Injectable()
export class RefreshSessionRepositoryAdapter implements IRefreshSessionRepository {
  private repo: Repository<RefreshSessionEntity>;

  constructor(@InjectDataSource() private dataSource: DataSource) {
    this.repo = this.dataSource.getRepository(RefreshSessionEntity);
  }

  async findByUserAndDevice(userUuid: string, deviceType: string): Promise<RefreshSession | null> {
   const found = await this.repo.findOne({
      where: {
        user: { usuarioUuid: userUuid },
        deviceType,
        revokedAt: IsNull(),
        expiresAt: MoreThan(new Date()),
      },
      relations: ['user'],
    });

    return found ? this.map(found) : null;
  }

  private map(e: RefreshSessionEntity): RefreshSession {
    return {
      ...e
    };
  }

  async create(session: RefreshSession): Promise<RefreshSession> {
    const entity = this.repo.create(session);
    const saved = await this.repo.save(entity);
    return this.map(await this.repo.findOne({
      where: { id: saved.id },
      relations: ['user']
    }));
  }

  async findById(sessionUuid: string): Promise<RefreshSession | null> {
    const found = await this.repo.findOne({ where: { sessionUuid } });
    return found ? this.map(found) : null;
  }

  async revokeById(sessionUuid: string): Promise<void> {
    await this.repo.update({ sessionUuid }, { revokedAt: new Date() });
  }

  async rotate(oldSession: RefreshSession, newSession: RefreshSession): Promise<RefreshSession> {
    return await this.dataSource.transaction(async manager => {
      await manager.update(RefreshSessionEntity, { sessionUuid: oldSession.sessionUuid }, { revokedAt: new Date(), lastUsedAt: new Date() });
      const entity = manager.create(RefreshSessionEntity, newSession);
      const saved = await manager.save(entity);
      return this.map(saved);
    });
  }

  async revokeAllUserSessions(sessionUuid: string, deviceType?: string): Promise<number> {
    console.log(sessionUuid, deviceType)
    const qb = this.repo.createQueryBuilder()
      .update()
      .set({ revokedAt: () => 'now()' })
      .where('session_uuid = :sessionUuid', { sessionUuid })
      .andWhere('revoked_at IS NULL');
    if (deviceType) qb.andWhere('device_type = :deviceType', { deviceType });
    const res = await qb.execute();
    console.log(res)
    return res.affected ?? 0;
  }

  async deleteExpired(now: Date = new Date()): Promise<number> {
    const res = await this.repo.createQueryBuilder()
      .delete()
      .where('expires_at < :now', { now })
      .execute();
    return res.affected ?? 0;
  }
}