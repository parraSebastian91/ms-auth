import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { Pool } from 'pg';
import { IPasswordResetRepository } from 'src/core/domain/puertos/outbound/IPasswordResetRepository.interface';
import { DataSource, Repository } from 'typeorm';
import { PasswordResetTokenEntity } from '../database/entities/passwordResetTokens.entity';

@Injectable()
export class PasswordResetRepositoryAdapter implements IPasswordResetRepository {
  private repo: Repository<PasswordResetTokenEntity>;

  constructor(@InjectDataSource() private dataSource: DataSource) {
    this.repo = this.dataSource.getRepository(PasswordResetTokenEntity);
  }

  async createResetToken(
    userId: number,
    email: string,
    tokenHash: string,
    expiresAt: Date,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ tokenUuid: string }> {
    const query = `
      INSERT INTO core.password_reset_tokens 
        (user_id, email, token_hash, expires_at, ip_address, user_agent)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING token_uuid
    `;

    const result = await this.repo.query(query, [
      userId,
      email,
      tokenHash,
      expiresAt,
      ipAddress,
      userAgent,
    ]);
    return { tokenUuid: result[0].token_uuid };
  }

  async findValidToken(uuid: string): Promise<{
    id: number;
    userId: number;
    uuid: string;
    tokenHash: string;
    email: string;
    expiresAt: Date;
    usedAt: Date | null;
  } | null> {
    const query = `
      SELECT 
        id,
        user_id as "userId",
        token_uuid as "uuid",
        token_hash as "tokenHash",
        email,
        expires_at as "expiresAt",
        used_at as "usedAt"
      FROM core.password_reset_tokens
      WHERE token_uuid = $1
        AND expires_at > NOW()
        AND used_at IS NULL
      LIMIT 1
    `;

    const result = await this.repo.query(query, [uuid]);
    return result[0] || null;
  }

  async markTokenAsUsed(tokenId: number): Promise<void> {
    const query = `
      UPDATE core.password_reset_tokens
      SET used_at = NOW()
      WHERE id = $1
    `;

    await this.repo.query(query, [tokenId]);
  }

  async deleteExpiredTokens(): Promise<void> {
    const query = `
      DELETE FROM core.password_reset_tokens
      WHERE expires_at < NOW()
    `;

    await this.repo.query(query);
  }

  async deleteUserTokens(userId: number): Promise<void> {
    const query = `
      DELETE FROM core.password_reset_tokens
      WHERE user_id = $1
    `;

    await this.repo.query(query, [userId]);
  }
}