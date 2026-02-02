import { Entity, Column, PrimaryGeneratedColumn, ManyToOne, JoinColumn, CreateDateColumn, Index, Generated } from 'typeorm';
import { UsuarioEntity } from './usuario.entity';

@Entity('password_reset_tokens')
@Index('idx_password_reset_token_hash', ['tokenHash'])
@Index('idx_password_reset_user_id', ['userId'])
@Index('idx_password_reset_expires_at', ['expiresAt'])
@Index('idx_password_reset_email', ['email'])
export class PasswordResetTokenEntity {
  @PrimaryGeneratedColumn('increment')
  id: number;

  @Column('uuid', { unique: true })
  @Generated('uuid')
  tokenUuid: string;

  @Column('varchar', { length: 255 })
  tokenHash: string;

  @Column('bigint')
  userId: number;

  @ManyToOne(() => UsuarioEntity, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: UsuarioEntity;

  @Column('varchar', { length: 100 })
  email: string;

  @Column('timestamp with time zone')
  expiresAt: Date | null;

  @Column('timestamp with time zone', { nullable: true })
  usedAt: Date | null;

  @Column('varchar', { length: 64, nullable: true })
  ipAddress: string;

  @Column('text', { nullable: true })
  userAgent: string;

  @CreateDateColumn({ type: 'timestamp with time zone' })
  createdAt: Date;
}