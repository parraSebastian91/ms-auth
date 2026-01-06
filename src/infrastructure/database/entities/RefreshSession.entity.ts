import { Column, CreateDateColumn, Entity, Index, JoinColumn, ManyToOne, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm';
import { UsuarioEntity } from './usuario.entity'; // ajusta ruta si difiere

@Entity('auth_refresh_sessions')
export class RefreshSessionEntity {
  
  @PrimaryGeneratedColumn('increment')
  id: number;

  @Column({ name: 'session_uuid', length: 36 })
  sessionUuid: string;

  //   @Index()
  //   @Column({ name: 'user_id', type: 'bigint' })
  //   userId: number;

  @Column({ name: 'device_type', length: 30 })
  deviceType: string; // WEB | DESKTOP | MOBILE

  @Column({ name: 'device_fingerprint', length: 128, nullable: true })
  deviceFingerprint?: string;

  @Index()
  @Column({ name: 'refresh_token_hash', length: 255 })
  refreshTokenHash: string;

  @Column({ length: 64, nullable: true })
  ip?: string;

  @Column({ name: 'user_agent', type: 'text', nullable: true })
  userAgent?: string;

  @Index()
  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  @Column({ name: 'last_used_at', type: 'timestamptz', nullable: true })
  lastUsedAt?: Date;

  @Column({ name: 'revoked_at', type: 'timestamptz', nullable: true })
  revokedAt?: Date;

  @Column({ name: 'rotation_parent_id', type: 'bigint', nullable: true })
  rotationParentId?: number;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @ManyToOne(() => UsuarioEntity, (user) => user.refreshSessions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id', referencedColumnName: 'id' })
  user: UsuarioEntity;
}