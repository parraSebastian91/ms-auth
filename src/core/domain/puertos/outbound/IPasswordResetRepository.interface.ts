export interface IPasswordResetRepository {
  createResetToken(
    userId: number,
    email: string,
    tokenHash: string,
    expiresAt: Date,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ tokenUuid: string }>;

  findValidToken(tokenHash: string): Promise<{
    id: number;
    userId: number;
    email: string;
    expiresAt: Date;
    usedAt: Date | null;
  } | null>;

  markTokenAsUsed(tokenId: number): Promise<void>;

  deleteExpiredTokens(): Promise<void>;

  deleteUserTokens(userId: number): Promise<void>;
}