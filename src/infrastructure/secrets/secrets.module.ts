import { Module } from '@nestjs/common';
import { VaultService } from './vault.service';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  providers: [VaultService],
  exports: [VaultService],
})
export class SecretsModule {}
