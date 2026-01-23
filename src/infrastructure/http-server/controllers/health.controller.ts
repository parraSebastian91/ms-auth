import { Controller, Get } from '@nestjs/common';
import {
  HealthCheckService,
  HealthCheck,
  TypeOrmHealthIndicator,
  MemoryHealthIndicator,
  DiskHealthIndicator,
} from '@nestjs/terminus';
import { VaultService } from 'src/infrastructure/secrets/vault.service';

@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private db: TypeOrmHealthIndicator,
    private memory: MemoryHealthIndicator,
    private disk: DiskHealthIndicator,
    private vaultService: VaultService,
  ) {}

  @Get()
  @HealthCheck()
  check() {
    return this.health.check([
      // Database health
      () => this.db.pingCheck('database'),
      
      // Memory health (heap no debe superar 150MB)
      () => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024),
      
      // RSS memory (no debe superar 300MB)
      () => this.memory.checkRSS('memory_rss', 300 * 1024 * 1024),
      
      // Disk health (debe tener al menos 50% libre)
      () =>
        this.disk.checkStorage('storage', {
          path: '/',
          thresholdPercent: 0.5,
        }),
      
      // Vault health
      async () => {
        const isAvailable = this.vaultService.isAvailable();
        return {
          vault: {
            status: isAvailable ? 'up' : 'down',
          },
        };
      },
    ]);
  }

  @Get('ready')
  ready() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'auth-service',
      version: process.env.npm_package_version || '1.0.0',
    };
  }

  @Get('live')
  live() {
    return {
      status: 'alive',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
    };
  }
}