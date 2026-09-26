import { Controller, Get } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  HealthCheckService,
  HealthCheck,
  TypeOrmHealthIndicator,
  MemoryHealthIndicator,
  DiskHealthIndicator,
} from '@nestjs/terminus';
import { Public } from '../decorators/public.decorator';

@ApiTags('Health')
@Public()
@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private db: TypeOrmHealthIndicator,
    private memory: MemoryHealthIndicator,
    private disk: DiskHealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  @ApiOperation({ summary: 'Estado detallado (base de datos, memoria y disco)' })
  check() {
    return this.health.check([
      // Database health
      () => this.db.pingCheck('database'),

      // Memory health (heap no debe superar 150MB)
      () => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024),

      // RSS memory (no debe superar 300MB)
      () => this.memory.checkRSS('memory_rss', 300 * 1024 * 1024),

      // Disk health (debe tener al menos 90% libre)
      () =>
        this.disk.checkStorage('storage', {
          path: '/',
          thresholdPercent: 0.9,
        }),
    ]);
  }

  @Get('ready')
  @ApiOperation({ summary: 'Readiness: el servicio está listo para recibir tráfico' })
  ready() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'identity-service',
      version: process.env.npm_package_version || '1.0.0',
    };
  }

  @Get('live')
  @ApiOperation({ summary: 'Liveness: el proceso está vivo' })
  live() {
    return {
      status: 'alive',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
    };
  }
}
