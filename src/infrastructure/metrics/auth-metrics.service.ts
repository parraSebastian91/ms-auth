import { Injectable } from '@nestjs/common';
import { InjectMetric } from '@willsoto/nestjs-prometheus';
import { Counter } from 'prom-client';

/** Contadores Prometheus del flujo de autenticación, para que los controladores no los conozcan. */
@Injectable()
export class AuthMetricsService {
  constructor(
    @InjectMetric('auth_login_attempts_total') private readonly loginAttempts: Counter<string>,
    @InjectMetric('auth_token_refresh_total') private readonly tokenRefresh: Counter<string>,
    @InjectMetric('auth_password_reset_requests_total') private readonly passwordReset: Counter<string>,
  ) {}

  loginAttempt(result: 'success' | 'failure'): void { this.loginAttempts.inc({ result }); }
  sessionRefreshed(): void { this.tokenRefresh.inc(); }
  passwordResetRequested(): void { this.passwordReset.inc(); }
}
