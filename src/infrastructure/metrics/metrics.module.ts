import { Global, Module } from '@nestjs/common';
import {
  PrometheusModule,
  makeCounterProvider,
  getToken,
} from '@willsoto/nestjs-prometheus';

@Global()
@Module({
  imports: [
    PrometheusModule.register({
      path: '/metrics',
      defaultMetrics: {
        enabled: true,
      },
      defaultLabels: {
        app: 'ms-auth',
      },
    }),
  ],
  providers: [
    makeCounterProvider({
      name: 'auth_login_attempts_total',
      help: 'Total de intentos de autenticación',
      labelNames: ['result'],
    }),
    makeCounterProvider({
      name: 'auth_token_refresh_total',
      help: 'Total de refrescos de sesión',
    }),
    makeCounterProvider({
      name: 'auth_register_attempts_total',
      help: 'Total de intentos de registro',
      labelNames: ['result'],
    }),
    makeCounterProvider({
      name: 'auth_password_reset_requests_total',
      help: 'Total de solicitudes de reseteo de contraseña',
    }),
  ],
  exports: [
    getToken('auth_login_attempts_total'),
    getToken('auth_token_refresh_total'),
    getToken('auth_register_attempts_total'),
    getToken('auth_password_reset_requests_total'),
  ],
})
export class MetricsModule {}