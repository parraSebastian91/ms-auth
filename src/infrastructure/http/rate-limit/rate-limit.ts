import { ThrottlerModuleOptions } from '@nestjs/throttler';

const MINUTE = 60_000;
export const minutes = (n: number) => n * MINUTE;
export const hours = (n: number) => n * 60 * MINUTE;

/** IP del cliente. Con `trust proxy` de Express es la que informa el proxy (ver TRUST_PROXY_HOPS en main.ts). */
export function clientIp(req: Record<string, any>): string {
  return req.ip ?? req.socket?.remoteAddress ?? 'unknown';
}

/**
 * Cuenta objetivo de la petición (username en login, correo en reset/OTP), normalizada. Limitar por
 * cuenta frena la fuerza bruta y el bombardeo de correos aunque el atacante rote de IP; sin
 * identificador cae a la IP.
 */
export function accountTracker(req: Record<string, any>): string {
  const raw = req.body?.username ?? req.body?.correo ?? req.body?.email ?? req.query?.correo;
  const id = typeof raw === 'string' ? raw.trim().toLowerCase().slice(0, 200) : '';
  return id ? `account:${id}` : `ip:${clientIp(req)}`;
}

const disabled = () => process.env.RATE_LIMIT_ENABLED === 'false';

/**
 * Limitadores globales, deliberadamente holgados: son la red de seguridad. Las rutas sensibles fijan
 * límites propios con @Throttle usando RATE_LIMITS. Almacenamiento en memoria (por instancia): con
 * varias réplicas el límite efectivo es N veces mayor hasta usar un almacenamiento compartido (Redis).
 */
export function createThrottlerOptions(): ThrottlerModuleOptions {
  return {
    throttlers: [
      { name: 'ip', ttl: minutes(1), limit: 120, getTracker: req => `ip:${clientIp(req)}`, skipIf: disabled },
      { name: 'account', ttl: minutes(15), limit: 1000, getTracker: accountTracker, skipIf: disabled },
    ],
    errorMessage: 'Demasiados intentos. Espera un momento e inténtalo de nuevo.',
  };
}

/** Límites por ruta (ttl en ms). `ip`: por cliente; `account`: por cuenta objetivo. */
export const RATE_LIMITS = {
  authorize: { ip: { limit: 20, ttl: minutes(1) }, account: { limit: 10, ttl: minutes(15) } },
  token: { ip: { limit: 30, ttl: minutes(1) } },
  registroCheck: { ip: { limit: 30, ttl: minutes(1) } },
  registroCreate: { ip: { limit: 10, ttl: hours(1) } },
  verificarEmail: { ip: { limit: 30, ttl: minutes(15) }, account: { limit: 10, ttl: minutes(15) } },
  resendOtp: { ip: { limit: 10, ttl: minutes(15) }, account: { limit: 3, ttl: minutes(15) } },
  resetRequest: { ip: { limit: 10, ttl: minutes(15) }, account: { limit: 3, ttl: hours(1) } },
  resetValidate: { ip: { limit: 30, ttl: minutes(15) } },
  resetConfirm: { ip: { limit: 10, ttl: minutes(15) } },
} as const;
