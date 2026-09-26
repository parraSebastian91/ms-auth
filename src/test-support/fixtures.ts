import { ConfigService } from '@nestjs/config';
import { UsuarioModel } from 'src/core/domain/model/usuario.model';
import { RefreshSessionModel } from 'src/core/domain/model/RefreshSession.model';

export const SECRETS = { access: 'test-access-secret', refresh: 'test-refresh-secret' };

/** Config mínima de JWT/sesión que leen los casos de uso. */
export function makeConfig(overrides: Record<string, any> = {}): ConfigService {
  const values: Record<string, any> = {
    'jwtConfig.access_secret': SECRETS.access,
    'jwtConfig.refresh_secret': SECRETS.refresh,
    'jwtConfig.access_expires_in': '5m',
    'jwtConfig.admin_expires_in': '30m',
    'jwtConfig.refresh_expires_in': '7d',
    'app.ttlRefreshSession': 7 * 24 * 60 * 60 * 1000,
    ...overrides,
  };
  return { get: (key: string) => values[key] } as unknown as ConfigService;
}

type RolFixture = { codigo: string; permisos?: { codigo: string }[] };

export function makeUsuario(o: Partial<{
  id: number; uuid: string; userName: string; password: string; emailVerificado: boolean;
  correo: string | null; roles: RolFixture[]; activo: boolean;
}> = {}): UsuarioModel {
  return UsuarioModel.create({
    id: o.id ?? 7,
    usuarioUuid: o.uuid ?? '11111111-1111-4111-8111-111111111111',
    userName: o.userName ?? 'ana',
    password: o.password ?? 'hash',
    creacion: new Date(),
    activo: o.activo ?? true,
    emailVerificado: o.emailVerificado ?? true,
    contacto: o.correo === null ? null : ({ correo: o.correo ?? 'ana@test.cl' } as any),
    rol: (o.roles ?? [{ codigo: 'CLIENTE_CEDENTE', permisos: [{ codigo: 'USR_VIEW' }] }]) as any,
  } as any);
}

export function makeRefreshSession(o: Partial<{
  sessionUuid: string; sessionId: string; userId: number; userUuid: string; deviceType: string;
  refreshTokenHash: string; expiresAt: Date; revokedAt: Date | null;
}> = {}): RefreshSessionModel {
  return RefreshSessionModel.create({
    id: 1,
    sessionUuid: o.sessionUuid ?? 'sess-uuid-1',
    sessionId: o.sessionId ?? 'sid-1',
    userId: o.userId ?? 7,
    userUuid: o.userUuid ?? '11111111-1111-4111-8111-111111111111',
    deviceType: o.deviceType ?? 'WEB',
    refreshTokenHash: o.refreshTokenHash ?? 'stored-hash',
    expiresAt: o.expiresAt ?? new Date(Date.now() + 3_600_000),
    revokedAt: o.revokedAt ?? null,
    ip: '1.1.1.1',
    userAgent: 'jest',
    deviceFingerprint: 'fp',
  });
}

/** Caché en memoria con la misma interfaz que ICacheRepository (para probar un solo uso del código, etc.). */
export function makeFakeCache() {
  const codes = new Map<string, any>();
  const tokens = new Map<string, string>();
  return {
    codes, tokens,
    setAuthCode: jest.fn(async (c: string, v: any) => { codes.set(c, v); }),
    getAuthCode: jest.fn(async (c: string) => codes.get(c) ?? null),
    deleteAuthCode: jest.fn(async (c: string) => { codes.delete(c); }),
    setAccessToken: jest.fn(async (id: string, t: string) => { tokens.set(id, t); }),
    getAccessToken: jest.fn(async (id: string) => tokens.get(id) ?? null),
    deleteAccessToken: jest.fn(async (id: string) => { tokens.delete(id); }),
    setEmailVerificationCode: jest.fn(), getEmailVerificationCode: jest.fn(), deleteEmailVerificationCode: jest.fn(),
  };
}

/** Vector de prueba de RFC 7636 (apéndice B). */
export const PKCE = {
  verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
  challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
};
