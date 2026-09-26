import { JwtService } from '@nestjs/jwt';
import { createHmac } from 'crypto';
import { makeConfig, makeFakeCache, makeRefreshSession, makeUsuario, PKCE, SECRETS } from 'src/test-support/fixtures';
import { AuthAplicationService } from './auth.service';

function setup() {
  const cache = makeFakeCache();
  const refreshRepo = {
    create: jest.fn(async (s: any) => ({ ...s, sessionUuid: 'new-sess-uuid' })),
    rotate: jest.fn(async (_old: any, n: any) => ({ ...n, sessionUuid: 'rotated-uuid' })),
    revokeById: jest.fn(async () => undefined),
    revokeUserSessions: jest.fn(async () => 2),
  };
  const jwt = new JwtService({ secret: SECRETS.access });
  const svc = new AuthAplicationService(cache as any, refreshRepo as any, jwt, makeConfig());
  return { svc, cache, refreshRepo, jwt };
}

describe('AuthAplicationService', () => {
  describe('PKCE', () => {
    it('hashingCodeChallenge produce el S256 base64url del vector de RFC 7636', () => {
      expect(setup().svc.hashingCodeChallenge(PKCE.verifier)).toBe(PKCE.challenge);
    });

    it('no usa relleno "=" ni los caracteres + /', () => {
      const out = setup().svc.hashingCodeChallenge('cualquier-verifier-largo-1234567890');
      expect(out).toMatch(/^[A-Za-z0-9_-]+$/);
    });
  });

  describe('verifyTokenSecret', () => {
    const hmac = (s: string) => createHmac('sha256', SECRETS.refresh).update(s).digest('hex');

    it('acepta el secreto correcto', () => {
      expect(setup().svc.verifyTokenSecret('mi-secreto', hmac('mi-secreto'))).toBe(true);
    });

    it('rechaza un secreto distinto', () => {
      expect(setup().svc.verifyTokenSecret('otro', hmac('mi-secreto'))).toBe(false);
    });

    it('rechaza un hash almacenado de otra longitud sin lanzar', () => {
      expect(setup().svc.verifyTokenSecret('mi-secreto', 'corto')).toBe(false);
    });
  });

  describe('createAuthorizationCode', () => {
    it('guarda en caché un código aleatorio de 64 hex con identidad, roles, permisos y challenge', async () => {
      const { svc, cache } = setup();
      const usuario = makeUsuario({ roles: [{ codigo: 'ADMIN', permisos: [{ codigo: 'USR_VIEW' }, { codigo: 'USR_EDIT' }] }] });
      const code = await svc.createAuthorizationCode(usuario, PKCE.challenge, 'WEB', 'cid-1');
      expect(code).toMatch(/^[0-9a-f]{64}$/);
      expect(cache.codes.get(code)).toMatchObject({
        userUuid: usuario.uuid, sub: 'ana', CorrelationId: 'cid-1', typeDevice: 'WEB',
        codeChallenge: PKCE.challenge, rol: ['ADMIN'], permisos: ['USR_VIEW', 'USR_EDIT'],
      });
    });

    it('cada código es distinto', async () => {
      const { svc } = setup();
      const u = makeUsuario();
      expect(await svc.createAuthorizationCode(u, 'c', 'WEB', 'x')).not.toBe(await svc.createAuthorizationCode(u, 'c', 'WEB', 'x'));
    });
  });

  describe('createRefreshSession', () => {
    const stored = () => ({
      userId: 7, userUuid: 'u-1', CorrelationId: 'c', sessionId: 'sid-1', sessionUuid: '', sub: 'ana',
      rol: ['CLIENTE_CEDENTE'], permisos: ['USR_VIEW'], typeDevice: 'WEB', codeChallenge: 'x', createdAt: 0,
    });

    it('sin sesión previa en caché crea una sesión nueva y cachea el access token', async () => {
      const { svc, refreshRepo, cache, jwt } = setup();
      const out = await svc.createRefreshSession(stored() as any);
      expect(refreshRepo.create).toHaveBeenCalledTimes(1);
      expect(refreshRepo.rotate).not.toHaveBeenCalled();
      expect(cache.tokens.get('sid-1')).toBe(out.accessToken);
      expect(jwt.verify(out.accessToken, { secret: SECRETS.access })).toMatchObject({ userUuid: 'u-1', roles: ['CLIENTE_CEDENTE'] });
    });

    it('el refresh token es un JWT firmado con el secreto de refresh que envuelve "sessionId.sessionUuid.secreto"', async () => {
      const { svc } = setup();
      const out = await svc.createRefreshSession(stored() as any);
      const decoded: any = new JwtService({ secret: SECRETS.refresh }).verify(out.refreshToken);
      expect(decoded.refreshToken.split('.')).toHaveLength(3);
      expect(decoded.refreshToken.startsWith('sid-1.new-sess-uuid.')).toBe(true);
    });

    it('con una sesión vigente en caché para ese sessionId la rota en vez de crear otra', async () => {
      const { svc, refreshRepo, cache, jwt } = setup();
      const prev = jwt.sign({ userId: 7, userUuid: 'u-1', sessionId: 'sid-1', sessionUuid: 'old-uuid', typeDevice: 'WEB', roles: [], permissions: [] }, { secret: SECRETS.access });
      cache.tokens.set('sid-1', prev);
      await svc.createRefreshSession(stored() as any);
      expect(refreshRepo.revokeById).toHaveBeenCalledWith('old-uuid');
      expect(refreshRepo.rotate).toHaveBeenCalledTimes(1);
      expect(refreshRepo.create).not.toHaveBeenCalled();
    });

    it('un usuario ADMIN recibe el TTL de administrador; uno común, el normal', async () => {
      const ttl = async (rol: string[]) => {
        const { svc, jwt } = setup();
        const out = await svc.createRefreshSession({ ...stored(), rol } as any);
        const p: any = jwt.verify(out.accessToken, { secret: SECRETS.access });
        return p.exp - p.iat;
      };
      expect(await ttl(['ADMIN'])).toBe(30 * 60);
      expect(await ttl(['SUPER_ADMIN'])).toBe(30 * 60);
      expect(await ttl(['CLIENTE_CEDENTE'])).toBe(5 * 60);
    });
  });

  describe('accessTokenExpiresIn', () => {
    it.each([
      [['ADMIN'], '30m'], [['SUPER_ADMIN'], '30m'], [['CLIENTE_CEDENTE', 'ADMIN'], '30m'],
      [['CLIENTE_CEDENTE'], '5m'], [[], '5m'], [undefined as any, '5m'],
    ])('roles %p → %s', (roles, expected) => {
      expect(setup().svc.accessTokenExpiresIn(roles)).toBe(expected);
    });
  });

  describe('revokeUserSessions', () => {
    it('devuelve 0 si no hay access token en caché', async () => {
      const { svc, refreshRepo } = setup();
      expect(await svc.revokeUserSessions('sid-x')).toBe(0);
      expect(refreshRepo.revokeUserSessions).not.toHaveBeenCalled();
    });

    it('devuelve 0 si el token de caché no se puede decodificar', async () => {
      const { svc, cache } = setup();
      cache.tokens.set('sid-1', 'no-es-un-jwt');
      expect(await svc.revokeUserSessions('sid-1')).toBe(0);
    });

    it('revoca en BD por sessionUuid+dispositivo y borra el token de caché', async () => {
      const { svc, cache, refreshRepo, jwt } = setup();
      cache.tokens.set('sid-1', jwt.sign({ userUuid: 'u', sessionUuid: 'sess-9', typeDevice: 'WEB' }));
      expect(await svc.revokeUserSessions('sid-1')).toBe(2);
      expect(refreshRepo.revokeUserSessions).toHaveBeenCalledWith('sess-9', 'WEB');
      expect(cache.tokens.has('sid-1')).toBe(false);
    });
  });
});
