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
    findById: jest.fn(async (): Promise<any> => null),
    getSessionsByUserId: jest.fn(async (): Promise<any[]> => []),
    revokeAllUserSessions: jest.fn(async () => 0),
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

  describe('rotateSession — cadena de rotación', () => {
    const current = { userId: 7, userUuid: 'u-1', sessionId: 'sid-1', sessionUuid: 'old-uuid', typeDevice: 'WEB', roles: [], permissions: [] } as any;

    it('enlaza la sesión nueva con la que rota (rotation_parent_id) y actualiza la fila vieja por su uuid', async () => {
      const { svc, refreshRepo } = setup();
      await svc.rotateSession(current, undefined, 42);

      const [oldSession, newSession] = refreshRepo.rotate.mock.calls[0];
      expect(oldSession.id).toBe(42);
      expect(oldSession.sessionUuid).toBe('old-uuid'); // antes era null: el UPDATE de la fila vieja no encontraba nada
      expect(newSession.rotationParentId).toBe(42);
      expect(newSession.sessionId).toBe('sid-1');
    });

    it('con el id conocido no hace una consulta extra', async () => {
      const { svc, refreshRepo } = setup();
      await svc.rotateSession(current, undefined, 42);
      expect(refreshRepo.findById).not.toHaveBeenCalled();
    });

    it('sin el id lo busca por el uuid de la sesión actual', async () => {
      const { svc, refreshRepo } = setup();
      refreshRepo.findById.mockResolvedValue({ id: 99 });
      await svc.rotateSession(current);
      expect(refreshRepo.findById).toHaveBeenCalledWith('old-uuid');
      expect(refreshRepo.rotate.mock.calls[0][1].rotationParentId).toBe(99);
    });

    it('la sesión nueva expone un secreto distinto en cada rotación y conserva el sessionId', async () => {
      const { svc } = setup();
      const a = await svc.rotateSession(current, undefined, 1);
      const b = await svc.rotateSession(current, undefined, 1);
      expect(a.plainToken).not.toBe(b.plainToken);
      expect(a.plainToken.startsWith('sid-1.')).toBe(true);
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

  describe('revokeAllUserSessions', () => {
    const sess = (sessionId: string) => ({ sessionId });

    it('revoca en BD y borra de la caché los access tokens de cada sesión activa (sin repetir sessionId)', async () => {
      const { svc, cache, refreshRepo } = setup();
      refreshRepo.getSessionsByUserId.mockResolvedValue([sess('sid-1'), sess('sid-2'), sess('sid-1')]);
      refreshRepo.revokeAllUserSessions.mockResolvedValue(3);
      cache.tokens.set('sid-1', 'a'); cache.tokens.set('sid-2', 'b'); cache.tokens.set('sid-otro-usuario', 'c');

      const out = await svc.revokeAllUserSessions(7);

      expect(out).toEqual({ revoked: 3, cacheCleared: 2, cacheFailed: 0 });
      expect(refreshRepo.getSessionsByUserId).toHaveBeenCalledWith('7');
      expect(refreshRepo.revokeAllUserSessions).toHaveBeenCalledWith('7');
      expect(cache.tokens.has('sid-1')).toBe(false);
      expect(cache.tokens.has('sid-2')).toBe(false);
      expect(cache.tokens.has('sid-otro-usuario')).toBe(true);
      expect(cache.deleteAccessToken).toHaveBeenCalledTimes(2);
    });

    it('lista las sesiones ANTES de revocar (la consulta solo devuelve las no revocadas)', async () => {
      const { svc, refreshRepo } = setup();
      await svc.revokeAllUserSessions('7');
      expect(refreshRepo.getSessionsByUserId.mock.invocationCallOrder[0]).toBeLessThan(refreshRepo.revokeAllUserSessions.mock.invocationCallOrder[0]);
    });

    it('sin sesiones activas no toca la caché', async () => {
      const { svc, cache } = setup();
      expect(await svc.revokeAllUserSessions(7)).toEqual({ revoked: 0, cacheCleared: 0, cacheFailed: 0 });
      expect(cache.deleteAccessToken).not.toHaveBeenCalled();
    });

    it('si Redis falla en algún token no lanza: lo cuenta y sigue con los demás', async () => {
      const { svc, cache, refreshRepo } = setup();
      refreshRepo.getSessionsByUserId.mockResolvedValue([sess('sid-1'), sess('sid-2')]);
      refreshRepo.revokeAllUserSessions.mockResolvedValue(2);
      cache.deleteAccessToken.mockImplementation(async (id: string) => { if (id === 'sid-1') throw new Error('redis caído'); cache.tokens.delete(id); });
      cache.tokens.set('sid-2', 'b');

      expect(await svc.revokeAllUserSessions(7)).toEqual({ revoked: 2, cacheCleared: 1, cacheFailed: 1 });
      expect(cache.tokens.has('sid-2')).toBe(false);
    });

    it('si la BD falla el error se propaga y no se toca la caché', async () => {
      const { svc, cache, refreshRepo } = setup();
      refreshRepo.getSessionsByUserId.mockResolvedValue([sess('sid-1')]);
      refreshRepo.revokeAllUserSessions.mockRejectedValue(new Error('bd caída'));
      await expect(svc.revokeAllUserSessions(7)).rejects.toThrow('bd caída');
      expect(cache.deleteAccessToken).not.toHaveBeenCalled();
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
