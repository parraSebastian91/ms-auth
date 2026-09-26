import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { makeConfig, makeFakeCache, makeRefreshSession, SECRETS } from 'src/test-support/fixtures';
import { AuthAplicationService } from '../../service/auth.service';
import { SessionUseCase } from './session.usecase';

const access = new JwtService({ secret: SECRETS.access });
const refresh = new JwtService({ secret: SECRETS.refresh });

const payload = (o: any = {}) => ({
  userId: 7, username: 'ana', userUuid: 'u-1', sessionUuid: 'sess-uuid-1', sessionId: 'sid-1',
  roles: ['CLIENTE_CEDENTE'], permissions: ['USR_VIEW'], typeDevice: 'WEB', ...o,
});

function setup(opts: { session?: any; usuario?: any } = {}) {
  const cache = makeFakeCache();
  const usuarioRepo: any = { getUsuarioById: jest.fn().mockResolvedValue(opts.usuario ?? null) };
  const refreshRepo: any = { findById: jest.fn().mockResolvedValue(opts.session === undefined ? makeRefreshSession() : opts.session) };
  // Servicio real (así el TTL por rol es el de producción); solo se espían las operaciones con E/S.
  const authService: any = new AuthAplicationService(cache as any, refreshRepo, access, makeConfig());
  jest.spyOn(authService, 'verifyTokenSecret').mockReturnValue(true);
  jest.spyOn(authService, 'rotateSession').mockImplementation(async (p: any) => ({
    plainToken: 'sid-1.new-uuid.newsecret',
    session: { userId: p.userId, userUuid: p.userUuid, sessionUuid: 'new-uuid', sessionId: p.sessionId, deviceType: p.typeDevice },
  }));
  jest.spyOn(authService, 'revokeUserSessions').mockResolvedValue(1);
  const uc = new SessionUseCase(usuarioRepo, refreshRepo, authService, access, cache as any, makeConfig());
  return { uc, cache, usuarioRepo, refreshRepo, authService };
}

/** Cookie de refresh como la emite el sistema: JWT que envuelve "sessionId.sessionUuid.secreto". */
const refreshCookie = (inner = 'sid-1.sess-uuid-1.secreto', secret = SECRETS.refresh) =>
  new JwtService({ secret }).sign({ refreshToken: inner });
const cmd = (cookies: any) => ({ tokens: cookies, typeDevice: 'WEB' });

describe('SessionUseCase', () => {
  describe('ExecuteValidateSession', () => {
    it('lanza 401 si no hay access token cacheado para la sesión', async () => {
      await expect(setup().uc.ExecuteValidateSession({ sessionId: 'sid-1' })).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('lanza 401 (no 500) si el JWT cacheado está vencido', async () => {
      const { uc, cache } = setup();
      cache.tokens.set('sid-1', access.sign(payload(), { expiresIn: -10 }));
      await expect(uc.ExecuteValidateSession({ sessionId: 'sid-1' })).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('lanza 401 si el JWT cacheado no se puede verificar (firma ajena o basura)', async () => {
      const { uc, cache } = setup();
      cache.tokens.set('sid-1', new JwtService({ secret: 'otra' }).sign(payload()));
      await expect(uc.ExecuteValidateSession({ sessionId: 'sid-1' })).rejects.toBeInstanceOf(UnauthorizedException);
      cache.tokens.set('sid-1', 'basura');
      await expect(uc.ExecuteValidateSession({ sessionId: 'sid-1' })).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('devuelve true con un access token vigente', async () => {
      const { uc, cache } = setup();
      cache.tokens.set('sid-1', access.sign(payload()));
      await expect(uc.ExecuteValidateSession({ sessionId: 'sid-1' })).resolves.toBe(true);
    });
  });

  describe('ExecuteRefreshSession — rechazos', () => {
    it('sin cookie de refresh', async () => {
      await expect(setup().uc.ExecuteRefreshSession(cmd({}))).rejects.toBeInstanceOf(UnauthorizedException);
      await expect(setup().uc.ExecuteRefreshSession(cmd(undefined))).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('cookie firmada con otro secreto o manipulada', async () => {
      await expect(setup().uc.ExecuteRefreshSession(cmd({ 'auth.refresh': refreshCookie(undefined, 'otro') }))).rejects.toBeInstanceOf(UnauthorizedException);
      await expect(setup().uc.ExecuteRefreshSession(cmd({ 'auth.refresh': 'x.y.z' }))).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('cookie válida pero sin el campo refreshToken', async () => {
      const cookie = refresh.sign({ otra: 'cosa' });
      await expect(setup().uc.ExecuteRefreshSession(cmd({ 'auth.refresh': cookie }))).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it.each(['solo-una-parte', 'a.b', 'a..c'])('refreshToken mal formado (%s)', async (inner) => {
      await expect(setup().uc.ExecuteRefreshSession(cmd({ 'auth.refresh': refreshCookie(inner) }))).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('sesión inexistente en BD', async () => {
      const { uc } = setup({ session: null });
      await expect(uc.ExecuteRefreshSession(cmd({ 'auth.refresh': refreshCookie() }))).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('sesión revocada', async () => {
      const { uc, authService } = setup({ session: makeRefreshSession({ revokedAt: new Date() }) });
      await expect(uc.ExecuteRefreshSession(cmd({ 'auth.refresh': refreshCookie() }))).rejects.toBeInstanceOf(UnauthorizedException);
      expect(authService.rotateSession).not.toHaveBeenCalled();
    });

    it('sesión expirada', async () => {
      const { uc } = setup({ session: makeRefreshSession({ expiresAt: new Date(Date.now() - 1000) }) });
      await expect(uc.ExecuteRefreshSession(cmd({ 'auth.refresh': refreshCookie() }))).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('secreto del refresh token no coincide con el hash guardado', async () => {
      const { uc, authService } = setup();
      authService.verifyTokenSecret.mockReturnValue(false);
      await expect(uc.ExecuteRefreshSession(cmd({ 'auth.refresh': refreshCookie() }))).rejects.toBeInstanceOf(UnauthorizedException);
      expect(authService.rotateSession).not.toHaveBeenCalled();
    });

    it('DOCUMENTA: reutilizar un refresh token ya rotado (revocado) solo da 401; no revoca el resto de la familia', async () => {
      const { uc, authService, refreshRepo } = setup({ session: makeRefreshSession({ revokedAt: new Date() }) });
      await uc.ExecuteRefreshSession(cmd({ 'auth.refresh': refreshCookie() })).catch(() => undefined);
      expect(authService.revokeUserSessions).not.toHaveBeenCalled();
      expect(refreshRepo.findById).toHaveBeenCalledTimes(1);
    });
  });

  describe('ExecuteRefreshSession — rotación', () => {
    it('con access token en caché rota la sesión, emite tokens nuevos y actualiza la caché', async () => {
      const { uc, cache, authService } = setup();
      cache.tokens.set('sid-1', access.sign(payload()));
      const out = await uc.ExecuteRefreshSession(cmd({ 'auth.refresh': refreshCookie() }));

      expect(authService.rotateSession).toHaveBeenCalledWith(expect.objectContaining({ userUuid: 'u-1', sessionUuid: 'sess-uuid-1' }), { ip: '1.1.1.1', ua: 'jest', fingerprint: 'fp' });
      const nuevo: any = access.verify(out.accessToken);
      expect(nuevo).toMatchObject({ userUuid: 'u-1', sessionUuid: 'new-uuid', roles: ['CLIENTE_CEDENTE'], permissions: ['USR_VIEW'] });
      expect(cache.tokens.get('sid-1')).toBe(out.accessToken);
      const r: any = refresh.verify(out.refreshToken);
      expect(r.refreshToken).toBe('sid-1.new-uuid.newsecret');
    });

    it('sin access token en caché reconstruye el payload desde la BD', async () => {
      const usuario = { userName: 'ana', rol: [{ codigo: 'SUPERVISOR', permisos: [{ codigo: 'ORG_VIEW' }] }] };
      const { uc, usuarioRepo, authService } = setup({ usuario });
      const out = await uc.ExecuteRefreshSession(cmd({ 'auth.refresh': refreshCookie() }));
      expect(usuarioRepo.getUsuarioById).toHaveBeenCalledWith(7);
      expect(authService.rotateSession).toHaveBeenCalledWith(expect.objectContaining({ roles: ['SUPERVISOR'], permissions: ['ORG_VIEW'] }), expect.anything());
      expect(access.verify(out.accessToken)).toMatchObject({ roles: ['SUPERVISOR'] });
    });

    it('sin caché y usuario borrado → 401 y no se rota', async () => {
      const { uc, authService } = setup({ usuario: null });
      await expect(uc.ExecuteRefreshSession(cmd({ 'auth.refresh': refreshCookie() }))).rejects.toBeInstanceOf(UnauthorizedException);
      expect(authService.rotateSession).not.toHaveBeenCalled();
    });

    describe('TTL del access token', () => {
      const ttl = async (o: any) => {
        const { uc, cache } = setup();
        cache.tokens.set('sid-1', access.sign(payload(o)));
        const out = await uc.ExecuteRefreshSession(cmd({ 'auth.refresh': refreshCookie() }));
        const p: any = access.verify(out.accessToken);
        return p.exp - p.iat;
      };
      it('usuario común: TTL normal (5 min)', async () => { expect(await ttl({})).toBe(300); });
      it('rol ADMIN: TTL de administrador (30 min)', async () => { expect(await ttl({ roles: ['ADMIN'] })).toBe(1800); });
      it('rol SUPER_ADMIN: también TTL de administrador (misma regla que el login)', async () => {
        expect(await ttl({ roles: ['SUPER_ADMIN'] })).toBe(1800);
      });
      it('un permiso llamado SUPER_ADMIN NO da TTL de administrador: solo cuentan los roles', async () => {
        expect(await ttl({ roles: ['CLIENTE_CEDENTE'], permissions: ['SUPER_ADMIN'] })).toBe(300);
      });
    });
  });

  describe('ExecuteLogout', () => {
    it('revoca las sesiones a través del servicio de aplicación', async () => {
      const { uc, authService } = setup();
      await uc.ExecuteLogout('sid-1');
      expect(authService.revokeUserSessions).toHaveBeenCalledWith('sid-1');
    });
  });
});
