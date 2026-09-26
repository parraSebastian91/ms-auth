import * as bcrypt from 'bcrypt';
import { EmailNotVerifiedError } from 'src/core/domain/errors/EmailNotVerified.error';
import { InvalidcodeToken } from 'src/core/domain/errors/InvalidCodeToken.error';
import { LoginError } from 'src/core/domain/errors/LoginError.error';
import { JwtService } from '@nestjs/jwt';
import { makeConfig, makeFakeCache, makeUsuario, PKCE, SECRETS } from 'src/test-support/fixtures';
import { AuthAplicationService } from '../../service/auth.service';
import { AuthorizationUseCase } from './authorization.usecase';

const PASSWORD = 'Secreta#123';

function setup(usuario: any = undefined, systems: any[] = [{}, {}]) {
  const cache = makeFakeCache();
  const usuarioRepo: any = {
    getUsuarioByUsername: jest.fn().mockResolvedValue(usuario),
    getSystemsByUsername: jest.fn().mockResolvedValue(systems),
  };
  const refreshRepo: any = { create: jest.fn(async (s: any) => ({ ...s, sessionUuid: 'su' })), rotate: jest.fn(), revokeById: jest.fn() };
  // AuthAplicationService real: así se prueba PKCE y la emisión de tokens de verdad.
  const authService = new AuthAplicationService(cache as any, refreshRepo, new JwtService({ secret: SECRETS.access }), makeConfig());
  return { uc: new AuthorizationUseCase(usuarioRepo, authService, cache as any), cache, usuarioRepo, refreshRepo };
}

const authorizeCmd = (o: any = {}) => ({
  username: 'ana', password: PASSWORD, typeDevice: 'WEB', code_challenge: PKCE.challenge, CorrelationId: 'cid-1', ...o,
});

describe('AuthorizationUseCase', () => {
  let hash: string;
  beforeAll(async () => { hash = await bcrypt.hash(PASSWORD, 4); });

  describe('ExecuteAuthorize', () => {
    it('un usuario inexistente da LoginError (credenciales inválidas) y NO emite código', async () => {
      const { uc, cache } = setup(null);
      await expect(uc.ExecuteAuthorize(authorizeCmd())).rejects.toBeInstanceOf(LoginError);
      expect(cache.setAuthCode).not.toHaveBeenCalled();
    });

    it('lanza LoginError con contraseña incorrecta y NO emite código', async () => {
      const { uc, cache } = setup(makeUsuario({ password: hash }));
      await expect(uc.ExecuteAuthorize(authorizeCmd({ password: 'mala' }))).rejects.toBeInstanceOf(LoginError);
      expect(cache.setAuthCode).not.toHaveBeenCalled();
    });

    it('anti-enumeración: usuario inexistente y contraseña errónea dan el MISMO error y mensaje', async () => {
      const missing = await setup(null).uc.ExecuteAuthorize(authorizeCmd()).catch(e => e);
      const wrong = await setup(makeUsuario({ password: hash })).uc.ExecuteAuthorize(authorizeCmd({ password: 'x' })).catch(e => e);
      expect(missing).toBeInstanceOf(LoginError);
      expect(wrong).toBeInstanceOf(LoginError);
      expect(missing.message).toBe(wrong.message);
    });

    it('anti-enumeración por tiempo: con usuario inexistente igual se ejecuta bcrypt (no responde al instante)', async () => {
      const { uc } = setup(null);
      const t0 = process.hrtime.bigint();
      await uc.ExecuteAuthorize(authorizeCmd()).catch(() => undefined);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      expect(ms).toBeGreaterThan(10); // bcrypt de coste 10 tarda decenas de ms; sin comparación sería < 1 ms
    });

    it('lanza EmailNotVerifiedError con el correo del contacto si el email no está verificado', async () => {
      const { uc, cache } = setup(makeUsuario({ password: hash, emailVerificado: false, correo: 'ana@test.cl' }));
      const err: any = await uc.ExecuteAuthorize(authorizeCmd()).catch(e => e);
      expect(err).toBeInstanceOf(EmailNotVerifiedError);
      expect(err.email).toBe('ana@test.cl');
      expect(cache.setAuthCode).not.toHaveBeenCalled();
    });

    it('sin contacto usa el username como correo en EmailNotVerifiedError', async () => {
      const { uc } = setup(makeUsuario({ password: hash, emailVerificado: false, correo: null }));
      const err: any = await uc.ExecuteAuthorize(authorizeCmd()).catch(e => e);
      expect(err.email).toBe('ana');
    });

    it('con credenciales válidas emite un código ligado al code_challenge y devuelve una redirección por sistema', async () => {
      const { uc, cache } = setup(makeUsuario({ password: hash }), [{}, {}, {}]);
      const out = await uc.ExecuteAuthorize(authorizeCmd());
      expect(out).toHaveLength(3);
      const code = decodeURIComponent(out[0].code);
      expect(cache.codes.get(code)).toMatchObject({ codeChallenge: PKCE.challenge, typeDevice: 'WEB', CorrelationId: 'cid-1' });
      expect(out[0].url).toBe(`/validate?code=${encodeURIComponent(code)}&cid=cid-1`);
    });

    it('escapa el CorrelationId en la URL de redirección', async () => {
      const { uc } = setup(makeUsuario({ password: hash }), [{}]);
      const out = await uc.ExecuteAuthorize(authorizeCmd({ CorrelationId: 'a b&c=d' }));
      expect(out[0].url).toContain('cid=a%20b%26c%3Dd');
    });

    it('DOCUMENTA: un usuario sin sistemas asignados recibe una lista vacía (aunque se emitió el código)', async () => {
      const { uc, cache } = setup(makeUsuario({ password: hash }), []);
      expect(await uc.ExecuteAuthorize(authorizeCmd())).toEqual([]);
      expect(cache.codes.size).toBe(1);
    });
  });

  describe('ExecuteToken', () => {
    const tokenCmd = (o: any = {}) => ({
      code: '', codeVerifier: PKCE.verifier, typeDevice: 'WEB', sessionId: 'sid-1', CorrelationId: 'cid-1', ...o,
    });
    async function withCode(typeDevice = 'WEB') {
      const s = setup(makeUsuario({ password: hash }));
      const [{ code }] = await s.uc.ExecuteAuthorize(authorizeCmd({ typeDevice }));
      return { ...s, code: decodeURIComponent(code) };
    }

    it.each(['', undefined])('rechaza un código vacío (%p)', async (code) => {
      await expect(setup().uc.ExecuteToken(tokenCmd({ code }))).rejects.toBeInstanceOf(InvalidcodeToken);
    });

    it('rechaza un código inexistente', async () => {
      await expect(setup().uc.ExecuteToken(tokenCmd({ code: 'no-existe' }))).rejects.toBeInstanceOf(InvalidcodeToken);
    });

    it('rechaza un code_verifier que no corresponde al challenge (PKCE) y conserva el código', async () => {
      const { uc, code, cache } = await withCode();
      await expect(uc.ExecuteToken(tokenCmd({ code, codeVerifier: 'verifier-incorrecto' }))).rejects.toThrow(/PKCE/);
      expect(cache.deleteAuthCode).not.toHaveBeenCalled();
    });

    it('rechaza un tipo de dispositivo distinto al de la emisión', async () => {
      const { uc, code, cache } = await withCode('WEB');
      await expect(uc.ExecuteToken(tokenCmd({ code, typeDevice: 'MOBILE' }))).rejects.toThrow(/dispositivo/);
      expect(cache.deleteAuthCode).not.toHaveBeenCalled();
    });

    it('compara el dispositivo sin distinguir mayúsculas ni espacios', async () => {
      const { uc, code } = await withCode('WEB');
      await expect(uc.ExecuteToken(tokenCmd({ code, typeDevice: '  web ' }))).resolves.toBeDefined();
    });

    it('con verifier y dispositivo correctos devuelve access y refresh token de la sesión indicada', async () => {
      const { uc, code, cache } = await withCode();
      const tokens = await uc.ExecuteToken(tokenCmd({ code, sessionId: 'sid-77' }));
      expect(tokens.accessToken).toBeTruthy();
      expect(tokens.refreshToken).toBeTruthy();
      expect(cache.tokens.has('sid-77')).toBe(true);
    });

    it('el código es de UN solo uso: el segundo canje falla', async () => {
      const { uc, code } = await withCode();
      await uc.ExecuteToken(tokenCmd({ code }));
      await expect(uc.ExecuteToken(tokenCmd({ code }))).rejects.toBeInstanceOf(InvalidcodeToken);
    });
  });
});
