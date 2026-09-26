import { accountTracker, clientIp } from './rate-limit';

describe('trackers de rate limit', () => {
  it('accountTracker usa username, correo o email del cuerpo, normalizado', () => {
    expect(accountTracker({ body: { username: '  ANA ' } })).toBe('account:ana');
    expect(accountTracker({ body: { correo: 'Ana@X.cl' } })).toBe('account:ana@x.cl');
    expect(accountTracker({ body: { email: 'ana@x.cl' } })).toBe('account:ana@x.cl');
    expect(accountTracker({ query: { correo: 'ana@x.cl' } })).toBe('account:ana@x.cl');
  });

  it('mayúsculas y espacios no permiten evadir el contador de una misma cuenta', () => {
    expect(accountTracker({ body: { username: 'Ana' } })).toBe(accountTracker({ body: { username: ' ana ' } }));
  });

  it('sin identificador (o con un valor no texto) cae a la IP', () => {
    expect(accountTracker({ ip: '9.9.9.9', body: {} })).toBe('ip:9.9.9.9');
    expect(accountTracker({ ip: '9.9.9.9', body: { username: { $ne: null } } })).toBe('ip:9.9.9.9');
    expect(accountTracker({ ip: '9.9.9.9' })).toBe('ip:9.9.9.9');
  });

  it('acota la longitud del identificador (no se puede inflar la memoria con claves enormes)', () => {
    expect(accountTracker({ body: { username: 'a'.repeat(5000) } }).length).toBeLessThanOrEqual('account:'.length + 200);
  });

  it('clientIp usa req.ip y, si falta, la dirección del socket', () => {
    expect(clientIp({ ip: '1.2.3.4' })).toBe('1.2.3.4');
    expect(clientIp({ socket: { remoteAddress: '5.6.7.8' } })).toBe('5.6.7.8');
    expect(clientIp({})).toBe('unknown');
  });
});
