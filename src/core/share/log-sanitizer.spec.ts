import { maskEmail, maskIdentifier, maskUsername } from './log-sanitizer';

describe('log-sanitizer', () => {
  it('maskEmail conserva la primera letra y el dominio', () => {
    expect(maskEmail('ana.perez@correo.cl')).toBe('a***@correo.cl');
  });
  it('maskEmail sin @ lo trata como username', () => {
    expect(maskEmail('sinarroba')).toBe('si***');
  });
  it('maskUsername deja solo 2 letras (o nada si es muy corto)', () => {
    expect(maskUsername('sparra')).toBe('sp***');
    expect(maskUsername('ab')).toBe('***');
  });
  it.each([[undefined], [null], ['']])('valores vacíos (%p) no rompen ni filtran', (v) => {
    expect(maskEmail(v as any)).toBe('(vacío)');
    expect(maskUsername(v as any)).toBe('(vacío)');
    expect(maskIdentifier(v as any)).toBe('(vacío)');
  });
  it('maskIdentifier decide según haya @', () => {
    expect(maskIdentifier('ana@x.cl')).toBe('a***@x.cl');
    expect(maskIdentifier('anaperez')).toBe('an***');
  });
  it('el resultado nunca contiene el valor original completo', () => {
    for (const v of ['ana@correo.cl', 'anaperez', 'x@y.z']) expect(maskIdentifier(v)).not.toContain(v);
  });
});
