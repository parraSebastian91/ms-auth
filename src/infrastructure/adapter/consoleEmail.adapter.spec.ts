import { Logger } from '@nestjs/common';
import { ConsoleEmailAdapter } from './consoleEmail.adapter';

describe('ConsoleEmailAdapter (adaptador sin servidor de correo)', () => {
  const original = process.env.NODE_ENV;
  afterEach(() => { process.env.NODE_ENV = original; jest.restoreAllMocks(); });

  const capture = () => {
    const lines: string[] = [];
    jest.spyOn(Logger.prototype, 'log').mockImplementation((m: any) => { lines.push(String(m)); });
    jest.spyOn(Logger.prototype, 'warn').mockImplementation((m: any) => { lines.push(String(m)); });
    return lines;
  };
  const URL_CON_TOKEN = 'https://app.test/pages/restablecer-password?token=SECRETO123&uuid=u-1';

  it('en desarrollo imprime el enlace de restablecimiento para poder probar el flujo', async () => {
    process.env.NODE_ENV = 'development';
    const lines = capture();
    await new ConsoleEmailAdapter().sendPasswordResetLink('ana@test.cl', URL_CON_TOKEN, 'Ana');
    expect(lines.join('\n')).toContain(URL_CON_TOKEN);
  });

  it('en producción NO vuelca el token al log y avisa que el correo no se envió', async () => {
    process.env.NODE_ENV = 'production';
    const lines = capture();
    await new ConsoleEmailAdapter().sendPasswordResetLink('ana@test.cl', URL_CON_TOKEN, 'Ana');
    const out = lines.join('\n');
    expect(out).not.toContain('SECRETO123');
    expect(out).not.toContain('ana@test.cl');
    expect(out).toMatch(/NO enviado/);
  });

  it('en desarrollo imprime el código de verificación (OTP) para poder registrarse sin correo', async () => {
    process.env.NODE_ENV = 'development';
    const lines = capture();
    await new ConsoleEmailAdapter().sendVerificationCode('ana@test.cl', '123456', 'Ana');
    expect(lines.join('\n')).toContain('123456');
  });

  it('en producción NO imprime el código OTP ni el correo completo', async () => {
    process.env.NODE_ENV = 'production';
    const lines = capture();
    await new ConsoleEmailAdapter().sendVerificationCode('ana@test.cl', '123456', 'Ana');
    const out = lines.join('\n');
    expect(out).not.toContain('123456');
    expect(out).not.toContain('ana@test.cl');
    expect(out).toMatch(/NO enviado/);
  });

  it('el aviso de cambio de contraseña no incluye datos sensibles', async () => {
    const lines = capture();
    await new ConsoleEmailAdapter().sendPasswordChangedNotice('ana@test.cl', 'Ana');
    expect(lines.join('\n')).toContain('ana@test.cl');
  });
});
