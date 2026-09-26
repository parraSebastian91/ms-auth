import * as fs from 'fs';
import * as path from 'path';
import { OpenAPIObject } from '@nestjs/swagger';
import * as request from 'supertest';
import { createOpenApiApp, createOpenApiDocument } from 'src/test-support/openapi-app';
import { setupSwagger } from './build-openapi-document';

const CONTRACT_FILE = path.resolve(process.cwd(), 'openapi.json');

describe('Contrato OpenAPI de ms-identity', () => {
  let doc: OpenAPIObject;
  beforeAll(async () => { doc = await createOpenApiDocument(); });

  const operations = () =>
    Object.entries(doc.paths).flatMap(([p, item]) =>
      Object.entries(item as Record<string, any>).map(([method, op]) => ({ key: `${method.toUpperCase()} ${p}`, op })));

  it('expone exactamente las rutas esperadas', () => {
    expect(operations().map(o => o.key).sort()).toEqual([
      'GET /health', 'GET /health/live', 'GET /health/ready',
      'GET /registro/check/{field}',
      'GET /security/password-reset/validate',
      'GET /usuario/profile/{uuid}',
      'POST /registro', 'POST /registro/resend-otp', 'POST /registro/verificar-email',
      'POST /security/authorize',
      'POST /security/logout',
      'POST /security/password-reset/request', 'POST /security/password-reset/reset',
      'POST /security/session/refresh',
      'POST /security/token',
      'PUT /usuario/profile/{uuid}',
    ].sort());
  });

  it('los nombres antiguos (authenticate, callback, session/test) ya no están', () => {
    const keys = operations().map(o => o.key).join('\n');
    expect(keys).not.toMatch(/authenticate|callback|session\/test/);
  });

  it('todas las operaciones tienen resumen y etiqueta', () => {
    const sinDoc = operations().filter(({ op }) => !op.summary || !op.tags?.length).map(o => o.key);
    expect(sinDoc).toEqual([]);
  });

  it('declara los esquemas de seguridad: Bearer JWT y cookies de sesión y refresh', () => {
    expect(doc.components?.securitySchemes).toMatchObject({
      bearer: { type: 'http', scheme: 'bearer' },
      session: { type: 'apiKey', in: 'cookie', name: 'auth.session' },
      refresh: { type: 'apiKey', in: 'cookie', name: 'auth.refresh' },
    });
  });

  it('el perfil exige Bearer y el refresh exige la cookie de refresh', () => {
    const ops = Object.fromEntries(operations().map(o => [o.key, o.op]));
    expect(ops['GET /usuario/profile/{uuid}'].security).toEqual([{ bearer: [] }]);
    expect(ops['PUT /usuario/profile/{uuid}'].security).toEqual([{ bearer: [] }]);
    expect(ops['POST /security/session/refresh'].security).toEqual([{ refresh: [] }]);
    expect(ops['POST /security/logout'].security).toEqual([{ session: [] }]);
    expect(ops['POST /security/authorize'].security).toBeUndefined();
  });

  it('el DTO de authorize documenta campos obligatorios y el enum de dispositivos', () => {
    const schema: any = (doc.components!.schemas as any).AuthorizeRequestDto;
    expect(schema.required.sort()).toEqual(['CorrelationId', 'code_challenge', 'password', 'typeDevice', 'username']);
    expect(schema.properties.typeDevice.enum).toEqual(['WEB', 'DESKTOP', 'MOBILE', 'POSTMAN']);
    expect(schema.properties.password.format).toBe('password');
  });

  it('el DTO de token documenta PKCE (code, codeVerifier, cid, typeDevice)', () => {
    const schema: any = (doc.components!.schemas as any).TokenRequestDto;
    expect(Object.keys(schema.properties).sort()).toEqual(['cid', 'code', 'codeVerifier', 'typeDevice']);
  });

  it('el perfil documenta la respuesta y el cuerpo del PUT', () => {
    const put: any = (doc.paths['/usuario/profile/{uuid}'] as any).put;
    expect(put.requestBody.content['application/json'].schema.$ref).toMatch(/UpdateUserProfileRequestDto$/);
    expect(Object.keys(put.responses)).toEqual(expect.arrayContaining(['200', '400', '401', '403', '404']));
    expect((doc.components!.schemas as any).UserProfileDTO.properties).toHaveProperty('roles');
    expect(JSON.stringify(doc)).not.toMatch(/password_hash/);
  });

  it('setupSwagger publica la UI en /docs y el contrato en /docs-json', async () => {
    const app = await createOpenApiApp();
    setupSwagger(app, '1.0.0');
    await app.init();
    const ui = await request(app.getHttpServer()).get('/docs');
    expect(ui.status).toBe(200);
    expect(ui.headers['content-type']).toMatch(/html/);
    const json = await request(app.getHttpServer()).get('/docs-json');
    expect(json.status).toBe(200);
    expect(json.body.paths).toHaveProperty(['/security/token']);
    await app.close();
  });

  it('los endpoints con límite de intentos documentan la respuesta 429', () => {
    const limitados = [
      'POST /security/authorize', 'POST /security/token', 'POST /security/password-reset/request',
      'GET /security/password-reset/validate', 'POST /security/password-reset/reset', 'POST /registro',
      'GET /registro/check/{field}', 'POST /registro/verificar-email', 'POST /registro/resend-otp',
    ];
    const ops = Object.fromEntries(operations().map(o => [o.key, o.op]));
    for (const k of limitados) expect(Object.keys(ops[k].responses)).toContain('429');
  });

  it('coincide con el openapi.json versionado (regenerar con: npm run openapi)', () => {
    if (process.env.WRITE_OPENAPI) fs.writeFileSync(CONTRACT_FILE, JSON.stringify(doc, null, 2) + '\n');
    expect(fs.existsSync(CONTRACT_FILE)).toBe(true);
    expect(JSON.parse(fs.readFileSync(CONTRACT_FILE, 'utf8'))).toEqual(JSON.parse(JSON.stringify(doc)));
  });
});
