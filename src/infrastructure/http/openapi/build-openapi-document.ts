import { INestApplication } from '@nestjs/common';
import { DocumentBuilder, OpenAPIObject, SwaggerModule } from '@nestjs/swagger';

/** Contrato OpenAPI de ms-identity a partir de los controladores del `app` dado. */
export function buildOpenApiDocument(app: INestApplication, version = '1.0.0'): OpenAPIObject {
  const config = new DocumentBuilder()
    .setTitle('ms-identity')
    .setDescription(
      'Identidad y autenticación de SEIS App: Authorization Code + PKCE, ciclo de sesión, ' +
        'recuperación de contraseña, registro y perfil de usuario.\n\n' +
        '**Flujo de login**: `POST /security/authorize` (credenciales + code_challenge) → código → ' +
        '`POST /security/token` (código + code_verifier) → cookies `auth.session` y `auth.refresh`. ' +
        'Las rutas de perfil usan el JWT de acceso como Bearer.',
    )
    .setVersion(version)
    .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }, 'bearer')
    .addCookieAuth('auth.session', { type: 'apiKey', in: 'cookie', name: 'auth.session' }, 'session')
    .addCookieAuth('auth.refresh', { type: 'apiKey', in: 'cookie', name: 'auth.refresh' }, 'refresh')
    .build();
  return SwaggerModule.createDocument(app, config);
}

/** Publica la UI en /docs y el JSON en /docs-json. main.ts decide cuándo llamarla (no en producción). */
export function setupSwagger(app: INestApplication, version?: string): void {
  SwaggerModule.setup('docs', app, buildOpenApiDocument(app, version), {
    jsonDocumentUrl: 'docs-json',
    swaggerOptions: { persistAuthorization: true },
  });
}
