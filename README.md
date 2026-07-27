# ms-auth - Microservicio de Autenticacion y Autorizacion

**Servicio:** ms-auth  
**Puerto:** 3000 (configurable via `PORT`)  
**Version:** 0.0.1  
**Ultima actualizacion:** 2026-07-26

---

## Proposito

Microservicio responsable de autenticacion, autorizacion, gestion de sesiones y registro de usuarios en SEIS_App. Maneja JWT tokens, refresh tokens, permisos basados en roles, y recuperacion de contraseñas.

---

## Arquitectura

```
Frontend → BFF (3002) → ms-auth (3000)
                            ↓
                   PostgreSQL + Redis + Vault
```

### Responsabilidades

- ✅ Autenticacion: Login/Logout
- ✅ Registro de usuarios y organizaciones
- ✅ Gestion de sesiones con Redis
- ✅ Refresh tokens (7 dias de validez)
- ✅ Recuperacion de contraseña (reset password)
- ✅ Validacion de permisos y roles
- ✅ Guards JWT para proteger endpoints

---

## Stack Tecnologico

- **Framework:** NestJS 10 + TypeScript
- **Base de datos:** PostgreSQL (usuarios, roles, permisos, sesiones)
- **Cache:** Redis (sesiones activas, refresh tokens)
- **Secrets:** Vault (JWT_SECRET, DB credentials)
- **Autenticacion:** JWT (access token) + Refresh Token (cookie HttpOnly)
- **Hashing:** bcrypt para passwords

---

## Controllers (3 Endpoints Groups)

### 1. Health Check (`/health`)
**Controller:** `health.controller.ts`  
**Auth:** Publica

- `GET /health` - Estado del servicio

---

### 2. Autenticacion (`/security`)
**Controller:** `auth.controller.ts`  
**Auth:** Publica (excepto endpoints protegidos)

#### Endpoints Publicos

**Login**
- `POST /security/login`
  - Body: `{ username, password }`
  - Response: JWT access token + refresh token en cookie `auth.refresh`
  - Cookie `auth.session` firmada (7 dias)

**Logout**
- `POST /security/logout`
  - Invalida sesion en Redis
  - Limpia cookies

**Refresh Session**
- `POST /security/session/refresh`
  - Body: `{ typeDevice: string }`
  - Lee refresh token desde cookie `auth.refresh`
  - Genera nuevo access token si refresh valido
  - Response: Nuevo JWT

**Password Reset**
- `POST /security/password/request`
  - Body: `{ email }`
  - Envia email con token de reset
- `POST /security/password/validate-token`
  - Body: `{ token }`
  - Valida token de reset
- `POST /security/password/reset`
  - Body: `{ token, newPassword }`
  - Resetea password con token valido

#### Endpoints Protegidos

**Authorization Check**
- `POST /security/authorization`
  - Body: `{ userId, resource, action }`
  - Valida si el usuario tiene permisos para ejecutar accion en recurso

**Test Session**
- `ALL /security/session/test`
  - Endpoint de debugging para verificar cookies y sesion

---

### 3. Registro (`/registro`)
**Controller:** `registro.controller.ts`  
**Auth:** Publica

**Registro de Usuario + Organizacion**
- `POST /registro`
  - Body: Datos de usuario y organizacion
  - Crea usuario, organizacion y asigna roles iniciales
  - Response: Confirmacion de registro

---

## Use Cases

### AuthUseCase (IAuthUseCase)

**Comandos:**
- `ExecuteAuthentication(AuthenticationCommand)` - Login de usuario
- `ExecuteRefreshSession(refreshSessionCommand)` - Renovar access token
- `ExecuteAuthorization(authorizationCommand)` - Validar permisos
- `ExecuteRequestPasswordReset(RequestPasswordResetCommand)` - Solicitar reset
- `ExecuteValidateResetToken(validateResetTokenCommand)` - Validar token reset
- `ExecuteResetPassword(ResetPasswordCommand)` - Resetear password

### RegistroUseCase (IRegistroUseCase)

**Comandos:**
- `ExecuteRegistro(RegistroCommand)` - Registrar usuario + organizacion

---

## Autenticacion y Sesiones

### Flujo de Login

1. Usuario envia `POST /security/login` con username/password
2. ms-auth valida credenciales contra PostgreSQL
3. Si valido:
   - Genera JWT access token (15-30 min expiracion)
   - Genera refresh token (7 dias)
   - Guarda sesion en Redis con datos de usuario
   - Setea cookies:
     - `auth.session` (firmada, HttpOnly, 7 dias)
     - `auth.refresh` (HttpOnly, 7 dias)
4. Response con JWT en body

### Flujo de Refresh

1. Cliente detecta access token expirado
2. Envia `POST /security/session/refresh` con refresh token en cookie
3. ms-auth valida refresh token en Redis
4. Si valido, genera nuevo access token
5. Response con nuevo JWT

### Sesiones en Redis

**Key pattern:** `session:{sessionId}`

**Contenido:**
```json
{
  "userId": "uuid",
  "username": "usuario@example.com",
  "roles": ["USR_STD", "CLIENTE_CEDENTE"],
  "organizacionId": "uuid",
  "authenticated": true,
  "accessToken": "jwt...",
  "refreshToken": "token...",
  "expiresAt": 1721980800
}
```

**TTL:** 7 dias (REFRESH_COOKIE_MAX_AGE_MS)

---

## Roles y Permisos

### Roles Disponibles

| Rol | Descripcion |
|-----|-------------|
| `USR_STD` | Usuario autenticado base |
| `CLIENTE_CEDENTE` | Empresa emisora de facturas |
| `ADMIN_CEDENTE` | Administrador de empresa cedente |
| `EJECUTIVO_FINANCIADORA` | Ejecutiva de factoring |
| `ADMIN_FINANCIADORA` | Administrador de financiadora |
| `SUPER_ADMIN` | Acceso total al sistema |

### Guards

**JwtAuthGuard:** Valida JWT en header `Authorization: Bearer <token>`

**PermissionsGuard:** Valida permisos granulares (resource + action)

**Decoradores:**
- `@Public()` - Endpoint publico sin autenticacion
- `@Roles(...roles)` - Requiere uno de los roles especificados

---

## Variables de Entorno

### Vault (Preloaded)

Paths leidos en bootstrap: `JWT`, `DB-SEIS-POSTGRES`, `REDIS`, `SHARED`

```bash
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=myroot
```

### Servicio

```bash
PORT=3000
NODE_ENV=production|development
JWT_SECRET=<leido desde Vault>
JWT_EXPIRES_IN=30m
REFRESH_TOKEN_EXPIRES_IN=7d
```

### Base de Datos (desde Vault)

```bash
DB_HOST=postgres
DB_PORT=5432
DB_USERNAME=seis_user
DB_PASSWORD=<desde Vault>
DB_DATABASE=seis_erp
```

### Redis (desde Vault)

```bash
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=<desde Vault>
```

---

## Estructura de Directorios

```
src/
├── main.ts                          # Bootstrap + Vault
├── app.module.ts                    # Modulo raiz
├── core/
│   ├── core.module.ts
│   ├── aplication/
│   │   └── useCase/
│   │       ├── auth/
│   │       │   ├── auth.usecase.ts          # AuthUseCase implementacion
│   │       │   └── command/                 # Commands (AuthenticationCommand, etc.)
│   │       └── registro/
│   │           └── registro.usecase.impl.ts # RegistroUseCase implementacion
│   └── domain/
│       ├── entities/                        # Usuario, Rol, Permiso
│       ├── repositories/                    # Interfaces de repositorios
│       └── puertos/
│           ├── inbound/                     # IAuthUseCase, IRegistroUseCase
│           └── outbound/                    # IUserRepository, ISessionRepository
└── infrastructure/
    ├── http/
    │   ├── controllers/                     # auth, registro, health
    │   ├── model/dto/                       # DTOs (LoginDto, RegistroDto, etc.)
    │   ├── decorators/                      # @Public(), @Roles()
    │   └── guards/                          # JwtAuthGuard, PermissionsGuard
    ├── persistence/
    │   ├── typeorm/                         # Repositorios TypeORM
    │   └── redis/                           # Sesiones Redis
    └── exceptionFileter/
        └── CoreException.filter.ts          # Exception filter
```

---

## Dependencias Criticas

- **PostgreSQL:** Si cae, no hay login ni validacion de credenciales
- **Redis:** Si cae, no hay sesiones (todas las sesiones activas se pierden)
- **Vault:** Si no esta en startup, el servicio no arranca (sin JWT_SECRET)

---

## Desarrollo

### Instalar dependencias

```bash
npm install
```

### Iniciar en desarrollo

```bash
npm run start:dev
```

### Build

```bash
npm run build
```

### Testing

```bash
npm run test          # Unit tests
npm run test:e2e      # E2E tests
npm run test:cov      # Coverage
```

---

## Docker

### Build

```bash
docker build -t ms-auth:latest .
```

### Logs

```bash
docker logs ms-auth -f
```

---

## Healthcheck

```bash
curl http://localhost:3000/health
```

Respuesta esperada:

```json
{
  "status": "ok",
  "timestamp": "2026-07-26T12:00:00.000Z"
}
```

---

## Integracion con BFF

El BFF (puerto 3002) consume ms-auth via HTTP para:

1. **Validar sesiones:** BFF envia `sessionId` desde cookie, ms-auth valida contra Redis
2. **Refresh tokens:** BFF proxy requests de `/security/session/refresh` a ms-auth
3. **Autorizacion:** BFF valida permisos antes de llamar a ms-core

**Patron:**
- BFF duplica `JwtAuthGuard` para validar JWT localmente (evita llamadas innecesarias)
- BFF llama a ms-auth solo para operaciones de escritura (login, logout, refresh)

---

## Seguridad

### Password Storage

- **Hashing:** bcrypt con salt rounds 10
- **Nunca** se almacena password en plain text
- **Nunca** se retorna password en responses

### JWT

- **Access Token:** Expira en 30 minutos (configurable)
- **Refresh Token:** Expira en 7 dias, almacenado en Redis
- **Secret:** Rotable via Vault

### Cookies

- **HttpOnly:** JavaScript no puede acceder
- **Secure:** Solo HTTPS en produccion
- **SameSite:** `lax` para prevenir CSRF

### Rate Limiting

⚠️ **Pendiente implementar:** Throttling de login attempts por IP/usuario

---

## Logs y Debugging

### Logs de NestJS

Cada request incluye:
- `[LOGIN]`, `[SESSION_REFRESH]`, `[LOGOUT]` prefijos
- `requestId` para trazabilidad
- `sessionId` para debugging de sesiones

### Ejemplo de log exitoso

```
[LOGIN] INIT requestId=abc123 ip=192.168.1.100
[LOGIN] SUCCESS requestId=abc123 userId=uuid-456 sessionId=sess-789
```

### Ejemplo de log fallido

```
[LOGIN] INVALID_CREDENTIALS requestId=abc123 username=user@example.com
```

---

## Troubleshooting

### Login falla con 401

1. Verificar credenciales en PostgreSQL
2. Revisar logs: `docker logs ms-auth -f`
3. Verificar Redis: `redis-cli ping`
4. Validar JWT_SECRET en Vault

### Refresh token no funciona

1. Verificar cookie `auth.refresh` en browser DevTools
2. Revisar sesion en Redis: `redis-cli get session:<sessionId>`
3. Verificar TTL: `redis-cli ttl session:<sessionId>`

### Sesiones se pierden aleatoriamente

1. Revisar memoria Redis: `redis-cli info memory`
2. Verificar eviction policy: `redis-cli config get maxmemory-policy`
3. Revisar logs de Redis por evictions

---

## Roadmap / Pendiente

- [ ] Rate limiting en `/security/login` (max 5 intentos por minuto por IP)
- [ ] OAuth2 / SSO con proveedores externos (Google, Microsoft)
- [ ] Multi-factor authentication (MFA)
- [ ] Auditoria de accesos (logs de login/logout a tabla audit)
- [ ] Rotacion automatica de refresh tokens
- [ ] Endpoint para revocar sesiones activas
- [ ] Metricas Prometheus (logins/min, refresh/min, login failures)

---

## Referencias

- **MONOREPO_ARCHITECTURE.md** - Arquitectura completa
- **CLAUDE.md** - ADN del proyecto
- **Guards:** BFF tambien implementa JwtAuthGuard (sin SPOF)
- **Graphify:** ~/Documents/Proyectos/SEIS_APP/graphify-out/graph.json

---

## Contacto / Contribucion

Este servicio es parte del monorepo SEIS_App. Para cambios:

1. Seguir Clean Architecture: dominio → aplicacion → infraestructura
2. Nunca exponer passwords en logs o responses
3. JWT secret solo via Vault
4. Guards duplicados en BFF (no hay SPOF)
5. Actualizar CLAUDE.md si haces cambios arquitectonicos

---

**Ultima actualizacion:** 2026-07-26  
**Maintainer:** Sebastian Parra (@parraSebastian91)
