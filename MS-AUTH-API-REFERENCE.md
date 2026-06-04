# ms-auth — Referencia Técnica de Endpoints para Agente IA

> Servicio: `ms-auth` | Puerto: `3000` (configurable vía `PORT`)
> Última actualización: 2026-06-03

---

## Arquitectura de Autenticación

ms-auth implementa un flujo **PKCE (Proof Key for Code Exchange)** con sesiones almacenadas en Redis. No expone tokens JWT directamente al cliente — los gestiona internamente y los mapea a una `sessionId` de express-session.

### Cookies emitidas por este servicio

| Cookie | Scope | Duración | Descripción |
|---|---|---|---|
| `auth.session` | HttpOnly, SameSite=lax | 1 hora (TTL Redis: 3600s) | ID de sesión express-session vinculado a tokens internos |
| `auth.refresh` | HttpOnly, SameSite=lax, Secure en HTTPS | 7 días | Refresh token para renovar la sesión |

### Almacén de sesiones
- **Backend:** Redis con prefijo `sess:`
- **Secret:** `SECRET_SESSION` (Vault path: `secret/data/SHARED`)
- La sesión contiene: `authenticated: boolean`, `accessToken: string`

---

## Envolvente de Respuesta Estándar (`ApiResponse<T>`)

```json
{
  "status": 200,
  "message": "Descripción del resultado",
  "data": { }
}
```

> **Excepción:** los endpoints `/health/*` y `/security/password-reset/*` retornan directamente el objeto del use case sin envolver.

---

## Endpoints

---

### 1. Health — `/health` (público)

#### `GET /health`

Health check completo vía `@nestjs/terminus`. Verifica 5 indicadores.

**Auth:** Ninguna.

**Respuesta `200`:**

```json
{
  "status": "ok",
  "info": {
    "database":    { "status": "up" },
    "memory_heap": { "status": "up" },
    "memory_rss":  { "status": "up" },
    "storage":     { "status": "up" },
    "vault":       { "status": "up" }
  },
  "error": {},
  "details": {
    "database":    { "status": "up" },
    "memory_heap": { "status": "up" },
    "memory_rss":  { "status": "up" },
    "storage":     { "status": "up" },
    "vault":       { "status": "up" }
  }
}
```

**Umbrales configurados:**

| Indicador | Umbral |
|---|---|
| `memory_heap` | Heap ≤ 150 MB |
| `memory_rss` | RSS ≤ 300 MB |
| `storage` | Disco ≤ 90% usado |

---

#### `GET /health/ready`

Readiness probe para orquestadores.

**Auth:** Ninguna.

**Respuesta `200`:**
```json
{
  "status": "ok",
  "timestamp": "2026-06-03T12:00:00.000Z",
  "service": "auth-service",
  "version": "1.0.0"
}
```

---

#### `GET /health/live`

Liveness probe con métricas de proceso.

**Auth:** Ninguna.

**Respuesta `200`:**
```json
{
  "status": "alive",
  "uptime": 3600.123,
  "memory": {
    "rss": 52428800,
    "heapTotal": 30408704,
    "heapUsed": 22020096,
    "external": 1234567,
    "arrayBuffers": 123456
  }
}
```

---

### 2. Seguridad / Auth — `/security` (todos públicos)

> Todas las rutas bajo `/security` tienen el decorador `@Public()` — no requieren sesión activa previa.

---

#### `POST /security/authenticate`

**Paso 1 del flujo PKCE.** Valida credenciales y retorna las URLs de redirección para completar el flujo de autorización.

**Headers:**

| Header | Requerido | Descripción |
|---|---|---|
| `Content-Type: application/json` | Sí | |
| `x-request-id: <uuid>` | Recomendado | Trazabilidad |

**Body (`application/json`):**

```json
{
  "username": "john.doe",
  "password": "contraseña_segura",
  "code_challenge": "base64url_sha256_del_code_verifier",
  "typeDevice": "WEB",
  "sessionId": "opcional-session-id"
}
```

| Campo | Tipo | Requerido | Validación |
|---|---|---|---|
| `username` | `string` | Sí | NotEmpty |
| `password` | `string` | Sí | NotEmpty |
| `code_challenge` | `string` | Sí | NotEmpty — hash PKCE S256 |
| `typeDevice` | `DeviceType` | Sí | Enum: `WEB`, `DESKTOP`, `MOBILE`, `POSTMAN` |
| `sessionId` | `string` | No | ID de sesión pre-existente (opcional) |

**Respuesta `200`:** `ApiResponse<string[]>` — lista de URLs de redirección

```json
{
  "status": 200,
  "message": "Login exitoso",
  "data": [
    "https://auth.seis.cl/authorize?code=ABC&state=XYZ"
  ]
}
```

**Respuesta `401`:**
```json
{
  "status": 401,
  "message": "Credenciales inválidas",
  "data": null
}
```

---

#### `POST /security/callback`

**Paso 2 del flujo PKCE.** Intercambia el `code` de autorización por tokens. Crea la sesión autenticada y establece las cookies `auth.session` y `auth.refresh`.

**Body (`application/json`):**

```json
{
  "code": "codigo_autorizacion_pkce",
  "codeVerifier": "codigo_verifier_original",
  "typeDevice": "WEB"
}
```

| Campo | Tipo | Requerido | Validación |
|---|---|---|---|
| `code` | `string` | Sí | NotEmpty — código emitido en paso 1 |
| `codeVerifier` | `string` | Sí | NotEmpty — verifier PKCE original |
| `typeDevice` | `DeviceType` | Sí | Enum: `WEB`, `DESKTOP`, `MOBILE`, `POSTMAN` |

**Respuesta `200` + cookies:**

```http
Set-Cookie: auth.session=s%3A<sessionId>.<firma>; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600
Set-Cookie: auth.refresh=<refreshToken>; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800
```

```json
{
  "status": 200,
  "message": "Callback exitoso",
  "data": { "message": "Autenticación exitosa" }
}
```

**Respuesta `401`:**
```json
{
  "status": 401,
  "message": "Token inválido o expirado",
  "data": null
}
```

> **Nota para el Agente IA:** Después de este endpoint el agente debe capturar y persistir ambas cookies para usarlas en llamadas subsiguientes al BFF.

---

#### `POST /security/session/refresh`

Renueva la sesión activa usando el `auth.refresh` cookie. Emite un nuevo `auth.refresh`.

**Requiere:** Cookie `auth.refresh` presente en la request.

**Body (`application/json`):**

```json
{
  "typeDevice": "WEB"
}
```

| Campo | Tipo | Requerido | Descripción |
|---|---|---|---|
| `typeDevice` | `string` | Sí | Tipo de dispositivo del cliente |

**Respuesta `200` + nueva cookie `auth.refresh`:**

```http
Set-Cookie: auth.refresh=<nuevoRefreshToken>; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800
```

```json
{ "message": "Session test successful" }
```

> Nota: la respuesta no usa `ApiResponse` — retorna directamente el objeto plano.

**Respuesta `401`:**
```json
{
  "status": 401,
  "message": "Token inválido o expirado",
  "data": null
}
```

---

#### `GET /security/logout`

Destruye la sesión activa, invalida tokens y limpia ambas cookies.

**Requiere:** Cookie `auth.session` activa.

**Cookies eliminadas:**
- `auth.refresh` (maxAge=0)
- `auth.session` (cleared)

**Respuesta `200`:**
```json
{
  "status": 200,
  "message": "Logout exitoso",
  "data": null
}
```

**Respuesta `500`** (si falla la destrucción de sesión):
```json
{
  "status": 500,
  "message": "Error durante logout",
  "data": null
}
```

---

#### `ALL /security/session/test`

Endpoint de diagnóstico. Acepta cualquier método HTTP. Retorna confirmación de que las cookies están presentes.

**Auth:** Ninguna.

**Respuesta `200`:**
```json
{ "message": "Session test successful" }
```

> Solo para debugging. No usar en flujos de producción del agente.

---

### 3. Recuperación de Contraseña

Todos los endpoints de esta sección son **públicos** (`@Public()`).

---

#### `POST /security/password-reset/request`

Inicia el flujo de recuperación de contraseña. Envía un correo con el token de reset.

**Body (`application/json`):**

```json
{
  "correo": "usuario@empresa.cl"
}
```

| Campo | Tipo | Validación |
|---|---|---|
| `correo` | `string` | `@IsEmail()`, NotEmpty |

**Respuesta `200`:** (esquema definido por `IAuthUseCase.ExecuteRequestPasswordRequest`)

> El agente no debe inspeccionar esta respuesta — solo confirmar el código HTTP 200/201.

---

#### `GET /security/password-reset/validate`

Valida que el token de reset sea válido y no haya expirado.

**Query params:**

| Param | Tipo | Requerido | Descripción |
|---|---|---|---|
| `token` | `string` | Sí | Token de recuperación recibido por email |
| `uuid` | `string` | Sí | UUID del registro de reset |

**Ejemplo:**
```
GET /security/password-reset/validate?token=abc123&uuid=uuid-del-registro
```

**Respuesta `200`:**
```json
{
  "valid": true
}
```

| Campo | Tipo | Descripción |
|---|---|---|
| `valid` | `boolean` | `true` si el token es válido y no expiró |

---

#### `POST /security/password-reset/reset`

Ejecuta el cambio de contraseña usando el token válido.

**Body (`application/json`):**

```json
{
  "token": "token_de_recuperacion",
  "uuid": "uuid-del-registro",
  "newPassword": "NuevaContraseña123!",
  "confirmPassword": "NuevaContraseña123!"
}
```

| Campo | Tipo | Validación |
|---|---|---|
| `token` | `string` | NotEmpty |
| `uuid` | `string` | NotEmpty |
| `newPassword` | `string` | MinLength: 8, NotEmpty |
| `confirmPassword` | `string` | MinLength: 8, NotEmpty — debe coincidir con `newPassword` |

**Respuesta `200`:** confirmación del cambio (esquema interno del use case).

---

## Flujo Completo de Autenticación (PKCE)

```
1. Cliente genera:
   code_verifier = random(43-128 chars)
   code_challenge = base64url(sha256(code_verifier))

2. POST /security/authenticate
   Body: { username, password, code_challenge, typeDevice }
   ← Respuesta: { data: [redirect_url] }

3. POST /security/callback
   Body: { code: <extraído de redirect_url>, codeVerifier, typeDevice }
   ← Cookies: auth.session + auth.refresh
   ← Body: { message: "Autenticación exitosa" }

4. Todas las llamadas al BFF usan la cookie auth.session

5. Cuando auth.session expira:
   POST /security/session/refresh
   Cookie: auth.refresh=<token>
   Body: { typeDevice }
   ← Nueva cookie: auth.refresh

6. Logout:
   GET /security/logout
   ← Cookies eliminadas
```

---

## Tabla Resumen de Endpoints

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| `GET` | `/health` | No | Health check completo (DB + memoria + disco + vault) |
| `GET` | `/health/ready` | No | Readiness probe |
| `GET` | `/health/live` | No | Liveness probe + métricas de proceso |
| `ALL` | `/security/session/test` | No | Diagnóstico de cookies (dev only) |
| `POST` | `/security/authenticate` | No | Paso 1 PKCE: validar credenciales |
| `POST` | `/security/callback` | No | Paso 2 PKCE: canjear code → sesión + cookies |
| `POST` | `/security/session/refresh` | Cookie `auth.refresh` | Renovar sesión expirada |
| `GET` | `/security/logout` | Cookie `auth.session` | Destruir sesión y limpiar cookies |
| `POST` | `/security/password-reset/request` | No | Solicitar email de recuperación |
| `GET` | `/security/password-reset/validate` | No | Validar token de recuperación |
| `POST` | `/security/password-reset/reset` | No | Ejecutar cambio de contraseña |

---

## Errores Comunes

| HTTP | Causa típica |
|---|---|
| `400 Bad Request` | Fallo de validación (campo faltante, formato inválido, `typeDevice` fuera de enum) |
| `401 Unauthorized` | Credenciales inválidas / token expirado / cookie ausente |
| `500 Internal Server Error` | Fallo al destruir sesión en Redis / error de conexión con Vault o DB |

---

## Notas para el Agente IA

1. **PKCE obligatorio** — no hay endpoint de login simple. Siempre generar `code_verifier` + `code_challenge` antes de `POST /security/authenticate`.
2. **Gestión de cookies** — el agente debe persistir `auth.session` y `auth.refresh` entre llamadas. Ambas son HttpOnly y no accesibles por JS.
3. **Sesión dura 1 hora** — implementar renovación proactiva con `POST /security/session/refresh` antes del vencimiento, usando `auth.refresh` (válido 7 días).
4. **El BFF valida la sesión** — ms-auth emite la sesión, el BFF la verifica. El agente nunca llama a ms-auth directamente para recursos de negocio.
5. **`x-request-id`** en headers permite correlacionar logs entre ms-auth y BFF para debugging.
6. **DeviceType** debe ser consistente en todos los pasos del flujo PKCE — usar `WEB` para agentes basados en HTTP.
