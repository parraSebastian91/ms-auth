# 🔍 Guía de Debugging - Sistema de Permisos JWT

## ✅ Cambios Realizados

### 1. **AuthGuard Actualizado**
- ✅ Incluye `token` original en `request['user']`
- ✅ Soporta tanto `payload.rol` como `payload.roles`
- ✅ Soporta tanto `payload.permisos` como `payload.permissions`
- ✅ Fallback robusto para diferentes estructuras de JWT

### 2. **PermissionsGuard Actualizado**
- ✅ Extrae token del header Authorization
- ✅ Decodifica JWT para obtener roles y permisos
- ✅ Soporte híbrido: token + base de datos
- ✅ Logs detallados para debugging

### 3. **Estructura del Token JWT**
Según tu AuthService, el token contiene:
```json
{
  "id": "usuario_id",
  "username": "nombre_usuario",
  "rol": ["ADMIN", "USER"],           // Códigos de roles
  "permisos": ["USR_VIEW", "USR_CREATE"] // Códigos de permisos
}
```

## 🧪 Testing con Postman

### Pre-request Script Actualizado para Debugging

```javascript
// Pre-request Script con Debug
const loginUrl = pm.globals.get("baseUrl") + "/auth/login";
const username = pm.globals.get("username") || "tu_usuario";
const password = pm.globals.get("password") || "tu_password";

console.log("🔐 Iniciando login...");
console.log("URL:", loginUrl);
console.log("Usuario:", username);

const loginRequest = {
    url: loginUrl,
    method: 'POST',
    header: {
        'Content-Type': 'application/json',
    },
    body: {
        mode: 'raw',
        raw: JSON.stringify({
            username: username,
            password: password,
            typeDevice: "postman"
        })
    }
};

pm.sendRequest(loginRequest, function (err, response) {
    if (err) {
        console.error("❌ Error en login:", err);
        return;
    }

    console.log("📊 Status de login:", response.status);
    
    if (response.status === 200) {
        const responseJson = response.json();
        console.log("📄 Respuesta completa:", JSON.stringify(responseJson, null, 2));
        
        if (responseJson.data && responseJson.data.access_token) {
            const token = responseJson.data.access_token;
            pm.globals.set("access_token", token);
            
            // Decodificar token para ver contenido (solo para debug)
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                console.log("🎫 Payload del token:", JSON.stringify(payload, null, 2));
                console.log("👥 Roles:", payload.rol || payload.roles);
                console.log("🔑 Permisos:", payload.permisos || payload.permissions);
            } catch (e) {
                console.log("⚠️ No se pudo decodificar el token");
            }
            
            console.log("✅ Login exitoso - Token guardado");
        } else {
            console.error("❌ Estructura de respuesta inesperada:", responseJson);
        }
    } else {
        console.error("❌ Login falló:", response.status, response.text());
    }
});
```

### Variables de Entorno Requeridas
```
baseUrl = http://localhost:3001
username = tu_usuario_real
password = tu_password_real
```

## 🔍 Debugging en Servidor

### Console Logs Agregados
El `PermissionsGuard` ahora incluye logs detallados:

```bash
# Logs que verás en la consola del servidor:
Token payload: { id: "123", username: "admin", rol: ["ADMIN"], permisos: ["USR_VIEW", "USR_CREATE"] }
Roles del token (códigos): ["ADMIN"]
Permisos del token (códigos): ["USR_VIEW", "USR_CREATE"]
Usando roles y permisos del token
```

### Ejemplo de Request Exitoso
```bash
POST /usuario
Authorization: Bearer eyJ0eXAiOiJKV1Q...

# En el servidor verás:
Token payload: { id: "123", username: "admin", rol: ["ADMIN"], permisos: ["USR_CREATE"] }
Roles del token (códigos): ["ADMIN"]  
Permisos del token (códigos): ["USR_CREATE"]
✅ Permiso USR_CREATE encontrado - Acceso permitido
```

### Ejemplo de Request Denegado
```bash
GET /usuario
Authorization: Bearer eyJ0eXAiOiJKV1Q...

# En el servidor verás:
Token payload: { id: "456", username: "user", rol: ["USER"], permisos: ["USR_READ"] }
Roles del token (códigos): ["USER"]
Permisos del token (códigos): ["USR_READ"]
❌ Error: Acceso denegado. Permisos requeridos: USR_VIEW, SYS_ADMIN
```

## 📋 Checklist de Testing

### ✅ Verificaciones Básicas
- [ ] El login funciona y devuelve access_token
- [ ] El token se decodifica correctamente
- [ ] Los roles aparecen en el payload como `rol` (array)
- [ ] Los permisos aparecen en el payload como `permisos` (array)

### ✅ Testing de Permisos
- [ ] Usuario con `USR_VIEW` puede hacer GET /usuario
- [ ] Usuario con `USR_CREATE` puede hacer POST /usuario  
- [ ] Usuario con `SYS_ADMIN` puede hacer cualquier operación
- [ ] Usuario sin permisos recibe 403 Forbidden

### ✅ Testing de Fallback BD
- [ ] Si token no tiene roles/permisos, consulta BD
- [ ] Logs muestran "consultando BD..."
- [ ] Funciona correctamente con datos de BD

## 🚨 Troubleshooting

### Token No Se Decodifica
```bash
# Si ves este error:
Token no válido

# Verificar:
1. Token tiene formato JWT válido (3 partes separadas por .)
2. Token no está expirado
3. Secret de JWT es correcto
```

### Permisos No Se Encuentran
```bash
# Si ves:
Acceso denegado. Permisos requeridos: USR_VIEW

# Verificar:
1. Token contiene permisos correctos
2. Nombres de permisos coinciden exactamente
3. Usuario tiene roles con permisos asignados
```

### Fallback a BD No Funciona
```bash
# Si ves:
Usuario no encontrado o sin roles asignados

# Verificar:
1. userId del token es válido
2. Usuario existe en BD
3. Usuario tiene roles asignados
4. Roles tienen permisos asignados
```

## 📊 Estructura Esperada en BD

```sql
-- Asegúrate de que tus datos tengan esta estructura:
usuario: { id, userName, rol: [array_de_roles] }
rol: { nombre, codigo, permisos: [array_de_permisos] }
permiso: { nombre, codigo }
```

El sistema está listo para funcionar con roles y permisos tanto desde el JWT como desde la base de datos! 🚀