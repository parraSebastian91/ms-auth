# Guía de Uso de Guards y Sistema de Permisos en el Sistema ERP

## Descripción General

Este sistema implementa un sistema completo de autenticación y autorización basado en JWT utilizando NestJS Guards. El sistema soporta tres niveles de control de acceso:

1. **Autenticación**: Validación de tokens JWT
2. **Roles**: Control de acceso basado en roles de usuario  
3. **Permisos**: Control granular basado en permisos específicos asociados a roles

Los guards se aplican de forma global para asegurar todas las rutas del API, con excepciones específicas marcadas como públicas.

## Componentes Implementados

### 1. AuthGuard (`src/infrastructure/http-server/guards/auth.guard.ts`)

- **Propósito**: Valida tokens JWT y asegura que el usuario esté autenticado
- **Funcionalidad**:
  - Extrae el token del header Authorization (Bearer token)
  - Valida el token usando el servicio de autenticación
  - Agrega información básica del usuario al request
  - Permite rutas marcadas con `@Public()`

### 2. PermissionsGuard (`src/infrastructure/http-server/guards/permissions.guard.ts`)

- **Propósito**: Verifica permisos específicos y roles del usuario
- **Funcionalidad**:
  - Obtiene roles y permisos del usuario desde la base de datos
  - Valida permisos específicos con `@Permissions()`
  - Valida roles como fallback con `@Roles()`
  - Permite combinación de ambos decoradores
  - Agrega información completa del usuario al request

### 3. Decoradores

#### @Public() (`src/infrastructure/http-server/decorators/public.decorator.ts`)
- Marca rutas que no requieren autenticación
- Uso: `@Public()`

#### @Permissions() (`src/infrastructure/http-server/decorators/permissions.decorator.ts`)
- Especifica qué permisos específicos se requieren para acceder a una ruta
- **Soporte para múltiples permisos**: El usuario necesita tener **AL MENOS UNO** de los permisos especificados
- Uso: 
  - Un permiso: `@Permissions('usuario.crear')`
  - Múltiples permisos: `@Permissions('usuario.crear', 'admin.all', 'super.create')`

#### @Roles() (`src/infrastructure/http-server/decorators/roles.decorator.ts`)
- Especifica qué roles pueden acceder a una ruta (usado como fallback si no hay permisos específicos)
- Uso: `@Roles('admin', 'superuser', 'user')`

#### @CurrentUser() (`src/infrastructure/http-server/decorators/current-user.decorator.ts`)
- Inyecta la información del usuario autenticado como parámetro
- Uso: 
  - `@CurrentUser() user: CurrentUserData` - Obtiene toda la información del usuario
  - `@CurrentUser('userId') userId: string` - Obtiene solo el ID del usuario
  - `@CurrentUser('username') username: string` - Obtiene solo el nombre de usuario
  - `@CurrentUser('roles') roles: string[]` - Obtiene solo los roles del usuario
  - `@CurrentUser('permissions') permissions: string[]` - Obtiene solo los permisos del usuario

## Configuración Global

Los guards se configuran globalmente en `http-server.module.ts`:

```typescript
providers: [
  {
    provide: APP_GUARD,
    useClass: AuthGuard,
  },
  {
    provide: APP_GUARD,
    useClass: PermissionsGuard,
  },
]
```

Esto significa que **todas las rutas** requieren autenticación por defecto, a menos que se marque lo contrario.

## Jerarquía de Control de Acceso

El sistema utiliza una jerarquía de control de acceso:

1. **@Public()**: Anula todo control de acceso
2. **@Permissions()**: Control granular por permisos específicos (prioritario)
3. **@Roles()**: Control por roles (usado como fallback si no hay permisos)
4. **Sin decoradores**: Solo requiere autenticación

## Ejemplos de Uso

### 1. Rutas Públicas (sin autenticación)
```typescript
@Controller('auth')
@Public() // Todo el controlador es público
export class AuthController {
  
  @Post('login')
  async login() { ... }
}
```

### 2. Rutas con Solo Autenticación
```typescript
@Controller('profile')
export class ProfileController {
  
  @Get() // Solo requiere estar autenticado
  async getProfile() { ... }
}
```

### 3. Rutas con Permisos Específicos (Recomendado)
```typescript
@Controller('usuario')
export class UsuarioController {
  
  @Post()
  @Permissions('usuario.crear') // Un solo permiso
  async createUsuario() { ... }
  
  @Get()
  @Permissions('usuario.listar', 'admin.view', 'super.all') // Múltiples permisos (OR lógico)
  async getAllUsuarios() { ... }
  
  @Delete(':id')
  @Permissions('usuario.eliminar', 'admin.delete') // Usuario necesita UNO de estos
  async deleteUsuario() { ... }
}
```

### 4. Combinación de Múltiples Permisos y Roles
```typescript
@Controller('usuario')
export class UsuarioController {
  
  @Delete(':id')
  @Permissions('usuario.eliminar', 'admin.delete', 'super.all') // AL MENOS uno de estos permisos
  @Roles('admin', 'superuser') // Y AL MENOS uno de estos roles
  async deleteUsuario() { ... }
  
  @Get('/sensitive')
  @Permissions(
    'data.sensitive',
    'audit.read', 
    'security.officer',
    'super.admin'
  ) // Permisos muy específicos - necesita solo uno
  async getSensitiveData() { ... }
}
```

### 4. Rutas con Roles (Fallback)
```typescript
@Controller('admin')
export class AdminController {
  
  @Get()
  @Roles('admin', 'superuser') // Solo admin o superuser
  async getAdminData() { ... }
}
```

### 5. Combinación de Permisos y Roles
```typescript
@Controller('usuario')
export class UsuarioController {
  
  @Delete(':id')
  @Permissions('usuario.eliminar') // Debe tener el permiso específico
  @Roles('admin') // Y también el rol de admin
  async deleteUsuario() { ... }
}
```

### 6. Acceso a Información del Usuario
```typescript
@Controller('usuario')
export class UsuarioController {
  
  @Get('/me')
  async getCurrentUser(@CurrentUser() user: CurrentUserData) {
    // user contiene { userId, username, roles, permissions }
    console.log('Permisos del usuario:', user.permissions);
    return await this.service.findById(user.userId);
  }
  
  @Get('/profile')
  async getUserProfile(
    @CurrentUser('userId') userId: string,
    @CurrentUser('permissions') permissions: string[]
  ) {
    // Acceso granular a propiedades específicas
    return await this.service.findById(userId);
  }
}
```

## Lógica de Validación de Permisos

### Múltiples Permisos (@Permissions)
- **Lógica OR**: El usuario necesita tener **AL MENOS UNO** de los permisos especificados
- Ejemplo: `@Permissions('read', 'write', 'admin')` → Usuario necesita `read` OR `write` OR `admin`

### Múltiples Roles (@Roles)  
- **Lógica OR**: El usuario necesita tener **AL MENOS UNO** de los roles especificados
- Ejemplo: `@Roles('user', 'admin')` → Usuario necesita rol `user` OR `admin`

### Combinación de Decoradores
- **Lógica AND**: Si usas ambos decoradores, el usuario debe cumplir AMBAS condiciones
- Ejemplo: 
  ```typescript
  @Permissions('delete', 'admin.all')  // Necesita UNO de estos permisos
  @Roles('admin', 'superuser')         // Y UNO de estos roles
  ```

## Flujo de Autenticación

1. **Cliente** envía request con token en header: `Authorization: Bearer <token>`
2. **AuthGuard** extrae y valida el token
3. **RolesGuard** verifica permisos (si se especifican roles)
4. **Controlador** procesa el request con información del usuario disponible

## Información del Usuario en el Request

Una vez autenticado, la información del usuario está disponible en `request['user']`:

```typescript
{
  userId: string,
  username: string,
  roles: string[],
  permissions: string[]
}
```

## Estructura de Permisos Recomendada

Se recomienda usar una nomenclatura consistente para los permisos:

```
[recurso].[accion]

Ejemplos:
- usuario.crear
- usuario.ver  
- usuario.editar
- usuario.eliminar
- usuario.listar
- producto.crear
- producto.ver
- producto.editar
- producto.eliminar
- producto.listar
- orden.crear
- orden.ver
- orden.procesar
- orden.cancelar
```

## Manejo de Errores

- **401 Unauthorized**: Token inválido, expirado o ausente
- **403 Forbidden**: Usuario no tiene los roles/permisos necesarios

## Roles y Permisos del Sistema

### Roles Principales:
- `admin`: Administrador del sistema con permisos completos
- `superuser`: Superusuario con permisos elevados
- `user`: Usuario regular con permisos básicos
- `viewer`: Usuario solo lectura

### Ejemplos de Permisos por Módulo:
- **Usuarios**: `usuario.crear`, `usuario.ver`, `usuario.editar`, `usuario.eliminar`, `usuario.listar`
- **Contactos**: `contacto.crear`, `contacto.ver`, `contacto.editar`, `contacto.eliminar`, `contacto.listar`
- **Roles**: `rol.crear`, `rol.ver`, `rol.editar`, `rol.eliminar`, `rol.listar`

## Consideraciones de Seguridad

1. Los tokens JWT deben incluir información básica del usuario
2. Los roles se validan contra la base de datos en tiempo real
3. Las rutas públicas deben ser mínimas y bien definidas
4. Los tokens tienen tiempo de vida limitado y pueden ser renovados

## Testing

Para probar las rutas protegidas:

1. **Obtener token**:
   ```bash
   POST /auth/login
   {
     "username": "usuario",
     "password": "contraseña"
   }
   ```

2. **Usar token en requests**:
   ```bash
   GET /usuario
   Authorization: Bearer <token>
   ```

3. **Verificar permisos del usuario actual**:
   ```bash
   GET /usuario/me
   Authorization: Bearer <token>
   ```

## Configuración de Base de Datos

Para que el sistema funcione correctamente, asegúrate de que:

1. La tabla `rol` contenga roles válidos
2. La tabla `permisos` contenga permisos específicos  
3. La tabla de relación `rol_permisos` asocie correctamente roles con permisos
4. Los usuarios tengan roles asignados

### Ejemplo de datos iniciales:

```sql
-- Insertar permisos
INSERT INTO permisos (nombre, descripcion) VALUES 
('usuario.crear', 'Crear usuarios'),
('usuario.ver', 'Ver usuarios'),
('usuario.editar', 'Editar usuarios'),
('usuario.eliminar', 'Eliminar usuarios'),
('usuario.listar', 'Listar usuarios');

-- Insertar roles
INSERT INTO rol (nombre, descripcion) VALUES 
('admin', 'Administrador del sistema'),
('user', 'Usuario regular'),
('viewer', 'Solo lectura');

-- Asociar permisos a roles (ejemplo)
INSERT INTO rol_permisos (rol_id, permiso_id) VALUES 
(1, 1), (1, 2), (1, 3), (1, 4), (1, 5), -- Admin tiene todos los permisos
(2, 2), (2, 5), -- User puede ver y listar
(3, 2), (3, 5); -- Viewer solo puede ver y listar
```

## Mantenimiento

- Revisar regularmente los roles y permisos asignados en la base de datos
- Monitorear logs de autenticación fallida y accesos denegados
- Actualizar tokens de refresco según política de seguridad
- Auditar permisos de usuarios periódicamente
- Mantener nomenclatura consistente para nuevos permisos

## Mejores Prácticas

1. **Usar permisos granulares**: Prefiere `@Permissions()` sobre `@Roles()` para control más fino
2. **Nomenclatura consistente**: Usa el formato `[recurso].[accion]`
3. **Principio de menor privilegio**: Asigna solo los permisos mínimos necesarios
4. **Auditoría**: Registra accesos y cambios de permisos
5. **Separación de responsabilidades**: Un permiso por acción específica
6. **Documentación**: Mantén actualizada la lista de permisos y su propósito