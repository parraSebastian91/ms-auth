# 🐳 Dockerización de ms-auth

Esta guía explica cómo ejecutar la aplicación NestJS con Docker y Docker Compose.

## 📋 Prerrequisitos

- Docker >= 20.10.0
- Docker Compose >= 2.0.0

# 🐳 Dockerización de ms-auth

Esta guía explica cómo ejecutar solo la aplicación NestJS con Docker, conectándose a PostgreSQL y Redis externos.

## 📋 Prerrequisitos

- Docker >= 20.10.0
- Docker Compose >= 2.0.0
- PostgreSQL ejecutándose externamente (puerto 5432)
- Redis ejecutándose externamente (puerto 6379)

## 🏗️ Arquitectura

Esta dockerización solo incluye:

- **ms-auth**: Aplicación NestJS (Puerto 3000)

Se conecta a servicios externos:
- **PostgreSQL**: Base de datos externa (Puerto 5432)
- **Redis**: Cache y sesiones externo (Puerto 6379)

## 🚀 Inicio Rápido

### Desarrollo

```bash
# Construir la imagen
./docker-build.sh

# Iniciar en modo desarrollo (con hot-reload)
./docker-dev.sh

# Ver logs en tiempo real
docker-compose logs -f ms-auth
```

### Producción

```bash
# Configurar variables de entorno
cp .env.prod .env.production
# Editar .env.production con valores seguros

# Iniciar en modo producción
./docker-prod.sh

# Ver logs
docker-compose -f docker-compose.prod.yml logs -f ms-auth
```

## 📂 Archivos de Configuración

### Desarrollo
- `docker-compose.yml`: Solo la aplicación ms-auth
- `.env.dev`: Variables de entorno para desarrollo

### Producción
- `docker-compose.prod.yml`: Aplicación optimizada para producción
- `.env.prod`: Variables de entorno para producción

## 🔧 Variables de Entorno

### Para desarrollo (`.env.dev`):
```bash
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=desarrollo
DATABASE_PASSWORD=071127
DATABASE_NAME=core_erp
REDIS_HOST=localhost
REDIS_PORT=6379
JWT_SECRET=tu_clave_secreta_desarrollo
```

### Para producción (`.env.prod`):
```bash
# CAMBIAR ESTOS VALORES EN PRODUCCIÓN
DATABASE_HOST=localhost
DATABASE_PASSWORD=TuPasswordSeguraAqui123!
JWT_SECRET=tu_clave_jwt_super_secreta_y_larga_para_produccion_2024
```

## 🔌 Conexión a Servicios Externos

Tu aplicación ms-auth puede conectarse a PostgreSQL y Redis de varias maneras:

### **Opción 1: Red compartida (recomendada para contenedores)**

1. **Crear red compartida**:
```bash
docker network create shared_erp_network
```

2. **Conectar tus contenedores existentes**:
```bash
# Conectar PostgreSQL
docker network connect shared_erp_network nombre_contenedor_postgres

# Conectar Redis  
docker network connect shared_erp_network nombre_contenedor_redis
```

3. **Usar script automático**:
```bash
# Ver información de la red
./docker-network-utils.sh network-info

# Conectar automáticamente PostgreSQL
./docker-network-utils.sh connect-postgres

# Conectar automáticamente Redis
./docker-network-utils.sh connect-redis
```

4. **Configurar variables de entorno**:
```bash
# En .env.dev o .env.prod
DATABASE_HOST=nombre_contenedor_postgres
REDIS_HOST=nombre_contenedor_redis
```

### **Opción 2: Host networking**

Si PostgreSQL y Redis están en el host (no en contenedores):
```bash
# En .env.dev o .env.prod
DATABASE_HOST=localhost
REDIS_HOST=localhost
```

### **Opción 3: IP específica**

Si conoces las IPs específicas:
```bash
DATABASE_HOST=192.168.1.100
REDIS_HOST=192.168.1.101
```

## 🛠️ Comandos Útiles

### **Scripts de utilidad**

```bash
# Script completo de utilidades
./docker-app-utils.sh help          # Ver todos los comandos disponibles
./docker-app-utils.sh logs          # Ver últimos 50 logs
./docker-app-utils.sh logs-follow   # Seguir logs en tiempo real
./docker-app-utils.sh shell         # Entrar al contenedor
./docker-app-utils.sh status        # Ver estado y recursos
./docker-app-utils.sh health        # Probar health check
./docker-app-utils.sh restart       # Reiniciar aplicación
./docker-app-utils.sh env           # Ver variables de entorno

# Alias rápido (ms)
./ms logs      # Ver logs recientes
./ms follow    # Seguir logs en tiempo real
./ms shell     # Entrar al contenedor
./ms status    # Ver estado
./ms health    # Probar health check
./ms restart   # Reiniciar aplicación
```

### **Comandos Docker Compose nativos**

```bash
# Construir solo la aplicación
docker-compose build ms-auth

# Reconstruir sin cache
docker-compose build --no-cache ms-auth

# Ver estado de servicios
docker-compose ps

# Ejecutar comandos dentro del contenedor
docker-compose exec ms-auth npm run test

# Ver logs de la aplicación
docker-compose logs -f ms-auth

# Reiniciar la aplicación
docker-compose restart ms-auth

# Detener la aplicación
docker-compose down

# Entrar al contenedor
docker-compose exec ms-auth sh
```

## 🔍 Health Check

La aplicación incluye un endpoint de health check:

- **URL**: `http://localhost:3000/health`
- **Método**: GET
- **Respuesta**:
```json
{
  "status": "ok",
  "timestamp": "2025-09-29T...",
  "uptime": 123.45,
  "environment": "development"
}
```

## 🧹 Limpieza

```bash
# Limpiar contenedores, imágenes y cache
./docker-clean.sh
```

## 🔒 Seguridad en Producción

1. **Cambiar credenciales por defecto**:
   - `DATABASE_PASSWORD`
   - `JWT_SECRET`

2. **Usar variables de entorno seguras**:
   ```bash
   # Generar JWT secret seguro
   openssl rand -base64 64
   ```

3. **Limitar puertos expuestos** si es necesario

## 🐛 Troubleshooting

### Problema: No se puede conectar a PostgreSQL
```bash
# Verificar que PostgreSQL esté listo
docker exec ms_auth_postgres pg_isready -U desarrollo -d core_erp

# Ver logs de PostgreSQL
docker-compose logs postgres
```

### Problema: Aplicación no inicia
```bash
# Verificar logs de la aplicación
docker-compose logs ms-auth

# Rebuilder la imagen
docker-compose build --no-cache ms-auth
```

### Problema: Puerto en uso
```bash
# Cambiar puertos en docker-compose.yml
ports:
  - "3001:3000"  # Usar puerto 3001 en lugar de 3000
```

## 📊 Monitoreo

### Ver recursos utilizados
```bash
docker stats
```

### Ver espacio en disco
```bash
docker system df
```

### Inspeccionar contenedor
```bash
docker inspect ms_auth_app
```

## 🔄 Actualización

Para actualizar la aplicación:

1. Hacer pull de cambios
2. Reconstruir imagen: `./docker-build.sh`
3. Reiniciar servicios: `docker-compose restart ms-auth`

---

## 📝 Notas Importantes

- Los volúmenes persisten los datos entre reinicios
- El modo desarrollo incluye hot-reload automático
- El health check permite monitoreo automático
- Los logs están disponibles en tiempo real
