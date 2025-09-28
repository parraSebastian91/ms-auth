# 🚀 Guía de Configuración del Entorno de Desarrollo ERP

## 📋 Requisitos Previos

- Ubuntu/Debian Linux (o distribución compatible)
- Conexión a Internet
- Permisos de sudo

## 🔧 Instalación Automática

### 1. Ejecutar Script de Configuración

```bash
chmod +x setup-environment.sh
./setup-environment.sh
```

### 2. Reiniciar Sesión (Recomendado)

Para aplicar los permisos de Docker correctamente:

```bash
# Opción 1: Reiniciar sesión completa
logout

# Opción 2: Activar grupo en sesión actual
newgrp docker
```

## 🚦 Comandos Útiles

### Gestión de Servicios

```bash
# Iniciar servicios de desarrollo
./start-services.sh

# Detener servicios
./stop-services.sh

# Verificar estado del entorno
./check-environment.sh

# Resetear base de datos
./reset-database.sh
```

### Comandos Docker Directos

```bash
# Iniciar contenedores
docker compose up -d

# Ver estado
docker compose ps

# Ver logs
docker compose logs -f postgres

# Acceder a PostgreSQL
docker compose exec postgres psql -U desarrollo -d core_erp

# Detener contenedores
docker compose down
```

### Desarrollo

```bash
# Instalar dependencias
npm install

# Iniciar aplicación en desarrollo
npm start

# Ejecutar en modo watch
npm run start:dev

# Ejecutar tests
npm test
```

## 🗂️ Estructura de Archivos Generados

```
.
├── .env                    # Variables de entorno
├── docker-compose.yml      # Configuración de contenedores
├── init-db/
│   └── 01-init.sql        # Script de inicialización de BD
├── start-services.sh       # Script para iniciar servicios
├── stop-services.sh        # Script para detener servicios
├── reset-database.sh       # Script para resetear BD
├── check-environment.sh    # Script de verificación
├── setup-environment.sh    # Script de instalación
└── SETUP-GUIDE.md         # Esta guía
```

## 🔗 Puertos Utilizados

- **3001**: Aplicación NestJS
- **5432**: PostgreSQL
- **6379**: Redis

## 🐛 Solución de Problemas

### Error de permisos con Docker

```bash
sudo usermod -aG docker $USER
newgrp docker
```

### Puertos ocupados

```bash
# Verificar qué proceso usa el puerto
sudo lsof -i :5432
sudo lsof -i :6379

# Detener contenedores que usen los puertos
docker compose down
```

### Resetear completamente el entorno

```bash
./stop-services.sh
docker system prune -a
./reset-database.sh
```

## 📚 Variables de Entorno Importantes

| Variable | Descripción | Valor por Defecto |
|----------|-------------|-------------------|
| `DB_HOST` | Host de PostgreSQL | `localhost` |
| `DB_PORT` | Puerto de PostgreSQL | `5432` |
| `DB_USERNAME` | Usuario de BD | `desarrollo` |
| `DB_PASSWORD` | Contraseña de BD | `071127` |
| `DB_NAME` | Nombre de BD | `core_erp` |
| `DB_SCHEMA` | Esquema de BD | `core` |

## ✅ Verificación de Instalación

1. Ejecutar: `./check-environment.sh`
2. Todos los elementos deben mostrar ✅
3. Iniciar servicios: `./start-services.sh`
4. Probar aplicación: `npm start`

## 🆘 Soporte

Si encuentras problemas:

1. Verifica los logs: `docker compose logs`
2. Consulta el estado: `./check-environment.sh`
3. Reinicia los servicios: `./stop-services.sh && ./start-services.sh`
