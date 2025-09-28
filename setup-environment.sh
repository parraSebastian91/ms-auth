#!/bin/bash
# =============================================================================
# Script de configuración completa para ERP Backend
# Autor: Automatizado por GitHub Copilot
# Fecha: $(date '+%Y-%m-%d')
# 
# Este script automatiza la instalación y configuración completa del entorno
# de desarrollo para el backend del sistema ERP
# =============================================================================

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir mensajes con color
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}[$(date '+%H:%M:%S')] ${message}${NC}"
}

print_success() {
    print_message $GREEN "✅ $1"
}

print_info() {
    print_message $BLUE "ℹ️  $1"
}

print_warning() {
    print_message $YELLOW "⚠️  $1"
}

print_error() {
    print_message $RED "❌ $1"
}

print_separator() {
    echo -e "${BLUE}===============================================================================${NC}"
}

# Función para verificar si un comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Función para verificar si un servicio está corriendo
service_running() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

# Función para instalar Docker
install_docker() {
    print_info "Verificando si Docker está instalado..."
    
    if command_exists docker; then
        print_success "Docker ya está instalado"
        docker --version
        return 0
    fi
    
    print_info "Instalando Docker..."
    
    # Descargar script oficial de Docker
    curl -fsSL https://get.docker.com -o get-docker.sh
    
    # Instalar Docker
    sudo sh get-docker.sh
    
    # Limpiar archivo temporal
    rm get-docker.sh
    
    print_success "Docker instalado correctamente"
}

# Función para configurar permisos de Docker
configure_docker_permissions() {
    print_info "Configurando permisos de Docker..."
    
    # Agregar usuario al grupo docker
    sudo usermod -aG docker $USER
    
    # Iniciar y habilitar servicio Docker
    sudo systemctl start docker
    sudo systemctl enable docker
    
    print_success "Permisos de Docker configurados"
    print_warning "Nota: Es recomendable reiniciar la sesión para aplicar los permisos del grupo docker"
}

# Función para crear archivo .env
create_env_file() {
    print_info "Creando archivo de configuración .env..."
    
    cat > .env << 'EOF'
# =============================================================================
# Configuración del Backend ERP
# =============================================================================

# Configuración del servidor
PORT=3001
NODE_ENV=development
LOG_LEVEL=info

# Configuración de Base de Datos PostgreSQL
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=desarrollo
DB_PASSWORD=071127
DB_NAME=core_erp
DB_SCHEMA=core
DB_LOGGING=true

# Configuración JWT
JWT_SECRET=SECRETING
JWT_EXPIRES_IN=5m
JWT_REFRESH_EXPIRES_IN=604800

# Configuración Redis
REDIS_HOST=localhost
REDIS_PORT=6379
EOF
    
    print_success "Archivo .env creado correctamente"
}

# Función para crear docker-compose.yml
create_docker_compose() {
    print_info "Creando configuración de Docker Compose..."
    
    cat > docker-compose.yml << 'EOF'
services:
  postgres:
    image: postgres:15
    container_name: core_erp_postgres
    restart: always
    environment:
      POSTGRES_DB: core_erp
      POSTGRES_USER: desarrollo
      POSTGRES_PASSWORD: 071127
      POSTGRES_HOST_AUTH_METHOD: trust
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init-db:/docker-entrypoint-initdb.d
    networks:
      - core_erp_network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U desarrollo -d core_erp"]
      interval: 30s
      timeout: 10s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: core_erp_redis
    restart: always
    ports:
      - "6379:6379"
    networks:
      - core_erp_network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5

volumes:
  postgres_data:

networks:
  core_erp_network:
    driver: bridge
EOF
    
    print_success "Docker Compose configurado correctamente"
}

# Función para crear script de inicialización de BD
create_init_db() {
    print_info "Creando scripts de inicialización de base de datos..."
    
    # Crear directorio si no existe
    mkdir -p init-db
    
    cat > init-db/01-init.sql << 'EOF'
-- =============================================================================
-- Script de inicialización de Base de Datos - ERP Core
-- =============================================================================

-- Crear el esquema core
CREATE SCHEMA IF NOT EXISTS core;

-- Otorgar permisos al usuario desarrollo
GRANT ALL PRIVILEGES ON SCHEMA core TO desarrollo;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA core TO desarrollo;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA core TO desarrollo;

-- Configurar búsqueda por defecto para incluir el esquema core
ALTER DATABASE core_erp SET search_path TO core,public;

-- Mensaje de confirmación
DO $$
BEGIN
    RAISE NOTICE 'Base de datos inicializada correctamente para ERP Core';
END $$;
EOF
    
    print_success "Scripts de inicialización de BD creados"
}

# Función para crear scripts de utilidad
create_utility_scripts() {
    print_info "Creando scripts de utilidad..."
    
    # Script para iniciar servicios
    cat > start-services.sh << 'EOF'
#!/bin/bash
# Script para iniciar los servicios de desarrollo

echo "🚀 Iniciando servicios de desarrollo..."

# Iniciar contenedores
docker compose up -d

# Esperar a que los servicios estén listos
echo "⏳ Esperando a que los servicios estén listos..."
sleep 10

# Verificar estado de los contenedores
echo "📊 Estado de los servicios:"
docker compose ps

# Verificar conectividad
echo "🔗 Verificando conectividad:"
docker compose exec postgres pg_isready -U desarrollo -d core_erp || echo "PostgreSQL aún no está listo"

echo "✅ Servicios iniciados. Ahora puedes ejecutar: npm start"
EOF
    
    # Script para detener servicios
    cat > stop-services.sh << 'EOF'
#!/bin/bash
# Script para detener los servicios de desarrollo

echo "🛑 Deteniendo servicios de desarrollo..."
docker compose down

echo "✅ Servicios detenidos"
EOF
    
    # Script para resetear base de datos
    cat > reset-database.sh << 'EOF'
#!/bin/bash
# Script para resetear la base de datos

echo "🗑️  Reseteando base de datos..."

# Detener servicios
docker compose down

# Eliminar volumen de la base de datos
docker volume rm ms-core_postgres_data 2>/dev/null || echo "Volumen no encontrado"

# Reiniciar servicios
docker compose up -d

echo "✅ Base de datos reseteada"
EOF
    
    # Script de verificación del entorno
    cat > check-environment.sh << 'EOF'
#!/bin/bash
# Script para verificar el estado del entorno

echo "🔍 Verificando entorno de desarrollo..."

# Verificar Docker
if command -v docker >/dev/null 2>&1; then
    echo "✅ Docker: $(docker --version)"
else
    echo "❌ Docker no está instalado"
fi

# Verificar Node.js
if command -v node >/dev/null 2>&1; then
    echo "✅ Node.js: $(node --version)"
else
    echo "❌ Node.js no está instalado"
fi

# Verificar npm
if command -v npm >/dev/null 2>&1; then
    echo "✅ npm: $(npm --version)"
else
    echo "❌ npm no está instalado"
fi

# Verificar contenedores
echo ""
echo "📊 Estado de contenedores:"
docker compose ps 2>/dev/null || echo "❌ Contenedores no están corriendo"

# Verificar archivos de configuración
echo ""
echo "📁 Archivos de configuración:"
[ -f .env ] && echo "✅ .env existe" || echo "❌ .env no existe"
[ -f docker-compose.yml ] && echo "✅ docker-compose.yml existe" || echo "❌ docker-compose.yml no existe"
[ -f package.json ] && echo "✅ package.json existe" || echo "❌ package.json no existe"

echo ""
echo "🚀 Para iniciar el entorno ejecuta: ./start-services.sh"
EOF
    
    # Hacer scripts ejecutables
    chmod +x start-services.sh stop-services.sh reset-database.sh check-environment.sh
    
    print_success "Scripts de utilidad creados"
}

# Función para crear documentación
create_documentation() {
    print_info "Creando documentación de instalación..."
    
    cat > SETUP-GUIDE.md << 'EOF'
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
EOF
    
    print_success "Documentación creada"
}

# Función principal
main() {
    print_separator
    print_info "🚀 Iniciando configuración del entorno de desarrollo ERP"
    print_separator
    
    # Verificar que estamos en el directorio correcto
    if [[ ! -f "package.json" ]]; then
        print_error "No se encontró package.json. Asegúrate de ejecutar este script desde la raíz del proyecto."
        exit 1
    fi
    
    # Instalar Docker
    install_docker
    
    # Configurar permisos
    configure_docker_permissions
    
    # Crear archivos de configuración
    create_env_file
    create_docker_compose
    create_init_db
    
    # Crear scripts de utilidad
    create_utility_scripts
    
    # Crear documentación
    create_documentation
    
    print_separator
    print_success "🎉 Configuración completada exitosamente!"
    print_separator
    
    print_info "📝 Próximos pasos:"
    echo "   1. Reiniciar sesión o ejecutar: newgrp docker"
    echo "   2. Ejecutar: ./start-services.sh"
    echo "   3. Instalar dependencias: npm install"
    echo "   4. Iniciar aplicación: npm start"
    echo ""
    print_info "📚 Consulta SETUP-GUIDE.md para más detalles"
    print_info "🔍 Verifica el entorno con: ./check-environment.sh"
    
    print_separator
}

# Ejecutar función principal
main "$@"