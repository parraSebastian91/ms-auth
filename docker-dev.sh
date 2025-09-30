#!/bin/bash

echo "🚀 Iniciando ms-auth en modo desarrollo..."

# Crear red compartida si no existe
echo "🌐 Creando red compartida..."
docker network create shared_erp_network 2>/dev/null || echo "Red shared_erp_network ya existe"

# Verificar que las dependencias externas estén disponibles
echo "🔍 Verificando dependencias externas..."

# Buscar contenedores de PostgreSQL en la red
POSTGRES_CONTAINERS=$(docker network inspect shared_erp_network --format='{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | grep -E "(postgres|postgresql)" || true)
if [ -n "$POSTGRES_CONTAINERS" ]; then
    echo "✅ Contenedores PostgreSQL encontrados en la red: $POSTGRES_CONTAINERS"
else
    echo "⚠️  No se encontraron contenedores PostgreSQL en la red shared_erp_network"
    echo "   Opciones:"
    echo "   1. Conectar tu contenedor PostgreSQL a la red: docker network connect shared_erp_network <postgres_container>"
    echo "   2. O usar localhost si PostgreSQL está en el host"
fi

# Buscar contenedores de Redis en la red
REDIS_CONTAINERS=$(docker network inspect shared_erp_network --format='{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | grep -E "(redis)" || true)
if [ -n "$REDIS_CONTAINERS" ]; then
    echo "✅ Contenedores Redis encontrados en la red: $REDIS_CONTAINERS"
else
    echo "⚠️  No se encontraron contenedores Redis en la red shared_erp_network"
    echo "   Opciones:"
    echo "   1. Conectar tu contenedor Redis a la red: docker network connect shared_erp_network <redis_container>"
    echo "   2. O usar localhost si Redis está en el host"
fi

# Levantar solo la aplicación
docker-compose up -d ms-auth

echo "⏳ Esperando que la aplicación esté lista..."

# Esperar a que la aplicación esté lista
sleep 10

echo "✅ Aplicación ms-auth iniciada en modo desarrollo"
echo ""
echo "🌐 Servicios disponibles:"
echo "  - Aplicación NestJS: http://localhost:3000"
echo "  - Health Check: http://localhost:3000/health"
echo ""
echo "📋 Comandos útiles:"
echo "  - Ver logs: docker-compose logs -f ms-auth"
echo "  - Entrar al contenedor: docker-compose exec ms-auth sh"
echo "  - Ver red: docker network inspect shared_erp_network"
echo "  - Detener: docker-compose down"
