#!/bin/bash

echo "🏭 Iniciando ms-auth en modo producción..."

# Verificar que existe .env.prod
if [ ! -f .env.prod ]; then
    echo "❌ Error: No se encontró el archivo .env.prod"
    echo "📝 Configura las variables de entorno en .env.prod"
    exit 1
fi

# Verificar que las dependencias externas estén disponibles
echo "🔍 Verificando dependencias externas..."

# Verificar PostgreSQL (opcional, solo advertencia)
if ! nc -z localhost 5432 2>/dev/null; then
    echo "⚠️  Advertencia: PostgreSQL no parece estar disponible en localhost:5432"
    echo "   Asegúrate de que tu instancia de PostgreSQL esté ejecutándose"
fi

# Verificar Redis (opcional, solo advertencia)
if ! nc -z localhost 6379 2>/dev/null; then
    echo "⚠️  Advertencia: Redis no parece estar disponible en localhost:6379"
    echo "   Asegúrate de que tu instancia de Redis esté ejecutándose"
fi

# Levantar solo la aplicación en modo producción
docker-compose -f docker-compose.prod.yml up -d ms-auth

echo "⏳ Esperando que la aplicación esté lista..."

# Esperar a que la aplicación esté lista
sleep 15

echo "✅ Aplicación ms-auth iniciada en modo producción"
echo ""
echo "🌐 Servicios disponibles:"
echo "  - Aplicación NestJS: http://localhost:3000"
echo "  - Health Check: http://localhost:3000/health"
echo ""
echo "📋 Comandos útiles:"
echo "  - Ver logs: docker-compose -f docker-compose.prod.yml logs -f ms-auth"
echo "  - Entrar al contenedor: docker-compose -f docker-compose.prod.yml exec ms-auth sh"
echo "  - Detener: docker-compose -f docker-compose.prod.yml down"
