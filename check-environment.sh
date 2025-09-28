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
