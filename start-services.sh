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
