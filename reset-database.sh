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
