#!/bin/bash

echo "🐳 Construyendo imagen Docker para ms-auth..."

# Construir la imagen para desarrollo
docker-compose build ms-auth

echo "✅ Imagen construida exitosamente"

# Mostrar las imágenes creadas
echo "📋 Imágenes Docker:"
docker images | grep ms-auth
