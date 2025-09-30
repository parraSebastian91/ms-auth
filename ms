#!/bin/bash

# Alias simples para comandos comunes de ms-auth

# Función para mostrar comandos disponibles
if [ "$1" = "" ] || [ "$1" = "help" ]; then
    echo "🚀 Comandos rápidos para ms-auth:"
    echo ""
    echo "  ./ms logs     - Ver logs recientes"
    echo "  ./ms follow   - Seguir logs en tiempo real"
    echo "  ./ms shell    - Entrar al contenedor"
    echo "  ./ms status   - Ver estado"
    echo "  ./ms health   - Probar health check"
    echo "  ./ms restart  - Reiniciar aplicación"
    echo ""
    echo "Para ver todos los comandos: ./docker-app-utils.sh help"
    exit 0
fi

# Ejecutar comando correspondiente
./docker-app-utils.sh "$@"
