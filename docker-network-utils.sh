#!/bin/bash

echo "🔗 Utilidades de red para ms-auth"
echo ""

# Función para mostrar ayuda
show_help() {
    echo "Uso: $0 [comando]"
    echo ""
    echo "Comandos disponibles:"
    echo "  network-info     - Mostrar información de la red compartida"
    echo "  connect-postgres - Conectar contenedor PostgreSQL a la red"
    echo "  connect-redis    - Conectar contenedor Redis a la red"
    echo "  list-containers  - Listar todos los contenedores"
    echo "  help            - Mostrar esta ayuda"
    echo ""
}

# Función para mostrar información de la red
network_info() {
    echo "🌐 Información de la red shared_erp_network:"
    echo ""
    
    if docker network inspect shared_erp_network >/dev/null 2>&1; then
        echo "✅ Red existe"
        echo ""
        echo "📋 Contenedores conectados:"
        docker network inspect shared_erp_network --format='{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'
        echo ""
        echo "🔧 Configuración de red:"
        docker network inspect shared_erp_network --format='Subnet: {{range .IPAM.Config}}{{.Subnet}}{{end}}'
    else
        echo "❌ La red shared_erp_network no existe"
        echo "   Ejecuta: docker network create shared_erp_network"
    fi
}

# Función para conectar PostgreSQL
connect_postgres() {
    echo "🔍 Buscando contenedores PostgreSQL..."
    
    # Buscar contenedores con postgres en el nombre
    POSTGRES_CONTAINERS=$(docker ps --format "table {{.Names}}" | grep -i postgres | grep -v NAMES)
    
    if [ -z "$POSTGRES_CONTAINERS" ]; then
        echo "❌ No se encontraron contenedores PostgreSQL ejecutándose"
        return 1
    fi
    
    echo "📋 Contenedores PostgreSQL encontrados:"
    echo "$POSTGRES_CONTAINERS"
    echo ""
    
    # Si hay un solo contenedor, conectarlo automáticamente
    CONTAINER_COUNT=$(echo "$POSTGRES_CONTAINERS" | wc -l)
    if [ $CONTAINER_COUNT -eq 1 ]; then
        CONTAINER_NAME=$(echo "$POSTGRES_CONTAINERS" | tr -d ' ')
        echo "🔗 Conectando $CONTAINER_NAME a shared_erp_network..."
        docker network connect shared_erp_network "$CONTAINER_NAME" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "✅ $CONTAINER_NAME conectado exitosamente"
            echo "💡 Ahora puedes usar DATABASE_HOST=$CONTAINER_NAME en tu .env"
        else
            echo "⚠️  $CONTAINER_NAME ya está conectado o hubo un error"
        fi
    else
        echo "❓ Múltiples contenedores encontrados. ¿Cuál quieres conectar?"
        echo "   Ejemplo: docker network connect shared_erp_network nombre_contenedor"
    fi
}

# Función para conectar Redis
connect_redis() {
    echo "🔍 Buscando contenedores Redis..."
    
    # Buscar contenedores con redis en el nombre
    REDIS_CONTAINERS=$(docker ps --format "table {{.Names}}" | grep -i redis | grep -v NAMES)
    
    if [ -z "$REDIS_CONTAINERS" ]; then
        echo "❌ No se encontraron contenedores Redis ejecutándose"
        return 1
    fi
    
    echo "📋 Contenedores Redis encontrados:"
    echo "$REDIS_CONTAINERS"
    echo ""
    
    # Si hay un solo contenedor, conectarlo automáticamente
    CONTAINER_COUNT=$(echo "$REDIS_CONTAINERS" | wc -l)
    if [ $CONTAINER_COUNT -eq 1 ]; then
        CONTAINER_NAME=$(echo "$REDIS_CONTAINERS" | tr -d ' ')
        echo "🔗 Conectando $CONTAINER_NAME a shared_erp_network..."
        docker network connect shared_erp_network "$CONTAINER_NAME" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "✅ $CONTAINER_NAME conectado exitosamente"
            echo "💡 Ahora puedes usar REDIS_HOST=$CONTAINER_NAME en tu .env"
        else
            echo "⚠️  $CONTAINER_NAME ya está conectado o hubo un error"
        fi
    else
        echo "❓ Múltiples contenedores encontrados. ¿Cuál quieres conectar?"
        echo "   Ejemplo: docker network connect shared_erp_network nombre_contenedor"
    fi
}

# Función para listar contenedores
list_containers() {
    echo "📦 Contenedores ejecutándose:"
    echo ""
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"
}

# Función principal
main() {
    case "$1" in
        "network-info"|"info")
            network_info
            ;;
        "connect-postgres"|"postgres")
            connect_postgres
            ;;
        "connect-redis"|"redis")
            connect_redis
            ;;
        "list-containers"|"list"|"containers")
            list_containers
            ;;
        "help"|"-h"|"--help"|"")
            show_help
            ;;
        *)
            echo "❌ Comando desconocido: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Ejecutar función principal
main "$@"
