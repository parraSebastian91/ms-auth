#!/bin/bash

echo "🔧 Utilidades de ms-auth Docker"
echo ""

# Función para mostrar ayuda
show_help() {
    echo "Uso: $0 [comando]"
    echo ""
    echo "Comandos disponibles:"
    echo "  logs             - Ver logs de la aplicación"
    echo "  logs-follow      - Ver logs en tiempo real"
    echo "  shell            - Acceder al contenedor (sh)"
    echo "  bash             - Acceder al contenedor (bash si está disponible)"
    echo "  status           - Ver estado del contenedor"
    echo "  restart          - Reiniciar la aplicación"
    echo "  stop             - Detener la aplicación"
    echo "  start            - Iniciar la aplicación"
    echo "  rebuild          - Reconstruir y reiniciar"
    echo "  env              - Ver variables de entorno"
    echo "  health           - Probar health check"
    echo "  ps               - Ver procesos dentro del contenedor"
    echo "  help             - Mostrar esta ayuda"
    echo ""
    echo "Ejemplos:"
    echo "  $0 logs          # Ver últimos 50 logs"
    echo "  $0 logs-follow   # Seguir logs en tiempo real"
    echo "  $0 shell         # Entrar al contenedor"
    echo "  $0 env           # Ver variables de entorno"
}

# Función para verificar si el contenedor existe
check_container() {
    if ! docker-compose ps ms-auth | grep -q "ms_auth_app"; then
        echo "❌ El contenedor ms-auth no está ejecutándose"
        echo "   Ejecuta: ./docker-dev.sh o docker-compose up -d ms-auth"
        exit 1
    fi
}

# Función para ver logs
show_logs() {
    echo "📋 Logs de ms-auth (últimas 50 líneas):"
    echo "═══════════════════════════════════════════════════════════════════"
    docker-compose logs --tail=50 ms-auth
}

# Función para seguir logs en tiempo real
follow_logs() {
    echo "📋 Siguiendo logs de ms-auth en tiempo real (Ctrl+C para salir):"
    echo "═══════════════════════════════════════════════════════════════════"
    docker-compose logs -f ms-auth
}

# Función para acceder al shell
access_shell() {
    echo "🐚 Accediendo al contenedor ms-auth..."
    echo "   Para salir, escribe: exit"
    echo ""
    docker-compose exec ms-auth sh
}

# Función para acceder con bash
access_bash() {
    echo "🐚 Intentando acceder con bash al contenedor ms-auth..."
    echo "   Para salir, escribe: exit"
    echo ""
    docker-compose exec ms-auth bash 2>/dev/null || {
        echo "⚠️  Bash no disponible, usando sh..."
        docker-compose exec ms-auth sh
    }
}

# Función para ver estado
show_status() {
    echo "📊 Estado del contenedor ms-auth:"
    echo "═══════════════════════════════════════════════════════════════════"
    docker-compose ps ms-auth
    echo ""
    echo "📈 Recursos utilizados:"
    docker stats ms_auth_app --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
}

# Función para reiniciar
restart_app() {
    echo "🔄 Reiniciando aplicación ms-auth..."
    docker-compose restart ms-auth
    echo "✅ Aplicación reiniciada"
}

# Función para detener
stop_app() {
    echo "🛑 Deteniendo aplicación ms-auth..."
    docker-compose stop ms-auth
    echo "✅ Aplicación detenida"
}

# Función para iniciar
start_app() {
    echo "🚀 Iniciando aplicación ms-auth..."
    docker-compose start ms-auth
    echo "✅ Aplicación iniciada"
}

# Función para reconstruir
rebuild_app() {
    echo "🏗️  Reconstruyendo y reiniciando aplicación ms-auth..."
    docker-compose down ms-auth
    docker-compose build --no-cache ms-auth
    docker-compose up -d ms-auth
    echo "✅ Aplicación reconstruida y reiniciada"
}

# Función para ver variables de entorno
show_env() {
    echo "🔧 Variables de entorno en el contenedor:"
    echo "═══════════════════════════════════════════════════════════════════"
    docker-compose exec ms-auth sh -c "printenv | sort"
}

# Función para probar health check
test_health() {
    echo "🏥 Probando health check..."
    echo "═══════════════════════════════════════════════════════════════════"
    
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health)
    
    if [ "$HTTP_CODE" = "200" ]; then
        echo "✅ Health check OK ($HTTP_CODE)"
        echo ""
        echo "Respuesta:"
        curl -s http://localhost:3000/health | python3 -m json.tool 2>/dev/null || curl -s http://localhost:3000/health
    else
        echo "❌ Health check falló ($HTTP_CODE)"
        echo "   La aplicación puede no estar lista o tener problemas"
    fi
}

# Función para ver procesos
show_processes() {
    echo "⚙️  Procesos ejecutándose en el contenedor:"
    echo "═══════════════════════════════════════════════════════════════════"
    docker-compose exec ms-auth ps aux
}

# Función principal
main() {
    case "$1" in
        "logs")
            check_container
            show_logs
            ;;
        "logs-follow"|"follow"|"tail")
            check_container
            follow_logs
            ;;
        "shell"|"sh")
            check_container
            access_shell
            ;;
        "bash")
            check_container
            access_bash
            ;;
        "status"|"stat")
            check_container
            show_status
            ;;
        "restart")
            restart_app
            ;;
        "stop")
            stop_app
            ;;
        "start")
            start_app
            ;;
        "rebuild")
            rebuild_app
            ;;
        "env"|"environment")
            check_container
            show_env
            ;;
        "health"|"check")
            test_health
            ;;
        "ps"|"processes")
            check_container
            show_processes
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
