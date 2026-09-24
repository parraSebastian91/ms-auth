#!/bin/bash
# entrypoint-with-vault.sh
# Carga secrets de Vault y ejecuta app

set -e

echo "🔐 Cargando secrets desde Vault..."

# Vault config
VAULT_ADDR="${VAULT_ADDR:-http://vault-mu17yahldtcx1jazhzt2s1no:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"

if [ -z "$VAULT_TOKEN" ]; then
    echo "❌ VAULT_TOKEN no configurado"
    exit 1
fi

# Función helper (KV v2)
vault_get() {
    local path=$1
    local field=$2
    curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
        "$VAULT_ADDR/v1/$path" | \
        jq -r ".data.data.$field"
}

load_database(){
    echo "  🔑 Cargando secrets de base de datos..."
    # Database
    local path="secret/data/flowis/postgres"
    export DATABASE_HOST=$(vault_get "$path" "DATABASE_HOST")
    export DATABASE_USER=$(vault_get "$path" "DATABASE_USER")
    export DATABASE_PASSWORD=$(vault_get "$path" "DATABASE_PASSWORD")
    export DATABASE_PORT=$(vault_get "$path" "DATABASE_PORT")
    export DATABASE_NAME=$(vault_get "$path" "DATABASE_NAME")
    export DATABASE_SSL=$(vault_get "$path" "DATABASE_SSL")
}

load_redis(){
    echo "  🔑 Cargando secrets de Redis..."
    # Redis
    local path="secret/data/flowis/redis"
    export REDIS_HOST=$(vault_get "$path" "REDIS_HOST")
    export REDIS_PORT=$(vault_get "$path" "REDIS_PORT")
    export REDIS_DB=$(vault_get "$path" "REDIS_DB")
    export REDIS_TTL=$(vault_get "$path" "REDIS_TTL")
}

load_JWT(){  
    echo "  🔑 Cargando secrets de JWT..."
    # JWT
    local path="secret/data/flowis/jwt"
    export SECRET=$(vault_get "$path" "SECRET")
    export JWT_ACCESS_SECRET=$(vault_get "$path" "JWT_ACCESS_SECRET")
    export JWT_ACCESS_EXPIRES_IN=$(vault_get "$path" "JWT_ACCESS_EXPIRES_IN")
    export JWT_REFRESH_SECRET=$(vault_get "$path" "JWT_REFRESH_SECRET")
    export JWT_REFRESH_EXPIRES_IN=$(vault_get "$path" "JWT_REFRESH_EXPIRES_IN")
    export JWT_ACCESS_ADMIN_EXPIRES_IN=$(vault_get "$path" "JWT_ACCESS_ADMIN_EXPIRES_IN")
}

load_session_env(){
    echo "  🔑 Cargando secrets de sesión..."
   # SESSION
    local path="secret/data/flowis/session"
    export PREFIX_SESSION=$(vault_get "$path" "PREFIX_SESSION")
    export SECRET_SESSION=$(vault_get "$path" "SECRET_SESSION")
    export TTL_COOKIE_SESSION=$(vault_get "$path" "TTL_COOKIE_SESSION")
    export TTL_SESSION=$(vault_get "$path" "TTL_SESSION")
    export TTL_AUTH_CODE=$(vault_get "$path" "TTL_AUTH_CODE")
}

load_storage_minio(){
    echo "  🔑 Cargando secrets de MinIO..."
    # MinIO
    local path="secret/data/flowis/storage_minio"
    export MINIO_ROOT_USER=$(vault_get "$path" "user")
    export MINIO_ROOT_PASSWORD=$(vault_get "$path" "password")
    export MINIO_ENDPOINT=$(vault_get "$path" "endpoint")
    export STORAGE_ENDPOINT=$MINIO_ENDPOINT
    export STORAGE_ACCESS_KEY=$MINIO_ROOT_USER
    export STORAGE_SECRET_KEY=$MINIO_ROOT_PASSWORD
}

load_rabbit_env(){
    echo "  🔑 Cargando secrets de RabbitMQ..."
    local path="secret/flowis/rabbitmq"
    export RABBITMQ_HOST=$(vault_get "$path" "RABBITMQ_HOST")
    export RABBITMQ_PORT=$(vault_get "$path" "RABBITMQ_PORT")
    export RABBITMQ_USER=$(vault_get "$path" "RABBITMQ_USER")
    export RABBITMQ_PASS=$(vault_get "$path" "RABBITMQ_PASS")
    export RABBITMQ_QUEUE=$(vault_get "$path" "RABBITMQ_QUEUE")
    export RABBITMQ_ROUTING_KEY=$(vault_get "$path" "RABBITMQ_ROUTING_KEY")
    export RABBITMQ_EXCHANGE=$(vault_get "$path" "RABBITMQ_EXCHANGE")
}

# Cargar secrets según el servicio
SERVICE_NAME="${SERVICE_NAME:-unknown}"

echo "  📦 Cargando secrets para $SERVICE_NAME..."
load_database
load_redis
load_JWT
load_session_env 
export CORS_ORIGINS=$(vault_get "secret/data/flowis/seis-auth-service" "CORS_ORIGINS")
export NODE_ENV=$(vault_get "secret/data/flowis/seis-auth-service" "NODE_ENV")
export PORT=$(vault_get "secret/data/flowis/seis-auth-service" "PORT")
export MIN_LOG_LEVEL=$(vault_get "secret/data/flowis/seis-auth-service" "MIN_LOG_LEVEL")

echo "🚀 Iniciando aplicación..."
echo ""

# Ejecutar comando original del container
exec "$@"
