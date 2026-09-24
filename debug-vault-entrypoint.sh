#!/bin/bash
# debug-vault-entrypoint.sh
# Script para depurar carga de secrets desde Vault

set -e

echo "=========================================="
echo "Debug: Vault Entrypoint"
echo "=========================================="
echo ""

# Variables esperadas
echo "1. Variables de entorno recibidas:"
echo "   VAULT_ADDR: ${VAULT_ADDR:-❌ NO DEFINIDA}"
echo "   VAULT_TOKEN: ${VAULT_TOKEN:+✓ DEFINIDA (oculta)}${VAULT_TOKEN:-❌ NO DEFINIDA}"
echo "   SERVICE_NAME: ${SERVICE_NAME:-❌ NO DEFINIDA}"
echo ""

# Verificar conexión a Vault
echo "2. Conectividad a Vault:"
if [ -n "$VAULT_ADDR" ]; then
    if curl -sf "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; then
        echo "   ✓ Vault accesible en $VAULT_ADDR"
    else
        echo "   ❌ Vault NO accesible en $VAULT_ADDR"
        echo "   Test: curl -f $VAULT_ADDR/v1/sys/health"
        exit 1
    fi
else
    echo "   ⚠️  VAULT_ADDR no configurada"
fi
echo ""

# Verificar token
echo "3. Validación de token:"
if [ -n "$VAULT_TOKEN" ] && [ -n "$VAULT_ADDR" ]; then
    STATUS=$(curl -s -w "%{http_code}" -o /dev/null \
        -H "X-Vault-Token: $VAULT_TOKEN" \
        "$VAULT_ADDR/v1/auth/token/lookup-self")
    
    if [ "$STATUS" = "200" ]; then
        echo "   ✓ Token válido"
    else
        echo "   ❌ Token inválido (HTTP $STATUS)"
        exit 1
    fi
else
    echo "   ⚠️  VAULT_TOKEN o VAULT_ADDR faltante"
fi
echo ""

# Test de lectura de secrets
echo "4. Test de lectura de secrets:"
if [ -n "$VAULT_TOKEN" ] && [ -n "$VAULT_ADDR" ]; then
    echo "   Leyendo secret/flowis/jwt..."
    
    RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
        -H "X-Vault-Token: $VAULT_TOKEN" \
        "$VAULT_ADDR/v1/secret/flowis/jwt")
    
    HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
    BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE/d')
    
    if [ "$HTTP_CODE" = "200" ]; then
        echo "   ✓ Secret leído correctamente"
        echo ""
        echo "   Campos disponibles:"
        echo "$BODY" | jq -r '.data.data | keys[]' 2>/dev/null | sed 's/^/     - /'
    else
        echo "   ❌ Error leyendo secret (HTTP $HTTP_CODE)"
        echo "$BODY" | jq 2>/dev/null || echo "$BODY"
    fi
fi
echo ""

# Verificar que jq funciona
echo "5. Verificar dependencias:"
command -v jq > /dev/null && echo "   ✓ jq instalado" || echo "   ❌ jq NO instalado"
command -v curl > /dev/null && echo "   ✓ curl instalado" || echo "   ❌ curl NO instalado"
echo ""

echo "=========================================="
echo "Debug completado"
echo "=========================================="
