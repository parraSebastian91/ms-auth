#!/bin/bash
# =============================================================================
# Script para empaquetar la solución completa para distribución
# =============================================================================

PACKAGE_NAME="erp-backend-setup-$(date +%Y%m%d-%H%M)"
TEMP_DIR="/tmp/$PACKAGE_NAME"

echo "📦 Creando paquete de instalación..."

# Crear directorio temporal
mkdir -p "$TEMP_DIR"

# Copiar archivos esenciales
cp setup-environment.sh "$TEMP_DIR/"
cp INSTALACION-RAPIDA.md "$TEMP_DIR/README.md"
cp .env "$TEMP_DIR/.env.example"

# Crear archivo de instalación completo
cat > "$TEMP_DIR/install.sh" << 'EOF'
#!/bin/bash
# =============================================================================
# Instalador automático del Backend ERP
# Ejecutar en el directorio raíz del proyecto
# =============================================================================

echo "🚀 Iniciando instalación automática del Backend ERP..."

# Copiar archivo de configuración
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "✅ Archivo .env creado desde ejemplo"
fi

# Ejecutar configuración
chmod +x setup-environment.sh
./setup-environment.sh

echo ""
echo "🎉 ¡Instalación completada!"
echo ""
echo "📝 Próximos pasos:"
echo "1. Reiniciar sesión o ejecutar: newgrp docker"
echo "2. Ejecutar: ./start-services.sh"
echo "3. Instalar dependencias: npm install"
echo "4. Iniciar aplicación: npm start"
EOF

chmod +x "$TEMP_DIR/install.sh"

# Crear archivo comprimido
cd /tmp
tar -czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME"

# Mover al directorio actual
mv "${PACKAGE_NAME}.tar.gz" "$OLDPWD/"

# Limpiar
rm -rf "$TEMP_DIR"

echo "✅ Paquete creado: ${PACKAGE_NAME}.tar.gz"
echo ""
echo "📋 Para usar en otro equipo:"
echo "1. Copiar ${PACKAGE_NAME}.tar.gz al nuevo equipo"
echo "2. Extraer: tar -xzf ${PACKAGE_NAME}.tar.gz"
echo "3. Ir al directorio del proyecto ERP"
echo "4. Copiar archivos: cp ${PACKAGE_NAME}/* ."
echo "5. Ejecutar: ./install.sh"