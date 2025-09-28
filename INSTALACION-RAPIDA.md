# 🔧 Instalación Rápida - Backend ERP

## ⚡ Instalación en Un Solo Comando

Para instalar todo el entorno de desarrollo en un equipo nuevo:

```bash
# 1. Clonar el repositorio
git clone https://github.com/parraSebastian91/backend_seis_erp.git
cd backend_seis_erp/CRUD/ms-core

# 2. Ejecutar script de configuración automática
chmod +x setup-environment.sh
./setup-environment.sh

# 3. Reiniciar sesión (para permisos Docker) o ejecutar:
newgrp docker

# 4. Iniciar servicios
./start-services.sh

# 5. Instalar dependencias Node.js
npm install

# 6. Iniciar aplicación
npm start
```

## 📦 Lo Que Se Instala Automáticamente

- ✅ **Docker & Docker Compose**
- ✅ **PostgreSQL 15** (contenedor)
- ✅ **Redis 7** (contenedor)
- ✅ **Configuración de variables de entorno**
- ✅ **Scripts de utilidad para desarrollo**
- ✅ **Documentación completa**

## 🚀 Scripts de Utilidad Incluidos

| Script | Descripción |
|--------|-------------|
| `./start-services.sh` | Iniciar base de datos y Redis |
| `./stop-services.sh` | Detener servicios |
| `./check-environment.sh` | Verificar estado del entorno |
| `./reset-database.sh` | Resetear base de datos |

## 🔗 URLs de Desarrollo

- **API**: http://localhost:3001
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

## 📝 Configuración por Defecto

- **DB Usuario**: `desarrollo`
- **DB Password**: `071127`
- **DB Nombre**: `core_erp`
- **DB Schema**: `core`

## 🆘 Solución de Problemas Rápidos

```bash
# Si Docker da errores de permisos:
sudo usermod -aG docker $USER
newgrp docker

# Si los puertos están ocupados:
./stop-services.sh
docker system prune -f

# Si la base de datos no responde:
./reset-database.sh

# Verificar todo está funcionando:
./check-environment.sh
```

## 📚 Documentación Completa

Consulta `SETUP-GUIDE.md` para documentación detallada.

---

**¿Problemas?** 
1. Ejecuta `./check-environment.sh`
2. Revisa los logs con `docker compose logs`
3. Reinicia con `./stop-services.sh && ./start-services.sh`