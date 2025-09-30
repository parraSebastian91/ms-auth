# Usar imagen base de Node.js
FROM node:20-alpine AS base

# Instalar dependencias necesarias
RUN apk add --no-cache libc6-compat curl

# Establecer directorio de trabajo
WORKDIR /app

# Copiar archivos de configuración de dependencias
COPY package*.json ./
COPY tsconfig*.json ./
COPY nest-cli.json ./

# Instalar dependencias de producción
RUN npm ci --only=production && npm cache clean --force

# Etapa de desarrollo
FROM base AS development
# Instalar todas las dependencias (incluyendo devDependencies)
RUN npm ci
COPY . .
EXPOSE 3000
CMD ["npm", "run", "start:dev"]

# Etapa de construcción
FROM base AS build
# Instalar todas las dependencias para compilar
RUN npm ci
COPY . .
RUN npm run build

# Etapa de producción
FROM node:18-alpine AS production

# Crear usuario no-root para seguridad
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nestjs -u 1001

# Instalar curl para health checks
RUN apk add --no-cache curl

WORKDIR /app

# Copiar archivos necesarios desde la etapa de construcción
COPY --from=build --chown=nestjs:nodejs /app/dist ./dist
COPY --from=build --chown=nestjs:nodejs /app/node_modules ./node_modules
COPY --from=build --chown=nestjs:nodejs /app/package*.json ./

# Cambiar a usuario no-root
USER nestjs

# Exponer puerto
EXPOSE 3000

# Variables de entorno por defecto
ENV NODE_ENV=production

# Comando de inicio para producción
CMD ["node", "dist/main.js"]
