# ============================================
# Dockerfile - Production (Multi-stage)
# ============================================
# Uso: docker build -t sebaondocker/seis-core-service:latest .

# ============================================
# Stage 1: Dependencies
# ============================================
FROM node:20-alpine AS deps

RUN apk add --no-cache libc6-compat

WORKDIR /app

# Copiar solo package files para cachear dependencias
COPY package*.json ./

# Instalar dependencias de producción
# Si existe package-lock.json usa npm ci, sino npm install
RUN if [ -f package-lock.json ]; then \
        npm ci --omit=dev --ignore-scripts && \
        npm cache clean --force; \
    else \
        npm install --production --ignore-scripts && \
        npm cache clean --force; \
    fi

# ============================================
# Stage 2: Builder
# ============================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copiar package files
COPY package*.json ./

# Instalar TODAS las dependencias (necesarias para build)
RUN if [ -f package-lock.json ]; then \
        npm ci; \
    else \
        npm install; \
    fi

# Copiar archivos de configuración
COPY tsconfig*.json ./
COPY nest-cli.json ./

# Copiar configuración de app
COPY config ./config

# Copiar código fuente
COPY src ./src

# Build de la aplicación
RUN npm run build && \
    npm prune --production

# ============================================
# Stage 3: Runner (Imagen final)
# ============================================
FROM node:20-alpine AS runner

# Instalar solo lo esencial
RUN apk add --no-cache \
    libc6-compat \
    curl \
    dumb-init

# Crear usuario no-root
RUN addgroup -g 1001 nodejs && \
    adduser -S -u 1001 -G nodejs nestjs

WORKDIR /app

# Copiar node_modules de producción
COPY --from=deps --chown=nestjs:nodejs /app/node_modules ./node_modules

# Copiar build compilado
COPY --from=builder --chown=nestjs:nodejs /app/dist ./dist

# Copiar package.json (necesario para start:prod)
COPY --chown=nestjs:nodejs package.json ./

# Cambiar a usuario no-root
USER nestjs

# Exponer puerto
EXPOSE 2000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:2000/health || exit 1

# Usar dumb-init para manejo correcto de señales
ENTRYPOINT ["dumb-init", "--"]

# Comando de producción
CMD ["node", "dist/main"]
