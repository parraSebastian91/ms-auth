# Etapa de dependencias
FROM node:20-alpine AS deps
WORKDIR /app
RUN apk add --no-cache libc6-compat curl
COPY package*.json ./
RUN npm ci

# Etapa de desarrollo (con hot-reload)
FROM node:20-alpine AS development
WORKDIR /app
COPY package*.json ./
# COPY --from=deps /app/node_modules ./node_modules
RUN npm install
COPY . .
ENV NODE_ENV=development
RUN npm run build
EXPOSE 3000
CMD ["npm", "run", "start:dev"]

# Etapa de build
FROM node:20-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# Etapa de producción
FROM node:20-alpine AS production
WORKDIR /app
RUN apk add --no-cache curl \
  && addgroup -g 1001 -S nodejs \
  && adduser -S nestjs -u 1001 -G nodejs
COPY --from=build --chown=nestjs:nodejs /app/dist ./dist
COPY --from=deps --chown=nestjs:nodejs /app/node_modules ./node_modules
COPY --from=build --chown=nestjs:nodejs /app/package*.json ./
ENV NODE_ENV=production
USER nestjs
EXPOSE 3000
CMD ["node", "dist/main.js"]