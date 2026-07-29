import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from './infrastructure/http/pipes/validation.pipe';

import * as session from 'express-session';
import { createClient } from 'redis';

const { RedisStore } = require('connect-redis');
const cookieParser = require('cookie-parser');

import * as vault from 'node-vault';

const SECRETS = {
  DB_POSTGRES: process.env.SECRET_DB_KEY || 'DB-SEIS-POSTGRES',
  CACHE_REDIS: process.env.SECRET_REDIS_KEY || 'REDIS',
  JWT: process.env.SECRET_JWT_KEY || 'JWT',
  SHARED: process.env.SECRET_SHARED || 'SHARED'
}

async function preloadVaultToEnv() {
  const vauldEndpoint = {
    apiVersion: 'v1',
    endpoint: process.env.VAULT_ADDR || 'http://vault:8200',
    token: process.env.VAULT_TOKEN || 'myroot',
  }
  const client = vault(vauldEndpoint);

  const paths = ['JWT', 'DB_POSTGRES', 'CACHE_REDIS', 'SHARED'];

  for (const path of paths) {
    try {
      const res = await client.read(`/secret/data/${SECRETS[path]}`);
      const data = res.data.data;
      for (const [k, v] of Object.entries(data)) {
        const envKey = String(k).toUpperCase();
        if (!process.env[envKey] && v !== undefined && v !== null) {
          process.env[envKey] = String(v);
        }
      }
    } catch (e) {
      if (process.env.NODE_ENV === 'production') throw e;
    }
  }
}

async function bootstrap() {
  // await preloadVaultToEnv();
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe());
  app.use(cookieParser());
  app.getHttpAdapter().getInstance().set('trust proxy', true);
  // Deshabilitar CORS completamente

  const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;
  const isProd = process.env.NODE_ENV === 'production';

  app.enableCors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
    exposedHeaders: ['Set-Cookie', 'x-request-id'],
    allowedHeaders: ['Content-Type', 'Origin', 'Accept', 'Authorization', 'x-request-id'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  });

  const redisUrl = `redis://${process.env.REDIS_HOST || 'seis_erp_redis'}:${process.env.REDIS_PORT || 6379}`;
  // Cliente Redis para sesiones
  const redisClient = createClient({
    url: redisUrl
  });

  // redisClient.on('error', (err) => console.error('Redis Client Error', err));

  // try {
  //   await redisClient.connect();
  //   console.log(`✅ Conectado a Redis para sesisones en: ${redisUrl}`);
  // } catch (error) {
  //   console.error('❌ Error conectando a Redis:', error);
  //   throw error; // Detener si Redis no está disponible
  // }

  app.use(
    session({
      store: new RedisStore({
        client: redisClient,
        prefix: process.env.PREFIX_SESSION,
        ttl: process.env.TTL_SESSION,
      }),
      name: 'auth.session',
      secret: process.env.SECRET_SESSION,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: isProd ? 'auto' : false,
        sameSite: 'lax',
        maxAge: Number(process.env.TTL_COOKIE_SESSION),
        path: '/',
      },
    })
  );

  // app.use((req, res, next) => {
  //   console.log('path:', req.path);
  //   console.log('X-Real-IP:', req.headers['x-real-ip']);
  //   console.log('X-Forwarded-For:', req.headers['x-forwarded-for']);
  //   console.log('IP remota:', req.ip);
  //   next();
  // });

  await app.listen(process.env.PORT).then(() => {
    console.log(`Application is running on: ${process.env.PORT}`);
  });
}
bootstrap();
