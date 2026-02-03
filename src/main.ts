import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from './infrastructure/http-server/pipes/validation.pipe';

import * as session from 'express-session';
import { createClient } from 'redis';

const { RedisStore } = require('connect-redis');
const cookieParser = require('cookie-parser');

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe());
  app.use(cookieParser()); 
  // Deshabilitar CORS completamente

  const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:4201';
  const isProd = process.env.NODE_ENV === 'production';

  app.enableCors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
    exposedHeaders: ['Set-Cookie'],
    allowedHeaders: ['Content-Type', 'Origin', 'Accept', 'Authorization'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],

  });

  const redisUrl = `redis://${process.env.REDIS_HOST || 'seis_erp_redis'}:${process.env.REDIS_PORT || 6379}`;
  // Cliente Redis para sesiones
  const redisClient = createClient({
    url: redisUrl
  });

  redisClient.on('error', (err) => console.error('Redis Client Error', err));

  try {
    await redisClient.connect();
    console.log(`✅ Conectado a Redis en: ${redisUrl}`);
  } catch (error) {
    console.error('❌ Error conectando a Redis:', error);
    throw error; // Detener si Redis no está disponible
  }

  app.use(
    session({
      store: new RedisStore({
        client: redisClient,
        prefix: 'sess:',
        ttl: 36000 // TTL en segundos (1 hora)
      }),
      name: 'auth.session',
      secret: process.env.SECRET_SESSION || 'default_secret',
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 3600000,
        path: '/',
      },
    })
  );
  app.getHttpAdapter().getInstance().set('trust proxy', true); // o true si está detrás de un proxy

  // app.use((req, res, next) => {
  //   console.log('path:', req.path);
  //   console.log('X-Real-IP:', req.headers['x-real-ip']);
  //   console.log('X-Forwarded-For:', req.headers['x-forwarded-for']);
  //   console.log('IP remota:', req.ip);
  //   next();
  // });

  await app.listen(process.env.PORT ?? 3000).then(() => {
    console.log(`Application is running on: ${process.env.PORT ?? 3000}`);
  });
}
bootstrap();
