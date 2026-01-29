import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from './infrastructure/http-server/pipes/validation.pipe';
const session = require('express-session');

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe());
  // Deshabilitar CORS completamente

  const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:4201';
  const isProd = process.env.NODE_ENV === 'production';

  app.enableCors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
  });

  app.use(
    session({
      name: process.env.SESSION_NAME || 'sid',
      secret: process.env.SECRET_SESSION || 'default_secret',
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: isProd,                   // true en producción (HTTPS / Kong TLS)
        sameSite: 'strict', // 'none' + secure en cross-site prod; 'lax' en dev
        maxAge: 3600000,
      },
    })
  )
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
