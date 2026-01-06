import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from './infrastructure/http-server/pipes/validation.pipe';
import * as Session from 'express-session';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe());
  // Deshabilitar CORS completamente
  app.enableCors();

  app.use(
    Session({
      secret: process.env.SECRET_SESSION || 'default_secret',
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true, // Protege contra XSS
        //secure: true,   // Solo sobre HTTPS
        sameSite: 'lax', // Protege contra CSRF
        maxAge: 3600000, // 1 hora
      },
    })
  )

  await app.listen(process.env.PORT ?? 3000).then(() => {
    console.log(`Application is running on: ${process.env.PORT ?? 3000}`);
  });
}
bootstrap();
