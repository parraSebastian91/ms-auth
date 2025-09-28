import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from './infrastructure/http-server/pipes/validation.pipe';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe());
  await app.listen(process.env.PORT ?? 3000).then(() => {
    console.log(`Application is running on: ${process.env.PORT ?? 3000}`);
  });
}
bootstrap();
