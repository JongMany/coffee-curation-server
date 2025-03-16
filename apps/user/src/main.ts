import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(process.env.port ?? 3000);
}
bootstrap()
  .then(() => {
    console.log('user microservice has a connection');
  })
  .catch(() => {
    console.log('user microservice has an error');
  });
