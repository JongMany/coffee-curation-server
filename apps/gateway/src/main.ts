import { AllGlobalExceptionsFilter } from '@app/common/filter/global-exception.filter';
import { ValidationPipe } from '@nestjs/common';
import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const httpAdapterHost = app.get(HttpAdapterHost);

  app.enableCors({
    origin: ['http://localhost:3003'],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });
  app.useGlobalPipes(new ValidationPipe());
  app.useGlobalFilters(new AllGlobalExceptionsFilter(httpAdapterHost));
  await app.init();

  await app.listen(process.env.HTTP_PORT ?? 8080);
}
bootstrap()
  .then(() => {
    console.log(`gateway has a connection in ${process.env.HTTP_PORT}`);
  })
  .catch((error) => {
    console.log('gateway has an error', error);
  });
