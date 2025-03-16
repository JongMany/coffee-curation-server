import { UserMicroservice } from '@app/common';
import CustomRpcExceptionFilter from '@app/common/filter/custom-rpc-exception.filter';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { join } from 'path';
import { AppModule } from './app.module';

async function bootstrap() {
  const configService = new ConfigService();

  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    AppModule,
    {
      transport: Transport.GRPC,
      options: {
        package: UserMicroservice.protobufPackage,
        protoPath: join(process.cwd(), 'proto/user.proto'),
        url: configService.getOrThrow('GRPC_URL'),
      },
    },
  );

  app.useGlobalFilters(new CustomRpcExceptionFilter());
  // app.useGlobalInterceptors(new GrpcExceptionInterceptor());

  // onModuleInit을 반드시 실행시키도록
  await app.init();

  await app.listen();
}
bootstrap()
  .then(() => {
    console.log('user microservice has a connection');
  })
  .catch(() => {
    console.log('user microservice has an error');
  });
