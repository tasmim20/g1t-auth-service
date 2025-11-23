/* eslint-disable @typescript-eslint/no-floating-promises */
import * as dotenv from 'dotenv';
dotenv.config();

import { NestFactory } from '@nestjs/core';
import { AuthModule } from './auth.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { join } from 'path';

async function bootstrap() {
  const host = process.env.AUTH_SERVICE_HOST;
  const port = Number(process.env.AUTH_SERVICE_PORT);

  // Always load proto from dist/proto
  const protoPath = join(__dirname, '../proto/auth.proto');

  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    AuthModule,
    {
      transport: Transport.GRPC,
      options: {
        package: 'auth',
        protoPath,
        url: `${host}:${port}`,
      },
    },
  );

  await app.listen();
  console.log(`✅ Auth Microservice is running on gRPC: ${host}:${port}`);
}

bootstrap();
