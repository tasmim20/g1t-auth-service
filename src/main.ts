/* eslint-disable prettier/prettier */
import { NestFactory } from '@nestjs/core';
import { AuthModule } from './auth.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import * as dotenv from 'dotenv';

async function bootstrap() {
  dotenv.config(); // Load .env file

  const host = process.env.AUTH_SERVICE_HOST;
  const port = Number(process.env.AUTH_SERVICE_PORT);

  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    AuthModule,
    {
      transport: Transport.TCP,
      options: {
        host,
        port,
      },
    },
  );

  await app.listen();
  console.log(`✅ Auth Microservice is running on TCP: ${host}:${port}`);
}

bootstrap();
