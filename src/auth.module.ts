import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from './prisma.service';
import { JwtStrategy } from './common/strategies/jwt.strategy';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { join } from 'path';
import * as dotenv from 'dotenv';
import { parseExpiration } from './common/utils/parse-expiration';

dotenv.config(); // load .env

const userProtoPath = join(__dirname, '../proto/user.proto');
const emailProtoPath = join(__dirname, '../proto/email.proto');

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt', session: false }),
    JwtModule.register({
      secret: process.env.JWT_ACCESS_SECRET || 'fallback_secret',
      signOptions: {
        expiresIn: parseExpiration(process.env.JWT_ACCESS_EXPIRATION),
      },
    }),
    ClientsModule.register([
      {
        name: 'USER_SERVICE',
        transport: Transport.GRPC,
        options: {
          package: 'user',
          protoPath: userProtoPath,
          url: `${process.env.USER_SERVICE_HOST}:${process.env.USER_SERVICE_PORT}`,
        },
      },
      {
        name: 'EMAIL_SERVICE',
        transport: Transport.GRPC,
        options: {
          package: 'email',
          protoPath: emailProtoPath,
          url: `${process.env.EMAIL_SERVICE_HOST}:${process.env.EMAIL_SERVICE_PORT}`,
        },
      },
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaService, JwtStrategy],
})
export class AuthModule {}
