import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ClientsModule, Transport } from '@nestjs/microservices';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from './prisma.service';
import { EmailService } from './email/email.service';
import { JwtStrategy } from './common/strategies/jwt.strategy';

const exp = process.env.JWT_EXPIRES_IN ?? '3600'; // seconds as string
const expiresIn = Number.isNaN(Number(exp)) ? '30s' : Number(exp); // -> number | '1h'

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt', session: false }),
    JwtModule.register({
      secret: process.env.JWT_ACCESS_SECRET,
      signOptions: { expiresIn },
    }),

    // 👇 Add User Microservice Client Here
    ClientsModule.register([
      {
        name: 'USER_SERVICE',
        transport: Transport.TCP,
        options: {
          host: process.env.USER_SERVICE_HOST,
          port: parseInt(process.env.USER_SERVICE_PORT!),
        },
      },
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaService, EmailService, JwtStrategy],
})
export class AuthModule {}
