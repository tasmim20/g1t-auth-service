import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard';
// import { AdminGuard } from './admin/admin.guard';
import { PrismaService } from './prisma.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { EmailService } from './email/email.service';

const exp = process.env.JWT_EXPIRES_IN ?? '3600'; // seconds as string
const expiresIn = Number.isNaN(Number(exp)) ? '1h' : Number(exp); // -> number | '1h'

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt', session: false }),
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn }, // now number | string literal
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PrismaService,
    JwtStrategy,
    JwtAuthGuard,
    EmailService,
  ],

  exports: [JwtModule, JwtAuthGuard],
})
export class AuthModule {}
