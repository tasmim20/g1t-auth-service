/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class OtpService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Create a new OTP for email or phone
   */
  async createOtp(emailOrPhone: string) {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiration = new Date();
    expiration.setMinutes(expiration.getMinutes() + 10); // 10 mins expiry

    // Use a transaction to ensure atomic creation
    await this.prisma.$transaction(async (tx) => {
      await tx.otp.create({
        data: {
          emailOrPhone,
          otp,
          expiresAt: expiration,
          isUsed: false,
        },
      });
    });

    return otp;
  }

  /**
   * Validate OTP for email or phone
   */
  async validateOtp(emailOrPhone: string, otp: string) {
    // Use a transaction to mark OTP as used atomically
    return await this.prisma.$transaction(async (tx) => {
      const record = await tx.otp.findFirst({
        where: { emailOrPhone, otp, isUsed: false },
      });

      if (!record) return false;

      if (new Date() > record.expiresAt) return false;

      await tx.otp.update({
        where: { id: record.id },
        data: { isUsed: true },
      });

      return true;
    });
  }
}
