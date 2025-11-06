/* eslint-disable @typescript-eslint/no-unsafe-enum-comparison */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from './prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { CreateDriverDto } from './dto/create-driver.dto';
import { LoginDto } from './dto/login.dto';
import { Role } from './dto/role.enum';
import { Response } from 'express';
import { RpcException } from '@nestjs/microservices';
import { EmailService } from './email/email.service';

interface AuthenticatedRequest extends Request {
  cookies: Record<string, string>;
}
@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailService,
  ) {}

  async register(createUserDto: CreateUserDto | CreateDriverDto) {
    try {
      const { email, password, role, firstName, lastName, mobileNumber } =
        createUserDto;

      if (
        !email ||
        !password ||
        !firstName ||
        !lastName ||
        !mobileNumber ||
        !role
      )
        throw new RpcException('All required fields must be provided.');

      const hashedPassword = await bcrypt.hash(password, 10);
      let user;

      if (role === Role.USER) {
        const existing = await this.prisma.user.findUnique({
          where: { email },
        });
        if (existing) throw new RpcException('User already exists.');

        user = await this.prisma.user.create({
          data: {
            email,
            password: hashedPassword,
            firstName,
            lastName,
            mobileNumber,
            role,
          },
        });
      } else if (role === Role.DRIVER) {
        const driverDto = createUserDto as CreateDriverDto;
        if (!driverDto.drivingLicense)
          throw new RpcException('Driving license required for drivers.');

        const existing = await this.prisma.driver.findUnique({
          where: { email },
        });
        if (existing)
          throw new RpcException('Driver already registered with this email.');

        user = await this.prisma.driver.create({
          data: {
            email: driverDto.email,
            password: hashedPassword,
            firstName: driverDto.firstName,
            lastName: driverDto.lastName,
            mobileNumber: driverDto.mobileNumber,
            role: driverDto.role,
            drivingLicense: driverDto.drivingLicense,
          },
        });
      } else if (role === Role.ADMIN) {
        const existing = await this.prisma.user.findUnique({
          where: { email },
        });
        if (existing) throw new RpcException('Admin already exists.');

        user = await this.prisma.user.create({
          data: {
            email,
            password: hashedPassword,
            firstName,
            lastName,
            mobileNumber,
            role,
          },
        });
      } else {
        throw new RpcException('Invalid role provided.');
      }
      // ✅ Generate email confirmation token
      const token = this.jwtService.sign(
        { email, type: 'emailConfirmation' },
        {
          secret: process.env.JWT_ACCESS_SECRET, // or a separate EMAIL_CONFIRM_SECRET
          expiresIn: '1h',
        },
      );

      console.log('Generated token:', token);

      // ✅ Send confirmation email with token
      await this.emailService.sendConfirmationEmail(email, token);

      return {
        message: `${role.charAt(0).toUpperCase() + role.slice(1)} registered successfully`,
        user,
      };
    } catch (error) {
      console.error('Registration Error:', error);
      throw error instanceof RpcException
        ? error
        : new RpcException('Failed to register. Please try again later.');
    }
  }

  // async login(loginDto: LoginDto) {
  //   try {
  //     const { email, password } = loginDto;
  //     if (!email || !password)
  //       throw new RpcException('Email and password are required.');

  //     let user = await this.prisma.user.findUnique({ where: { email } });
  //     if (!user)
  //       user = await this.prisma.driver.findUnique({ where: { email } });

  //     if (!user) throw new RpcException('User not found.');

  //     if (!user.isConfirmed) {
  //       console.error('User tried to login without confirming email:', email);
  //       return {
  //         status: 'error',
  //         message: 'Please confirm your email before logging in.',
  //       };
  //     }

  //     const isPasswordValid = await bcrypt.compare(password, user.password);
  //     if (!isPasswordValid) throw new RpcException('Invalid password.');

  //     const payload = { email: user.email, role: user.role };
  //     const accessToken = this.jwtService.sign(payload);

  //     return { message: 'Login successful', accessToken, role: user.role };
  //   } catch (error) {
  //     console.error('Login Error:', error);
  //     throw error instanceof RpcException
  //       ? error
  //       : new RpcException('Failed to login. Please try again later.');
  //   }
  // }

  async login(loginDto: LoginDto) {
    try {
      const { email, password } = loginDto;

      if (!email || !password)
        throw new RpcException('Email and password are required.');

      let user = await this.prisma.user.findUnique({ where: { email } });
      if (!user)
        user = await this.prisma.driver.findUnique({ where: { email } });

      if (!user) throw new RpcException('User not found.');

      if (!user.isConfirmed) {
        console.error('User tried to login without confirming email:', email);
        return {
          status: 'error',
          message: 'Please confirm your email before logging in.',
        };
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) throw new RpcException('Invalid password.');

      const payload = { email: user.email, role: user.role };

      // Create access and refresh tokens
      // ✅ Generate tokens
      const accessToken = this.jwtService.sign(payload, {
        secret: process.env.JWT_ACCESS_SECRET,
        expiresIn: '30s',
      });

      const refreshToken = this.jwtService.sign(payload, {
        secret: process.env.JWT_REFRESH_SECRET,
        expiresIn: '7d',
      });

      // ✅ Hash and store refresh token
      const hashedRefresh = await bcrypt.hash(refreshToken, 10);
      await this.prisma.user.update({
        where: { email: user.email },
        data: { refreshToken: hashedRefresh },
      });
      if (user.role === Role.USER || user.role === Role.ADMIN) {
        await this.prisma.user.update({
          where: { email: user.email },
          data: { refreshToken: hashedRefresh },
        });
      } else if (user.role === Role.DRIVER) {
        await this.prisma.driver.update({
          where: { email: user.email },
          data: { refreshToken: hashedRefresh },
        });
      }
      // Return access token to client
      return {
        message: 'Login successful',
        accessToken,
        refreshToken,
        role: user.role,
      };
    } catch (error) {
      console.error('Login Error:', error);
      throw error instanceof RpcException
        ? error
        : new RpcException('Failed to login. Please try again later.');
    }
  }

  // Refresh Access Token (Using Refresh Token)
  async refreshToken(refreshToken: string) {
    try {
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      const user = await this.prisma.user.findUnique({
        where: { email: payload.email },
      });
      if (!user || !user.refreshToken)
        throw new RpcException('Invalid refresh token');

      const isMatch = await bcrypt.compare(refreshToken, user.refreshToken);
      if (!isMatch) throw new RpcException('Invalid refresh token');

      const newAccessToken = this.jwtService.sign(
        { email: user.email, role: user.role },
        {
          secret: process.env.JWT_ACCESS_SECRET,
          expiresIn: '1m',
        },
      );

      const newRefreshToken = this.jwtService.sign(
        { email: user.email, role: user.role },
        {
          secret: process.env.JWT_REFRESH_SECRET,
          expiresIn: '7d',
        },
      );

      const hashedNewToken = await bcrypt.hash(newRefreshToken, 10);
      await this.prisma.user.update({
        where: { email: user.email },
        data: { refreshToken: hashedNewToken },
      });

      return { newAccessToken, newRefreshToken };
    } catch (error) {
      throw new RpcException('Failed to refresh token');
    }
  }

  // logout() {
  //   try {
  //     return { message: 'Logout successful' };
  //   } catch (error) {
  //     console.error('Logout Error:', error);
  //     throw new RpcException('Failed to logout. Please try again later.');
  //   }
  // }
  async logout(refreshToken: string) {
    if (!refreshToken) return { message: 'No refresh token found' };

    try {
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      await this.prisma.user.update({
        where: { email: payload.email },
        data: { refreshToken: null },
      });

      return { message: 'Logout successful' };
    } catch (error) {
      console.error('Logout Error:', error);
      throw new RpcException('Failed to logout. Please try again later.');
    }
  }

  /** Get all users */
  async getAllUsers() {
    try {
      return await this.prisma.user.findMany({
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          mobileNumber: true,
          role: true,
        },
      });
    } catch (error) {
      console.error('Get All Users Error:', error);
      throw new RpcException('Failed to fetch users.');
    }
  }

  /** Get user by email */
  async getUserByEmail(email: string) {
    try {
      const user = await this.prisma.user.findUnique({
        where: { email },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          mobileNumber: true,
          role: true,
        },
      });
      if (!user) throw new RpcException('User not found.');
      return user;
    } catch (error) {
      console.error('Get User By Email Error:', error);
      throw new RpcException('Failed to fetch user.');
    }
  }

  /** Get all drivers */
  async getAllDrivers() {
    try {
      return await this.prisma.driver.findMany({
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          mobileNumber: true,
          role: true,
          drivingLicense: true,
        },
      });
    } catch (error) {
      console.error('Get All Drivers Error:', error);
      throw new RpcException('Failed to fetch drivers.');
    }
  }

  /** Get driver by email */
  async getDriverByEmail(email: string) {
    try {
      const driver = await this.prisma.driver.findUnique({
        where: { email },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          mobileNumber: true,
          role: true,
          drivingLicense: true,
        },
      });
      if (!driver) throw new RpcException('Driver not found.');
      return driver;
    } catch (error) {
      console.error('Get Driver By Email Error:', error);
      throw new RpcException('Failed to fetch driver.');
    }
  }

  /** Confirm user or driver registration */
  async confirmRegistration(token: string) {
    try {
      const payload = this.jwtService.verify(token, {
        secret: process.env.JWT_ACCESS_SECRET,
      });

      if (payload.type !== 'emailConfirmation') {
        throw new RpcException('Invalid token type.');
      }

      const email = payload.email;

      // Try updating user first
      let user = await this.prisma.user.updateMany({
        where: { email },
        data: { isConfirmed: true },
      });

      // If not found, try updating driver
      if (user.count === 0) {
        user = await this.prisma.driver.updateMany({
          where: { email },
          data: { isConfirmed: true },
        });
      }

      if (user.count === 0) throw new RpcException('User not found.');

      return { message: 'Email successfully confirmed. You can now log in.' };
    } catch (error) {
      console.error('Confirm Registration Error:', error);
      throw new RpcException('Invalid or expired token.');
    }
  }
  async forgotPassword(email: string) {
    try {
      // Check if user exists
      let userOrDriver: any = await this.prisma.user.findUnique({
        where: { email },
      });
      let type: 'USER' | 'DRIVER' = 'USER';

      if (!userOrDriver) {
        userOrDriver = await this.prisma.driver.findUnique({
          where: { email },
        });
        type = 'DRIVER';
      }

      if (!userOrDriver) throw new RpcException('User not found.');

      // Generate 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      console.log(`✅ OTP for ${email}: ${otp}`);

      // OTP expiry 10 minutes from now
      const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

      // Save OTP and expiry in DB
      if (type === 'USER') {
        await this.prisma.user.update({
          where: { email },
          data: { otp, otpExpiry },
        });
      } else {
        await this.prisma.driver.update({
          where: { email },
          data: { otp, otpExpiry },
        });
      }

      // Send OTP email
      await this.emailService.sendOTPEmail(email, otp);

      return { message: 'OTP sent to your email. It is valid for 10 minutes.' };
    } catch (error) {
      console.error('Forgot Password Error:', error);
      throw new RpcException('Failed to process forgot password.');
    }
  }

  // ------------------- RESET PASSWORD -------------------
  async resetPassword(email: string, otp: string, newPassword: string) {
    try {
      // Check if user exists
      let userOrDriver: any = await this.prisma.user.findUnique({
        where: { email },
      });
      let type: 'USER' | 'DRIVER' = 'USER';

      if (!userOrDriver) {
        userOrDriver = await this.prisma.driver.findUnique({
          where: { email },
        });
        type = 'DRIVER';
      }

      if (!userOrDriver) throw new RpcException('User not found.');

      // Validate OTP
      if (userOrDriver.otp !== otp) throw new RpcException('Invalid OTP.');
      if (new Date(userOrDriver.otpExpiry) < new Date())
        throw new RpcException('OTP has expired.');

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password and clear OTP
      if (type === 'USER') {
        await this.prisma.user.update({
          where: { email },
          data: { password: hashedPassword, otp: null, otpExpiry: null },
        });
      } else {
        await this.prisma.driver.update({
          where: { email },
          data: { password: hashedPassword, otp: null, otpExpiry: null },
        });
      }

      return { message: 'Password reset successfully.' };
    } catch (error) {
      console.error('Reset Password Error:', error);
      throw new RpcException(error.message || 'Failed to reset password.');
    }
  }
}
