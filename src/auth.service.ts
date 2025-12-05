/* eslint-disable @typescript-eslint/no-misused-promises */
/* eslint-disable @typescript-eslint/require-await */
/* eslint-disable @typescript-eslint/no-unsafe-enum-comparison */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from './prisma.service';
import * as argon2 from 'argon2';
import { CreateDriverDto } from './dto/create-driver.dto';
import { LoginDto } from './dto/login.dto';
import { Role } from './dto/role.enum';
import { RpcException } from '@nestjs/microservices';
import type { ClientGrpc } from '@nestjs/microservices';
import { firstValueFrom, Observable } from 'rxjs';
import { CreateRiderDto } from './dto/create-rider.dto';
import { RefreshToken } from './common/user.interface';
import { parseExpiration } from './common/utils/parse-expiration';
import ms from 'ms';

interface AuthenticatedRequest extends Request {
  cookies: Record<string, string>;
}
interface UserService {
  createProfile(data: {
    userId: number;
    email: string;
    role: string; // 'RIDER' | 'DRIVER' | 'ADMIN'
    firstName: string;
    lastName: string;
    mobileNumber: string;
    profilePhoto?: string;
    bio?: string;
    address?: string;
  }): Observable<{ success: boolean; message: string; profileId: number }>;
}
interface EmailService {
  SendConfirmationEmail(data: {
    to: string;
    token: string;
  }): Observable<{ success: boolean; message: string }>;
  SendOTPEmail(data: {
    to: string;
    otp: string;
  }): Observable<{ success: boolean; message: string }>;
}
@Injectable()
export class AuthService {
  private userService: UserService;
  private emailService: EmailService;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    @Inject('USER_SERVICE') private readonly userClient: ClientGrpc,
    @Inject('EMAIL_SERVICE') private readonly emailClient: ClientGrpc,
  ) {}
  onModuleInit() {
    try {
      this.userService = this.userClient.getService<UserService>('UserService');
      console.log('AuthService: userService initialized');

      this.emailService =
        this.emailClient.getService<EmailService>('EmailService');
      console.log('AuthService: emailGrpcService initialized');
    } catch (err) {
      console.error('AuthService.onModuleInit error:', err);
    }
  }

  async register(createUserDto: CreateRiderDto | CreateDriverDto) {
    try {
      const { email, password, role, firstName, lastName, mobileNumber } =
        createUserDto;

      // Validate required fields
      if (
        !email ||
        !password ||
        !firstName ||
        !lastName ||
        !mobileNumber ||
        !role
      ) {
        throw new RpcException('All required fields must be provided.');
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Variable to store created user
      let user: any;
      // ------------------ RIDER ------------------
      if (role === Role.RIDER) {
        const existing = await this.prisma.rider.findUnique({
          where: { email },
        });
        if (existing) throw new RpcException('Rider already exists.');

        user = await this.prisma.rider.create({
          data: {
            email,
            password: hashedPassword,
            firstName,
            lastName,
            mobileNumber,
            role,
          },
        });

        // ------------------ DRIVER ------------------
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

        // ------------------ ADMIN ------------------
      } else if (role === Role.ADMIN) {
        const existing = await this.prisma.admin.findUnique({
          where: { email },
        });
        if (existing) throw new RpcException('Admin already exists.');

        user = await this.prisma.admin.create({
          data: {
            email,
            password: hashedPassword,
            firstName,
            lastName, // Admin model has 'name' instead of firstName/lastName
            role,
          },
        });

        // ------------------ INVALID ROLE ------------------
      } else {
        throw new RpcException('Invalid role provided.');
      }

      // ------------------ EMAIL CONFIRMATION TOKEN ------------------
      const token = this.jwtService.sign(
        { email, type: 'emailConfirmation' },
        {
          secret: process.env.JWT_ACCESS_SECRET,
          expiresIn: process.env.JWT_EMAIL_CONFIRMATION_EXPIRATION as any,
        },
      );

      console.log('Generated email confirmation token:', token);

      // Send confirmation email
      await firstValueFrom(
        this.emailService.SendConfirmationEmail({ to: email, token }),
      );

      // Return success response
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

  async login(loginDto: LoginDto) {
    try {
      const { email, password } = loginDto;

      if (!email || !password)
        throw new RpcException('Email and password are required.');

      let user: any = null;

      // Determine the user by querying each role (Rider, Driver, Admin)
      user = await this.prisma.rider.findUnique({
        where: { email },
      });

      // If not found in Rider, try to find in Driver, then Admin
      if (!user)
        user = await this.prisma.driver.findUnique({ where: { email } });
      if (!user)
        user = await this.prisma.admin.findUnique({ where: { email } });

      if (!user) throw new RpcException('User not found.');

      // Ensure the user is confirmed
      if (!user.isConfirmed) {
        console.error('User tried to login without confirming email:', email);
        return {
          status: 'error',
          message: 'Please confirm your email before logging in.',
        };
      }

      // Check if the password is valid
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) throw new RpcException('Invalid password');

      // Generate access and refresh tokens
      const accessToken = this.jwtService.sign(
        { email: user.email, role: user.role, id: user.id },
        {
          secret: process.env.JWT_ACCESS_SECRET,
          expiresIn: parseExpiration(process.env.JWT_ACCESS_EXPIRATION),
        },
      );

      // Before creating a new refresh token:
      // await this.prisma.refreshToken.updateMany({
      //   where: {
      //     riderId: user.role === Role.RIDER ? user.id : null,
      //     driverId: user.role === Role.DRIVER ? user.id : null,
      //     adminId: user.role === Role.ADMIN ? user.id : null,
      //     isUsed: false,
      //     isRevoked: false,
      //   },
      //   data: { isUsed: true, isRevoked: true },
      // });

      const refreshToken = this.jwtService.sign(
        { email: user.email, role: user.role, id: user.id, type: 'refresh' },
        {
          secret: process.env.JWT_REFRESH_SECRET,
          expiresIn: parseExpiration(process.env.JWT_REFRESH_EXPIRATION),
        },
      );
      // ---- Hash the refresh token before storing ----
      const hashedRefreshToken = await argon2.hash(refreshToken);

      // Store the refresh token in the RefreshToken table with proper expiration, one-time use
      await this.prisma.refreshToken.create({
        data: {
          token: hashedRefreshToken,
          riderId: user.role === Role.RIDER ? user.id : null,
          driverId: user.role === Role.DRIVER ? user.id : null,
          adminId: user.role === Role.ADMIN ? user.id : null,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days expiration
          isUsed: false,
          isRevoked: false,
        },
      });

      // Return response with generated tokens and role
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

  async refreshToken(oldRefreshToken: string) {
    if (!oldRefreshToken) {
      throw new RpcException('Refresh token is required.');
    }

    let payload: any;
    try {
      payload = await this.jwtService.verifyAsync(oldRefreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });
    } catch (err) {
      throw new RpcException('Invalid or expired refresh token.');
    }

    if (payload.type !== 'refresh') {
      throw new RpcException('Invalid token type.');
    }

    // Fetch all active tokens for this user
    const tokens = await this.prisma.refreshToken.findMany({
      where: {
        riderId: payload.role === Role.RIDER ? payload.id : null,
        driverId: payload.role === Role.DRIVER ? payload.id : null,
        adminId: payload.role === Role.ADMIN ? payload.id : null,
        isUsed: false,
        isRevoked: false,
        expiresAt: { gt: new Date() },
      },
    });

    if (!tokens.length) {
      throw new RpcException(
        'Invalid, expired, or already used refresh token.',
      );
    }

    // Verify hashed token
    let tokenRecord: RefreshToken | null = null;
    for (const record of tokens) {
      const isMatch = await argon2.verify(record.token, oldRefreshToken);
      if (isMatch) {
        tokenRecord = record;
        break;
      }
    }

    if (!tokenRecord) {
      throw new RpcException('Invalid refresh token.');
    }

    // Invalidate old token
    await this.prisma.refreshToken.update({
      where: { id: tokenRecord.id },
      data: { isUsed: true, isRevoked: true },
    });

    // Generate new access token
    const newAccessToken = this.jwtService.sign(
      {
        id: payload.id,
        email: payload.email,
        role: payload.role,
        type: 'access',
      },
      {
        secret: process.env.JWT_ACCESS_SECRET,
        expiresIn: parseExpiration(process.env.JWT_ACCESS_EXPIRATION),
      },
    ); // Invalidate all old refresh tokens BEFORE creating a new one
    // await this.prisma.refreshToken.updateMany({
    //   where: {
    //     riderId: payload.role === Role.RIDER ? payload.id : null,
    //     driverId: payload.role === Role.DRIVER ? payload.id : null,
    //     adminId: payload.role === Role.ADMIN ? payload.id : null,
    //     isUsed: false,
    //     isRevoked: false,
    //   },
    //   data: { isUsed: true, isRevoked: true },
    // });

    // Generate new refresh token (raw)
    const newRefreshToken = this.jwtService.sign(
      {
        id: payload.id,
        email: payload.email,
        role: payload.role,
        type: 'refresh',
      },
      {
        secret: process.env.JWT_REFRESH_SECRET,
        expiresIn: parseExpiration(process.env.JWT_REFRESH_EXPIRATION),
      },
    );

    // Hash the refresh token before storing
    const hashedToken = await argon2.hash(newRefreshToken);

    const refreshExpiresMs = ms(
      parseExpiration(process.env.JWT_REFRESH_EXPIRATION),
    );
    const expiresAt = new Date(Date.now() + refreshExpiresMs);

    await this.prisma.refreshToken.create({
      data: {
        token: hashedToken,
        riderId: payload.role === Role.RIDER ? payload.id : null,
        driverId: payload.role === Role.DRIVER ? payload.id : null,
        adminId: payload.role === Role.ADMIN ? payload.id : null,
        isUsed: false,
        isRevoked: false,
        expiresAt,
      },
    });

    // Return tokens to client (raw refresh token)
    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }
  async logout(refreshToken: string) {
    try {
      if (!refreshToken) {
        // ✅ Always return an object
        return { status: 'success', message: 'Logged out' };
      }

      // Decode token to get user info
      let payload: any;
      try {
        payload = await this.jwtService.verifyAsync(refreshToken, {
          secret: process.env.JWT_REFRESH_SECRET,
        });
      } catch {
        // Expired token → still consider logout successful
        return { status: 'success', message: 'Logged out' };
      }

      // Revoke all active refresh tokens for this user
      await this.prisma.refreshToken.updateMany({
        where: {
          riderId: payload.role === Role.RIDER ? payload.id : null,
          driverId: payload.role === Role.DRIVER ? payload.id : null,
          adminId: payload.role === Role.ADMIN ? payload.id : null,
          isUsed: false,
          isRevoked: false,
        },
        data: {
          isUsed: true,
          isRevoked: true,
        },
      });

      return { status: 'success', message: 'Logged out' };
    } catch (err) {
      console.error('Logout Error:', err);
      return { status: 'error', message: 'Failed to logout' };
    }
  }

  /** Confirm user or driver registration */
  async confirmRegistration(token: string) {
    try {
      // Decode token
      const payload = this.jwtService.verify(token, {
        secret: process.env.JWT_ACCESS_SECRET,
      });

      if (payload.type !== 'emailConfirmation') {
        throw new RpcException('Invalid token type.');
      }

      const email = payload.email;
      let updatedAccount: any = null; // allow any account type (rider/driver/admin)

      // Try Rider first
      const rider = await this.prisma.rider.findUnique({ where: { email } });
      if (rider) {
        updatedAccount = await this.prisma.rider.update({
          where: { email },
          data: { isConfirmed: true },
        });
      }

      // Try Driver
      const driver = await this.prisma.driver.findUnique({ where: { email } });
      if (driver) {
        updatedAccount = await this.prisma.driver.update({
          where: { email },
          data: { isConfirmed: true },
        });
      }

      // Try Admin (no isConfirmed field)
      const admin = await this.prisma.admin.findUnique({ where: { email } });
      if (admin) {
        updatedAccount = admin;
      }

      if (!updatedAccount) {
        throw new RpcException('Account not found.');
      }
      // Notify User-Service to create the profile
      // ✅ Call gRPC properly
      // ---------- gRPC: CreateProfile ----------
      console.log(
        'AuthService.confirmRegistration updatedAccount:',
        updatedAccount,
      );

      // ---- gRPC call to User-Service ----
      // Defensive check: ensure userService is ready
      if (!this.userService) {
        console.error(
          'AuthService.confirmRegistration: userService is NOT initialized',
        );
      } else {
        try {
          console.log('AuthService: calling userService.createProfile with', {
            userId: updatedAccount.id,
            email: updatedAccount.email,
            role: updatedAccount.role,
            firstName: updatedAccount.firstName ?? updatedAccount.name ?? '',
            lastName: updatedAccount.lastName ?? '',
          });

          const payload = {
            userId: Number(updatedAccount.id),
            email: updatedAccount.email ?? '',
            role: updatedAccount.role ?? 'RIDER',
            firstName: updatedAccount.firstName ?? updatedAccount.name ?? '',
            lastName: updatedAccount.lastName ?? '',
            profilePhoto: updatedAccount.profilePhoto ?? '',
            mobileNumber: updatedAccount.mobileNumber ?? '',
            bio: updatedAccount.bio ?? '',
            address: updatedAccount.address ?? '',
          };

          const result = await firstValueFrom(
            this.userService.createProfile(payload),
            { defaultValue: null }, // avoid unhandled promise if not emit
          );

          console.log('AuthService: createProfile result:', result);
        } catch (err) {
          console.error(
            'AuthService: createProfile gRPC error (stack):',
            err?.stack ?? err,
          );
        }
      }

      return { message: 'Email successfully confirmed. You can now log in.' };
    } catch (error) {
      console.error('Confirm Registration Error:', error);
      throw new RpcException('Invalid or expired token.');
    }
  }

  // Forgot Password: Generate OTP and send to user's email
  async forgotPassword(email: string) {
    try {
      // Find the account (Rider, Driver)
      const account =
        (await this.prisma.rider.findUnique({ where: { email } })) ||
        (await this.prisma.driver.findUnique({ where: { email } }));

      if (!account) throw new RpcException('Account not found.');

      // Determine the type (Rider or Driver)
      const type: 'RIDER' | 'DRIVER' =
        account.role === 'DRIVER' ? 'DRIVER' : 'RIDER';

      // Generate 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      console.log(`✅ OTP for ${email}: ${otp}`);

      // OTP expiry: 10 minutes from now
      const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

      // Save OTP and expiry in DB
      if (type === 'RIDER') {
        await this.prisma.rider.update({
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
      await firstValueFrom(this.emailService.SendOTPEmail({ to: email, otp }));

      return { message: 'OTP sent to your email. It is valid for 10 minutes.' };
    } catch (error) {
      console.error('Forgot Password Error:', error);
      throw new RpcException('Failed to process forgot password.');
    }
  }

  // Reset Password: Validate OTP and set new password
  async resetPassword(email: string, otp: string, newPassword: string) {
    try {
      // Find the account (Rider, Driver)
      const account =
        (await this.prisma.rider.findUnique({ where: { email } })) ||
        (await this.prisma.driver.findUnique({ where: { email } }));

      if (!account) throw new RpcException('Account not found.');

      // Determine type (Rider or Driver)
      const type: 'RIDER' | 'DRIVER' =
        account.role === 'DRIVER' ? 'DRIVER' : 'RIDER';

      // Validate OTP
      if (account.otp !== otp) throw new RpcException('Invalid OTP.');
      if (!account.otpExpiry || new Date(account.otpExpiry) < new Date()) {
        throw new RpcException('OTP has expired.');
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password and clear OTP
      if (type === 'RIDER') {
        await this.prisma.rider.update({
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
      throw new RpcException('Failed to reset password.');
    }
  }
  private async findUserByEmail(email: string) {
    const rider = await this.prisma.rider.findUnique({ where: { email } });
    if (rider) return { ...rider, type: 'RIDER' };

    const driver = await this.prisma.driver.findUnique({ where: { email } });
    if (driver) return { ...driver, type: 'DRIVER' };

    const admin = await this.prisma.admin.findUnique({ where: { email } });
    if (admin) return { ...admin, type: 'ADMIN' };

    return null;
  }

  async resetPasswordWithoutOtp(
    email: string,
    currentPassword: string,
    newPassword: string,
  ) {
    try {
      // Find the account (Rider, Driver, Admin)
      const account =
        (await this.prisma.rider.findUnique({ where: { email } })) ||
        (await this.prisma.driver.findUnique({ where: { email } })) ||
        (await this.prisma.admin.findUnique({ where: { email } }));

      if (!account) throw new RpcException('Account not found.');

      // Check current password
      const isPasswordValid = await bcrypt.compare(
        currentPassword,
        account.password,
      );
      if (!isPasswordValid)
        throw new RpcException('Current password is incorrect.');

      // Hash the new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password
      if (account.role === 'RIDER') {
        await this.prisma.rider.update({
          where: { email },
          data: { password: hashedPassword },
        });
      } else if (account.role === 'DRIVER') {
        await this.prisma.driver.update({
          where: { email },
          data: { password: hashedPassword },
        });
      } else if (account.role === 'ADMIN') {
        await this.prisma.admin.update({
          where: { email },
          data: { password: hashedPassword },
        });
      }

      return { message: 'Password updated successfully.' };
    } catch (error) {
      console.error('Reset Password Without OTP Error:', error);
      throw new RpcException(error.message || 'Failed to reset password.');
    }
  }
}
