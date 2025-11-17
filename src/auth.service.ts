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
import { Inject, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from './prisma.service';
import * as argon2 from 'argon2';
import { CreateDriverDto } from './dto/create-driver.dto';
import { LoginDto } from './dto/login.dto';
import { Role } from './dto/role.enum';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { EmailService } from './email/email.service';
import { CreateRiderDto } from './dto/create-rider.dto';
import { RefreshToken } from './common/user.interface';

interface AuthenticatedRequest extends Request {
  cookies: Record<string, string>;
}
@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailService,

    //inject user microservice
    @Inject('USER_SERVICE') private readonly userClient: ClientProxy,
  ) {}

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
            name: `${firstName} ${lastName}`, // Admin model has 'name' instead of firstName/lastName
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
          expiresIn: '1h',
        },
      );

      console.log('Generated email confirmation token:', token);

      // Send confirmation email
      await this.emailService.sendConfirmationEmail(email, token);

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
        { secret: process.env.JWT_ACCESS_SECRET, expiresIn: '1m' },
      );

      const refreshToken = this.jwtService.sign(
        { email: user.email, role: user.role, id: user.id, type: 'refresh' },
        { secret: process.env.JWT_REFRESH_SECRET, expiresIn: '7d' },
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
        expiresIn: '1m',
      },
    );

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
        expiresIn: '7d',
      },
    );

    // Hash the refresh token before storing
    const hashedToken = await argon2.hash(newRefreshToken);

    await this.prisma.refreshToken.create({
      data: {
        token: hashedToken,
        riderId: payload.role === Role.RIDER ? payload.id : null,
        driverId: payload.role === Role.DRIVER ? payload.id : null,
        adminId: payload.role === Role.ADMIN ? payload.id : null,
        isUsed: false,
        isRevoked: false,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
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

      // Decode token
      let payload: any;
      try {
        payload = await this.jwtService.verifyAsync(refreshToken, {
          secret: process.env.JWT_REFRESH_SECRET,
        });
      } catch {
        // Expired token → still consider logout successful
        return { status: 'success', message: 'Logged out' };
      }

      // Find active tokens for user
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

      // Revoke matching token
      for (const t of tokens) {
        try {
          if (await argon2.verify(t.token, refreshToken)) {
            await this.prisma.refreshToken.update({
              where: { id: t.id },
              data: { isUsed: true, isRevoked: true },
            });
            break;
          }
        } catch {
          continue; // skip invalid/corrupted hashes
        }
      }

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

      return { message: 'Email successfully confirmed. You can now log in.' };
    } catch (error) {
      console.error('Confirm Registration Error:', error);
      throw new RpcException('Invalid or expired token.');
    }
  }

  async getUserProfile(userId: number, role: Role) {
    return this.userClient
      .send('get-profile', { userId, role }) // <--- RPC call to user-service
      .toPromise(); // convert Observable to Promise
  }
  // /** Get all users */
  // async getAllRiders() {
  //   try {
  //     return await this.prisma.rider.findMany({
  //       select: {
  //         id: true,
  //         email: true,
  //         firstName: true,
  //         lastName: true,
  //         mobileNumber: true,
  //         role: true,
  //       },
  //     });
  //   } catch (error) {
  //     console.error('Get All Users Error:', error);
  //     throw new RpcException('Failed to fetch users.');
  //   }
  // }

  // /** Get user by email */
  // async getRiderByEmail(email: string) {
  //   try {
  //     const rider = await this.prisma.rider.findUnique({
  //       where: { email },
  //       select: {
  //         id: true,
  //         email: true,
  //         firstName: true,
  //         lastName: true,
  //         mobileNumber: true,
  //         role: true,
  //       },
  //     });
  //     if (!rider) throw new RpcException('User not found.');
  //     return rider;
  //   } catch (error) {
  //     console.error('Get User By Email Error:', error);
  //     throw new RpcException('Failed to fetch user.');
  //   }
  // }

  // /** Get all drivers */
  // async getAllDrivers() {
  //   try {
  //     return await this.prisma.driver.findMany({
  //       select: {
  //         id: true,
  //         email: true,
  //         firstName: true,
  //         lastName: true,
  //         mobileNumber: true,
  //         role: true,
  //         drivingLicense: true,
  //       },
  //     });
  //   } catch (error) {
  //     console.error('Get All Drivers Error:', error);
  //     throw new RpcException('Failed to fetch drivers.');
  //   }
  // }

  // /** Get driver by email */
  // async getDriverByEmail(email: string) {
  //   try {
  //     const driver = await this.prisma.driver.findUnique({
  //       where: { email },
  //       select: {
  //         id: true,
  //         email: true,
  //         firstName: true,
  //         lastName: true,
  //         mobileNumber: true,
  //         role: true,
  //         drivingLicense: true,
  //       },
  //     });
  //     if (!driver) throw new RpcException('Driver not found.');
  //     return driver;
  //   } catch (error) {
  //     console.error('Get Driver By Email Error:', error);
  //     throw new RpcException('Failed to fetch driver.');
  //   }
  // }

  // async getProfile(userId: number, role: Role) {
  //   try {
  //     // Validate the role to ensure it's one of the allowed roles
  //     if (![Role.RIDER, Role.DRIVER, Role.ADMIN].includes(role)) {
  //       throw new RpcException('Invalid role provided.');
  //     }

  //     // Common fields for all roles
  //     const selectFields = {
  //       id: true,
  //       email: true,
  //       role: true,
  //       isConfirmed: true,
  //       firstName: true,
  //       lastName: true,
  //       mobileNumber: true,
  //       profilePhoto: true, // optional field for profile photo
  //     };

  //     let user;
  //     switch (role) {
  //       case Role.RIDER:
  //         user = await this.prisma.rider.findUnique({
  //           where: { id: userId },
  //           select: selectFields,
  //         });
  //         if (!user)
  //           throw new RpcException(`Rider with ID ${userId} not found.`);
  //         break;

  //       case Role.DRIVER:
  //         user = await this.prisma.driver.findUnique({
  //           where: { id: userId },
  //           select: {
  //             ...selectFields,
  //             drivingLicense: true, // Driver-specific field
  //           },
  //         });
  //         if (!user)
  //           throw new RpcException(`Driver with ID ${userId} not found.`);
  //         break;

  //       case Role.ADMIN:
  //         user = await this.prisma.admin.findUnique({
  //           where: { id: userId },
  //           select: {
  //             ...selectFields,
  //             name: true, // Admin uses 'name' instead of firstName/lastName
  //           },
  //         });
  //         if (!user)
  //           throw new RpcException(`Admin with ID ${userId} not found.`);
  //         break;

  //       default:
  //         throw new RpcException('Invalid role provided.');
  //     }

  //     return user; // Return the user profile data
  //   } catch (error) {
  //     console.error('Get Profile Error:', error);
  //     throw new RpcException(error.message || 'Failed to fetch profile.');
  //   }
  // }

  // /** Get admin */
  // async getAdmin() {
  //   try {
  //     const admin = await this.prisma.admin.findFirst({
  //       select: {
  //         id: true,
  //         name: true,
  //         email: true,
  //         role: true,
  //       },
  //     });
  //     if (!admin) throw new RpcException('Admin not found.');
  //     return admin;
  //   } catch (error) {
  //     console.error('Get Admin Error:', error);
  //     throw new RpcException('Failed to fetch admin.');
  //   }
  // }

  // async forgotPassword(email: string) {
  //   try {
  //     // Find the account (Rider, Driver, or Admin if needed)
  //     const account =
  //       (await this.prisma.rider.findUnique({ where: { email } })) ||
  //       (await this.prisma.driver.findUnique({ where: { email } }));

  //     if (!account) throw new RpcException('Account not found.');

  //     // Determine the type
  //     const type: 'RIDER' | 'DRIVER' =
  //       account.role === 'DRIVER' ? 'DRIVER' : 'RIDER';

  //     // Generate 6-digit OTP
  //     const otp = Math.floor(100000 + Math.random() * 900000).toString();
  //     console.log(`✅ OTP for ${email}: ${otp}`);

  //     // OTP expiry 10 minutes from now
  //     const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

  //     // Save OTP and expiry in DB
  //     if (type === 'RIDER') {
  //       await this.prisma.rider.update({
  //         where: { email },
  //         data: { otp, otpExpiry },
  //       });
  //     } else {
  //       await this.prisma.driver.update({
  //         where: { email },
  //         data: { otp, otpExpiry },
  //       });
  //     }

  //     // Send OTP email
  //     await this.emailService.sendOTPEmail(email, otp);

  //     return { message: 'OTP sent to your email. It is valid for 10 minutes.' };
  //   } catch (error) {
  //     console.error('Forgot Password Error:', error);
  //     throw new RpcException('Failed to process forgot password.');
  //   }
  // }
  // async resetPassword(email: string, otp: string, newPassword: string) {
  //   try {
  //     // Find the account (Rider or Driver)
  //     const account =
  //       (await this.prisma.rider.findUnique({ where: { email } })) ||
  //       (await this.prisma.driver.findUnique({ where: { email } }));

  //     if (!account) throw new RpcException('Account not found.');

  //     // Determine type
  //     const type: 'RIDER' | 'DRIVER' =
  //       account.role === 'DRIVER' ? 'DRIVER' : 'RIDER';

  //     // Validate OTP
  //     // Validate OTP
  //     if (account.otp !== otp) throw new RpcException('Invalid OTP.');
  //     if (!account.otpExpiry || new Date(account.otpExpiry) < new Date())
  //       throw new RpcException('OTP has expired.');

  //     // Hash new password
  //     const hashedPassword = await bcrypt.hash(newPassword, 10);

  //     // Update password and clear OTP
  //     if (type === 'RIDER') {
  //       await this.prisma.rider.update({
  //         where: { email },
  //         data: { password: hashedPassword, otp: null, otpExpiry: null },
  //       });
  //     } else {
  //       await this.prisma.driver.update({
  //         where: { email },
  //         data: { password: hashedPassword, otp: null, otpExpiry: null },
  //       });
  //     }

  //     return { message: 'Password reset successfully.' };
  //   } catch (error) {
  //     console.error('Reset Password Error:', error);
  //     throw new RpcException(error.message || 'Failed to reset password.');
  //   }
  // }
}
