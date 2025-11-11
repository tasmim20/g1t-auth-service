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
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from './prisma.service';
import * as argon2 from 'argon2';
import { CreateDriverDto } from './dto/create-driver.dto';
import { LoginDto } from './dto/login.dto';
import { Role } from './dto/role.enum';
import { RpcException } from '@nestjs/microservices';
import { EmailService } from './email/email.service';
import { CreateRiderDto } from './dto/create-rider.dto';

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

  // async register(createUserDto: CreateRiderDto | CreateDriverDto) {
  //   try {
  //     const { email, password, role, firstName, lastName, mobileNumber } =
  //       createUserDto;

  //     if (
  //       !email ||
  //       !password ||
  //       !firstName ||
  //       !lastName ||
  //       !mobileNumber ||
  //       !role
  //     ) {
  //       throw new RpcException('All required fields must be provided.');
  //     }

  //     const hashedPassword = await bcrypt.hash(password, 10);
  //     let user;

  //     if (role === Role.RIDER) {
  //       // changed from USER → RIDER
  //       const existing = await this.prisma.rider.findUnique({
  //         where: { email },
  //       }); // prisma.rider
  //       if (existing) throw new RpcException('Rider already exists.');

  //       user = await this.prisma.rider.create({
  //         data: {
  //           email,
  //           password: hashedPassword,
  //           firstName,
  //           lastName,
  //           mobileNumber,
  //           role,
  //         },
  //       });
  //     } else if (role === Role.DRIVER) {
  //       const driverDto = createRiderDto as CreateDriverDto;
  //       if (!driverDto.drivingLicense)
  //         throw new RpcException('Driving license required for drivers.');

  //       const existing = await this.prisma.driver.findUnique({
  //         where: { email },
  //       });
  //       if (existing)
  //         throw new RpcException('Driver already registered with this email.');

  //       user = await this.prisma.driver.create({
  //         data: {
  //           email: driverDto.email,
  //           password: hashedPassword,
  //           firstName: driverDto.firstName,
  //           lastName: driverDto.lastName,
  //           mobileNumber: driverDto.mobileNumber,
  //           role: driverDto.role,
  //           drivingLicense: driverDto.drivingLicense,
  //         },
  //       });
  //     } else if (role === Role.ADMIN) {
  //       const existing = await this.prisma.user.findUnique({
  //         where: { email },
  //       });
  //       if (existing) throw new RpcException('Admin already exists.');

  //       user = await this.prisma.user.create({
  //         data: {
  //           email,
  //           password: hashedPassword,
  //           firstName,
  //           lastName,
  //           mobileNumber,
  //           role,
  //         },
  //       });
  //     } else {
  //       throw new RpcException('Invalid role provided.');
  //     }

  //     // Generate email confirmation token
  //     const token = this.jwtService.sign(
  //       { email, type: 'emailConfirmation' },
  //       {
  //         secret: process.env.JWT_ACCESS_SECRET,
  //         expiresIn: '1h',
  //       },
  //     );

  //     console.log('Generated token:', token);

  //     // Send confirmation email
  //     await this.emailService.sendConfirmationEmail(email, token);

  //     return {
  //       message: `${role.charAt(0).toUpperCase() + role.slice(1)} registered successfully`,
  //       user,
  //     };
  //   } catch (error) {
  //     console.error('Registration Error:', error);
  //     throw error instanceof RpcException
  //       ? error
  //       : new RpcException('Failed to register. Please try again later.');
  //   }
  // }

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

  // async login(loginDto: LoginDto) {
  //   try {
  //     const { email, password } = loginDto;

  //     if (!email || !password)
  //       throw new RpcException('Email and password are required.');
  //     let user: any = await this.prisma.rider.findUnique({ where: { email } });
  //     if (!user)
  //       user = await this.prisma.driver.findUnique({ where: { email } });
  //     if (!user)
  //       user = await this.prisma.admin.findUnique({ where: { email } });

  //     if (!user) throw new RpcException('User not found.');

  //     if (!user.isConfirmed) {
  //       console.error('User tried to login without confirming email:', email);
  //       return {
  //         status: 'error',
  //         message: 'Please confirm your email before logging in.',
  //       };
  //     }
  //     const isPasswordValid = await bcrypt.compare(password, user.password);
  //     if (!isPasswordValid) throw new RpcException('Invalid password');

  //     // const payload = { email: user.email, role: user.role };

  //     // Create access and refresh tokens
  //     // ✅ Generate tokens
  //     const accessToken = this.jwtService.sign(
  //       { email: user.email, role: user.role, id: user.id },
  //       { secret: process.env.JWT_ACCESS_SECRET, expiresIn: '30s' },
  //     );

  //     // Generate refresh token (long-lived)
  //     const refreshToken = this.jwtService.sign(
  //       { email: user.email, role: user.role, id: user.id },
  //       { secret: process.env.JWT_REFRESH_SECRET, expiresIn: '7d' },
  //     );

  //     // ✅ Hash and store refresh token
  //     // const hashedRefresh = await argon2.hash(refreshToken);
  //     await this.prisma.rider.update({
  //       where: { email: user.email },
  //       data: { refreshToken: refreshToken },
  //     });
  //     if (user.role === Role.DRIVER) {
  //       await this.prisma.driver.update({
  //         where: { email: user.email },
  //         data: { refreshToken: refreshToken },
  //       });
  //     } else if (user.role === Role.RIDER || user.role === Role.ADMIN) {
  //       await this.prisma.rider.update({
  //         where: { email: user.email }, // use user.email, not rider.email
  //         data: { refreshToken: refreshToken },
  //       });
  //     }
  //     // Save refresh token in table
  //     await this.prisma.refreshToken.create({
  //       data: {
  //         token: refreshToken,
  //         riderId: user.role === Role.RIDER ? user.id : null,
  //         driverId: user.role === Role.DRIVER ? user.id : null,
  //         adminId: user.role === Role.ADMIN ? user.id : null,
  //         expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  //         isUsed: false,
  //         isRevoked: false, // 7 days
  //       },
  //     });
  //     // Return access token to client
  //     return {
  //       message: 'Login successful',
  //       accessToken,
  //       refreshToken,
  //       role: user.role,
  //     };
  //   } catch (error) {
  //     console.error('Login Error:', error);
  //     throw error instanceof RpcException
  //       ? error
  //       : new RpcException('Failed to login. Please try again later.');
  //   }
  // }

  // async revokeAllUserTokens(userId: number, role: Role) {
  //   try {
  //     // Determine the correct field based on role
  //     const whereClause: any = {
  //       isUsed: false,
  //       isRevoked: false,
  //     };

  //     if (role === Role.RIDER) whereClause.riderId = userId;
  //     if (role === Role.DRIVER) whereClause.driverId = userId;
  //     if (role === Role.ADMIN) whereClause.adminId = userId;

  //     // Revoke all active tokens for this user
  //     const updatedCount = await this.prisma.refreshToken.updateMany({
  //       where: whereClause,
  //       data: {
  //         isRevoked: true,
  //         isUsed: true, // optional: mark as used to prevent reuse
  //       },
  //     });

  //     console.log(
  //       `Revoked tokens count for user ${userId}:`,
  //       updatedCount.count,
  //     );
  //   } catch (error) {
  //     console.error(`Failed to revoke tokens for user ${userId}:`, error);
  //     throw new RpcException('Failed to revoke user tokens.');
  //   }
  // }
  // async refreshToken(oldRefreshToken: string) {
  //   try {
  //     // 1️⃣ Verify the provided refresh token strictly with the refresh secret
  //     const payload: any = await this.jwtService.verifyAsync(oldRefreshToken, {
  //       secret: process.env.JWT_REFRESH_SECRET, // Only refresh secret
  //     });

  //     console.log('Requested refresh token:', oldRefreshToken); // Log the requested refresh token

  //     // 2️⃣ Find the refresh token record in the RefreshToken table
  //     const tokenRecord = await this.prisma.refreshToken.findFirst({
  //       where: {
  //         token: oldRefreshToken, // Compare the provided token with the stored token
  //         isUsed: false, // Ensure it's not already used
  //         isRevoked: false, // Ensure it's not revoked
  //         expiresAt: { gt: new Date() }, // Ensure it's not expired
  //       },
  //     });

  //     console.log('Stored token record from DB:', tokenRecord); // Log the token record from DB

  //     if (!tokenRecord) {
  //       throw new RpcException(
  //         'Invalid, expired, or already used refresh token.',
  //       );
  //     }

  //     // 3️⃣ Immediately invalidate the old refresh token (mark as used and revoked)
  //     await this.prisma.refreshToken.update({
  //       where: { id: tokenRecord.id },
  //       data: { isUsed: true, isRevoked: true }, // Mark the token as used and revoked
  //     });

  //     // 4️⃣ Generate new access token and refresh token
  //     const newAccessToken = this.jwtService.sign(
  //       {
  //         id: payload.id,
  //         email: payload.email,
  //         role: payload.role,
  //         type: 'access',
  //       },
  //       { secret: process.env.JWT_ACCESS_SECRET, expiresIn: '30s' },
  //     );

  //     const newRefreshToken = this.jwtService.sign(
  //       {
  //         id: payload.id,
  //         email: payload.email,
  //         role: payload.role,
  //         type: 'refresh',
  //       },
  //       { secret: process.env.JWT_REFRESH_SECRET, expiresIn: '7d' },
  //     );

  //     // 5️⃣ Update the user's refresh token field in the user table (Rider, Driver, or Admin table)
  //     if (payload.role === Role.RIDER) {
  //       await this.prisma.rider.update({
  //         where: { id: payload.id },
  //         data: { refreshToken: newRefreshToken }, // Update the refreshToken field in Rider table
  //       });
  //     } else if (payload.role === Role.DRIVER) {
  //       await this.prisma.driver.update({
  //         where: { id: payload.id },
  //         data: { refreshToken: newRefreshToken }, // Update the refreshToken field in Driver table
  //       });
  //     }

  //     // 6️⃣ Save the new refresh token in the RefreshToken table
  //     await this.prisma.refreshToken.create({
  //       data: {
  //         token: newRefreshToken,
  //         riderId: payload.role === Role.RIDER ? payload.id : null,
  //         driverId: payload.role === Role.DRIVER ? payload.id : null,
  //         adminId: payload.role === Role.ADMIN ? payload.id : null,
  //         isUsed: false,
  //         isRevoked: false,
  //         expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days expiration
  //       },
  //     });

  //     // 7️⃣ Return the new access token and refresh token
  //     return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  //   } catch (error) {
  //     console.error('Refresh token error:', error);
  //     throw new RpcException('Invalid or expired refresh token.');
  //   }
  // }

  // Ensure token is invalidated first before creating new ones
  // async refreshToken(oldRefreshToken: string) {
  //   try {
  //     // 1️⃣ Verify the old refresh token
  //     const payload: any = await this.jwtService
  //       .verifyAsync(oldRefreshToken, {
  //         secret: process.env.JWT_REFRESH_SECRET,
  //       })
  //       .catch((error) => {
  //         console.error('Error verifying token:', error);
  //         throw new RpcException('Invalid or expired refresh token.');
  //       });

  //     console.log('Payload:', payload); // Log the payload for debugging

  //     // 2️⃣ Use transaction to ensure token is marked as used atomically
  //     const tokenRecord = await this.prisma.$transaction(async (prisma) => {
  //       // Find the latest valid token for the user and role
  //       const token = await prisma.refreshToken.findFirst({
  //         where: {
  //           riderId: payload.role === Role.RIDER ? payload.id : null,
  //           driverId: payload.role === Role.DRIVER ? payload.id : null,
  //           adminId: payload.role === Role.ADMIN ? payload.id : null,
  //           isUsed: false,
  //           isRevoked: false,
  //         },
  //         orderBy: { createdAt: 'desc' },
  //       });

  //       if (!token) {
  //         console.log('No valid token found');
  //         throw new RpcException('Invalid or expired refresh token.');
  //       }

  //       console.log('Token record:', token); // Log the token record for debugging

  //       // Mark token as used and revoked in the same transaction
  //       await prisma.refreshToken.updateMany({
  //         where: {
  //           id: token.id,
  //           isUsed: false,
  //           isRevoked: false,
  //         },
  //         data: { isUsed: true, isRevoked: true }, // Prevent reuse of this token
  //       });

  //       return token; // Return the token to be used for generating new tokens
  //     });

  //     // 3️⃣ Generate new tokens
  //     const newAccessToken = this.jwtService.sign(
  //       { id: payload.id, email: payload.email, role: payload.role },
  //       { secret: process.env.JWT_ACCESS_SECRET, expiresIn: '30s' },
  //     );

  //     const newRefreshToken = this.jwtService.sign(
  //       { id: payload.id, email: payload.email, role: payload.role },
  //       { secret: process.env.JWT_REFRESH_SECRET, expiresIn: '7d' },
  //     );

  //     console.log('New refresh token:', newRefreshToken); // Log the new refresh token

  //     // 4️⃣ Store the new refresh token directly in the DB
  //     await this.prisma.refreshToken.create({
  //       data: {
  //         riderId: payload.role === Role.RIDER ? payload.id : null,
  //         driverId: payload.role === Role.DRIVER ? payload.id : null,
  //         adminId: payload.role === Role.ADMIN ? payload.id : null,
  //         token: newRefreshToken, // Store the token directly (no hashing)
  //         isUsed: false,
  //         isRevoked: false,
  //         expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days expiration
  //       },
  //     });

  //     // 5️⃣ Return new tokens
  //     return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  //   } catch (error) {
  //     console.error('Refresh token error:', error);
  //     throw new RpcException('Invalid or expired refresh token.');
  //   }
  // }

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

      // Store the refresh token in the RefreshToken table with proper expiration, one-time use
      await this.prisma.refreshToken.create({
        data: {
          token: refreshToken,
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

  // async revokeAllUserTokens(userId: number, role: Role) {
  //   try {
  //     const whereClause: any = {
  //       isUsed: false,
  //       isRevoked: false,
  //     };

  //     if (role === Role.RIDER) whereClause.riderId = userId;
  //     if (role === Role.DRIVER) whereClause.driverId = userId;
  //     if (role === Role.ADMIN) whereClause.adminId = userId;

  //     const updatedCount = await this.prisma.refreshToken.updateMany({
  //       where: whereClause,
  //       data: {
  //         isRevoked: true,
  //         isUsed: true,
  //       },
  //     });

  //     console.log(
  //       `Revoked tokens count for user ${userId}:`,
  //       updatedCount.count,
  //     );
  //   } catch (error) {
  //     console.error(`Failed to revoke tokens for user ${userId}:`, error);
  //     throw new RpcException('Failed to revoke user tokens.');
  //   }
  // }
  async refreshToken(oldRefreshToken: string) {
    // 1) must be present
    if (!oldRefreshToken) {
      throw new RpcException('Refresh token is required.');
    }

    let payload: any;
    try {
      // 2) verify with REFRESH secret only
      payload = await this.jwtService.verifyAsync(oldRefreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });
    } catch (e) {
      // bad signature / expired / malformed
      throw new RpcException('Invalid or expired refresh token.');
    }

    // 3) must be a refresh token
    if (payload.type !== 'refresh') {
      throw new RpcException('Invalid token type.');
    }

    // 4) must exist in DB and be active
    const tokenRecord = await this.prisma.refreshToken.findFirst({
      where: {
        token: oldRefreshToken,
        isUsed: false,
        isRevoked: false,
        expiresAt: { gt: new Date() },
      },
    });

    if (!tokenRecord) {
      // token not stored or already rotated
      throw new RpcException(
        'Invalid, expired, or already used refresh token.',
      );
    }

    // 5) invalidate old token FIRST
    await this.prisma.refreshToken.update({
      where: { id: tokenRecord.id },
      data: { isUsed: true, isRevoked: true },
    });

    // 6) now it is safe to mint new ones
    const newAccessToken = this.jwtService.sign(
      {
        id: payload.id,
        email: payload.email,
        role: payload.role,
        type: 'access',
      },
      { secret: process.env.JWT_ACCESS_SECRET, expiresIn: '1m' },
    );

    const newRefreshToken = this.jwtService.sign(
      {
        id: payload.id,
        email: payload.email,
        role: payload.role,
        type: 'refresh',
      },
      { secret: process.env.JWT_REFRESH_SECRET, expiresIn: '7d' },
    );

    // 7) store the new refresh token
    await this.prisma.refreshToken.create({
      data: {
        token: newRefreshToken,
        riderId: payload.role === Role.RIDER ? payload.id : null,
        driverId: payload.role === Role.DRIVER ? payload.id : null,
        adminId: payload.role === Role.ADMIN ? payload.id : null,
        isUsed: false,
        isRevoked: false,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  async logout(refreshToken: string) {
    try {
      // Verify token
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      // Find the token in DB
      const tokenRecord = await this.prisma.refreshToken.findUnique({
        where: { token: refreshToken },
      });

      if (!tokenRecord || tokenRecord.isUsed || tokenRecord.isRevoked) {
        throw new RpcException('Invalid refresh token');
      }

      // Revoke the token
      await this.prisma.refreshToken.update({
        where: { token: refreshToken },
        data: { isRevoked: true },
      });

      return { message: 'Logged out successfully' };
    } catch (error) {
      console.error('Logout Error:', error);
      throw new RpcException('Failed to logout.');
    }
  }

  /** Get all users */
  async getAllRiders() {
    try {
      return await this.prisma.rider.findMany({
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
  async getRiderByEmail(email: string) {
    try {
      const rider = await this.prisma.rider.findUnique({
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
      if (!rider) throw new RpcException('User not found.');
      return rider;
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

  async getProfile(userId: number, role: Role) {
    try {
      // Validate the role to ensure it's one of the allowed roles
      if (![Role.RIDER, Role.DRIVER, Role.ADMIN].includes(role)) {
        throw new RpcException('Invalid role provided.');
      }

      // Common fields for all roles
      const selectFields = {
        id: true,
        email: true,
        role: true,
        isConfirmed: true,
        firstName: true,
        lastName: true,
        mobileNumber: true,
        profilePhoto: true, // optional field for profile photo
      };

      let user;
      switch (role) {
        case Role.RIDER:
          user = await this.prisma.rider.findUnique({
            where: { id: userId },
            select: selectFields,
          });
          if (!user)
            throw new RpcException(`Rider with ID ${userId} not found.`);
          break;

        case Role.DRIVER:
          user = await this.prisma.driver.findUnique({
            where: { id: userId },
            select: {
              ...selectFields,
              drivingLicense: true, // Driver-specific field
            },
          });
          if (!user)
            throw new RpcException(`Driver with ID ${userId} not found.`);
          break;

        case Role.ADMIN:
          user = await this.prisma.admin.findUnique({
            where: { id: userId },
            select: {
              ...selectFields,
              name: true, // Admin uses 'name' instead of firstName/lastName
            },
          });
          if (!user)
            throw new RpcException(`Admin with ID ${userId} not found.`);
          break;

        default:
          throw new RpcException('Invalid role provided.');
      }

      return user; // Return the user profile data
    } catch (error) {
      console.error('Get Profile Error:', error);
      throw new RpcException(error.message || 'Failed to fetch profile.');
    }
  }

  /** Get admin */
  async getAdmin() {
    try {
      const admin = await this.prisma.admin.findFirst({
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
        },
      });
      if (!admin) throw new RpcException('Admin not found.');
      return admin;
    } catch (error) {
      console.error('Get Admin Error:', error);
      throw new RpcException('Failed to fetch admin.');
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

  async forgotPassword(email: string) {
    try {
      // Find the account (Rider, Driver, or Admin if needed)
      const account =
        (await this.prisma.rider.findUnique({ where: { email } })) ||
        (await this.prisma.driver.findUnique({ where: { email } }));

      if (!account) throw new RpcException('Account not found.');

      // Determine the type
      const type: 'RIDER' | 'DRIVER' =
        account.role === 'DRIVER' ? 'DRIVER' : 'RIDER';

      // Generate 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      console.log(`✅ OTP for ${email}: ${otp}`);

      // OTP expiry 10 minutes from now
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
      await this.emailService.sendOTPEmail(email, otp);

      return { message: 'OTP sent to your email. It is valid for 10 minutes.' };
    } catch (error) {
      console.error('Forgot Password Error:', error);
      throw new RpcException('Failed to process forgot password.');
    }
  }
  async resetPassword(email: string, otp: string, newPassword: string) {
    try {
      // Find the account (Rider or Driver)
      const account =
        (await this.prisma.rider.findUnique({ where: { email } })) ||
        (await this.prisma.driver.findUnique({ where: { email } }));

      if (!account) throw new RpcException('Account not found.');

      // Determine type
      const type: 'RIDER' | 'DRIVER' =
        account.role === 'DRIVER' ? 'DRIVER' : 'RIDER';

      // Validate OTP
      // Validate OTP
      if (account.otp !== otp) throw new RpcException('Invalid OTP.');
      if (!account.otpExpiry || new Date(account.otpExpiry) < new Date())
        throw new RpcException('OTP has expired.');

      // Hash new password
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
      throw new RpcException(error.message || 'Failed to reset password.');
    }
  }

  // async forgotPassword(email: string) {
  //   try {
  //     // Check if user exists
  //     let userOrDriver: any = await this.prisma.user.findUnique({
  //       where: { email },
  //     });
  //     let type: 'USER' | 'DRIVER' = 'USER';

  //     if (!userOrDriver) {
  //       userOrDriver = await this.prisma.driver.findUnique({
  //         where: { email },
  //       });
  //       type = 'DRIVER';
  //     }

  //     if (!userOrDriver) throw new RpcException('User not found.');

  //     // Generate 6-digit OTP
  //     const otp = Math.floor(100000 + Math.random() * 900000).toString();
  //     console.log(`✅ OTP for ${email}: ${otp}`);

  //     // OTP expiry 10 minutes from now
  //     const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

  //     // Save OTP and expiry in DB
  //     if (type === 'USER') {
  //       await this.prisma.user.update({
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

  // ------------------- RESET PASSWORD -------------------
  // async resetPassword(email: string, otp: string, newPassword: string) {
  //   try {
  //     // Check if user exists
  //     let userOrDriver: any = await this.prisma.user.findUnique({
  //       where: { email },
  //     });
  //     let type: 'USER' | 'DRIVER' = 'USER';

  //     if (!userOrDriver) {
  //       userOrDriver = await this.prisma.driver.findUnique({
  //         where: { email },
  //       });
  //       type = 'DRIVER';
  //     }

  //     if (!userOrDriver) throw new RpcException('User not found.');

  //     // Validate OTP
  //     if (userOrDriver.otp !== otp) throw new RpcException('Invalid OTP.');
  //     if (new Date(userOrDriver.otpExpiry) < new Date())
  //       throw new RpcException('OTP has expired.');

  //     // Hash new password
  //     const hashedPassword = await bcrypt.hash(newPassword, 10);

  //     // Update password and clear OTP
  //     if (type === 'USER') {
  //       await this.prisma.user.update({
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

  // async function getProfile(userId: number, role: Role) {
  //   const prisma = new PrismaClient();
  //   if (role === Role.USER) {
  //     return await prisma.user.findUnique({
  //       where: { id: userId },
  //     });
  //   } else if (role === Role.DRIVER) {
  //     return await prisma.driver.findUnique({
  //       where: { id: userId },
  //     });
  //   } else {
  //     throw new Error('Role not recognized');
  //   }
  // }
}
