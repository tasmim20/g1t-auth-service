/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Controller } from '@nestjs/common';
import { GrpcMethod, RpcException } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { CreateDriverDto } from './dto/create-driver.dto';
import { CreateRiderDto } from './dto/create-rider.dto';
import { LoginDto } from './dto/login.dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @GrpcMethod('AuthService', 'Register')
  async register(data: CreateRiderDto | CreateDriverDto) {
    const result = await this.authService.register(data);
    return {
      success: true,
      message: result?.message ?? 'Registered successfully',
    };
  }

  @GrpcMethod('AuthService', 'ConfirmRegistration')
  async confirmRegistration(data: { token: string }) {
    const result = await this.authService.confirmRegistration(data.token);
    return {
      success: true,
      message: result?.message ?? 'Confirmed successfully',
    };
  }

  @GrpcMethod('AuthService', 'Login')
  async login(data: LoginDto) {
    const result = await this.authService.login(data);
    return {
      accessToken: result.accessToken ?? '',
      refreshToken: result.refreshToken ?? '',
      role: result.role ?? '',
    };
  }

  @GrpcMethod('AuthService', 'RefreshToken')
  async refreshToken(data: { refreshToken: string }) {
    const result = await this.authService.refreshToken(data.refreshToken);
    return {
      accessToken: result.accessToken ?? '',
      refreshToken: result.refreshToken ?? '',
    };
  }

  @GrpcMethod('AuthService', 'Logout')
  async logout(data: { refreshToken: string }) {
    const result = await this.authService.logout(data.refreshToken);
    return {
      success: result?.status === 'success',
      message: result?.message ?? 'Logged out',
    };
  }

  // ------------------ Forgot Password ------------------
  @GrpcMethod('AuthService', 'ForgotPassword')
  async forgotPassword(data: { email: string }) {
    console.log('Received forgot password request for:', data.email);

    try {
      // Call the service's forgotPassword method to handle OTP generation and email sending
      const result = await this.authService.forgotPassword(data.email);

      // Return the response to the client
      return {
        success: true,
        message: result?.message ?? 'OTP sent successfully.',
      };
    } catch (error) {
      console.error('Error in ForgotPassword method:', error);
      throw new RpcException(
        error.message || 'Failed to process forgot password.',
      );
    }
  }

  // ------------------ Reset Password ------------------
  @GrpcMethod('AuthService', 'ResetPassword')
  async resetPassword(data: {
    email: string;
    otp: string;
    newPassword: string;
  }) {
    console.log('Received reset password request for:', data.email);

    try {
      const result = await this.authService.resetPassword(
        data.email,
        data.otp,
        data.newPassword,
      );

      // Return success response
      return {
        success: true,
        message: result?.message ?? 'Password reset successfully.',
      };
    } catch (error) {
      console.error('Error in ResetPassword method:', error);
      throw new RpcException(error.message || 'Failed to reset password.');
    }
  }
  @GrpcMethod('AuthService', 'ResetPasswordWithoutOtp')
  async resetPasswordWithoutOtp(data: {
    email: string;
    currentPassword: string;
    newPassword: string;
  }) {
    console.log('Received reset password WITHOUT OTP request for:', data.email);

    try {
      const result = await this.authService.resetPasswordWithoutOtp(
        data.email,
        data.currentPassword,
        data.newPassword,
      );
      return {
        success: true,
        message: result?.message ?? 'Password updated successfully.',
      };
    } catch (error) {
      console.error('Error in ResetPasswordWithoutOtp method:', error);
      throw new RpcException(error.message || 'Failed to update password.');
    }
  }
}
