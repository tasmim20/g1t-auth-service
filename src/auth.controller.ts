/* eslint-disable @typescript-eslint/no-unsafe-call */
import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { CreateDriverDto } from './dto/create-driver.dto';
import { LoginDto } from './dto/login.dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // Register a new user or driver
  @MessagePattern({ cmd: 'register' })
  async register(@Payload() data: CreateUserDto | CreateDriverDto) {
    return this.authService.register(data);
  }
  @MessagePattern({ cmd: 'confirm-registration' })
  confirmRegistration(@Payload() token: string) {
    return this.authService.confirmRegistration(token);
  }

  // Login user/driver
  @MessagePattern({ cmd: 'login' })
  async login(@Payload() data: LoginDto) {
    return this.authService.login(data);
  }

  @MessagePattern({ cmd: 'refresh-token' })
  async refreshToken(@Payload() data: { refreshToken: string }) {
    return this.authService.refreshToken(data.refreshToken);
  }

  @MessagePattern({ cmd: 'logout' })
  async logout(@Payload() data: { refreshToken: string }) {
    return this.authService.logout(data.refreshToken);
  }

  // Get all users
  @MessagePattern({ cmd: 'users' })
  getAllUsers() {
    return this.authService.getAllUsers();
  }

  // Get user by email
  @MessagePattern({ cmd: 'user/email' })
  getUserByEmail(@Payload() email: string) {
    return this.authService.getUserByEmail(email);
  }

  // Get all drivers
  @MessagePattern({ cmd: 'drivers' })
  getAllDrivers() {
    return this.authService.getAllDrivers();
  }

  // Get driver by email
  @MessagePattern({ cmd: 'driver/email' })
  getDriverByEmail(@Payload() email: string) {
    return this.authService.getDriverByEmail(email);
  }
  @MessagePattern({ cmd: 'forgot-password' })
  forgotPassword(@Payload() email: string) {
    return this.authService.forgotPassword(email);
  }

  @MessagePattern({ cmd: 'reset-password' })
  resetPassword(
    @Payload() body: { email: string; otp: string; newPassword: string },
  ) {
    return this.authService.resetPassword(
      body.email,
      body.otp,
      body.newPassword,
    );
  }
}
