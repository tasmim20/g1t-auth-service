/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-call */
import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { CreateDriverDto } from './dto/create-driver.dto';
import { LoginDto } from './dto/login.dto';
import { CreateRiderDto } from './dto/create-rider.dto';
// import { Role } from './dto/role.enum';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // Register a new user or driver
  @MessagePattern({ cmd: 'register' })
  async register(@Payload() data: CreateRiderDto | CreateDriverDto) {
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

  @MessagePattern({ cmd: 'refresh' })
  async refreshToken(@Payload() data: { refreshToken: string }) {
    return this.authService.refreshToken(data.refreshToken);
  }

  @MessagePattern({ cmd: 'logout' })
  async logout(@Payload() data: { refreshToken: string }) {
    return this.authService.logout(data.refreshToken);
  }

  // @MessagePattern({ cmd: 'profile' })
  // async getProfile(@Payload() data: { userId: number; role: Role }) {
  //   const { userId, role } = data;

  //   if (!userId || !role) {
  //     throw new RpcException('userId and role are required');
  //   }

  //   // Call your service to fetch the profile based on userId and role
  //   const profile = await this.authService.getProfile(userId, role);
  //   return profile;
  // }

  // // Get all riders
  // @MessagePattern({ cmd: 'riders' })
  // getAllRiders() {
  //   return this.authService.getAllRiders();
  // }

  // // Get user by email
  // @MessagePattern({ cmd: 'rider/email' })
  // getRiderByEmail(@Payload() email: string) {
  //   return this.authService.getRiderByEmail(email);
  // }

  // // Get all drivers
  // @MessagePattern({ cmd: 'drivers' })
  // getAllDrivers() {
  //   return this.authService.getAllDrivers();
  // }

  // // Get driver by email
  // @MessagePattern({ cmd: 'driver/email' })
  // getDriverByEmail(@Payload() email: string) {
  //   return this.authService.getDriverByEmail(email);
  // }
  // @MessagePattern({ cmd: 'forgot-password' })
  // forgotPassword(@Payload() email: string) {
  //   return this.authService.forgotPassword(email);
  // }

  // @MessagePattern({ cmd: 'reset-password' })
  // resetPassword(
  //   @Payload() body: { email: string; otp: string; newPassword: string },
  // ) {
  //   return this.authService.resetPassword(
  //     body.email,
  //     body.otp,
  //     body.newPassword,
  //   );
  // }
}
