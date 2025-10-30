/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
// /* eslint-disable @typescript-eslint/no-unsafe-assignment */
// /* eslint-disable @typescript-eslint/no-unsafe-member-access */
// import { Injectable } from '@nestjs/common';
// import { CanActivate, ExecutionContext } from '@nestjs/common';
// import { JwtAuthGuard } from './jwt-auth.guard'; // Import JwtAuthGuard

// @Injectable()
// export class AdminGuard extends JwtAuthGuard implements CanActivate {
//   async canActivate(context: ExecutionContext): Promise<boolean> {
//     // Call the parent class's `canActivate` to check if the JWT token is valid
//     const isAuthenticated = await super.canActivate(context);

//     if (!isAuthenticated) {
//       return false; // If not authenticated, deny access
//     }

//     // Get the request object
//     const request = context.switchToHttp().getRequest();
//     // Ensure that the `user` is attached to the request by the `JwtAuthGuard`
//     const user = request.user;

//     if (!user) {
//       return false; // If no user exists, deny access
//     }

//     // Check if the user has the 'admin' role
//     if (user.role !== 'ADMIN') {
//       return false; // Deny access if the user is not an admin
//     }

//     return true; // Allow access if the user is an admin
//   }
// }

import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';

@Injectable()
export class AdminGuard extends JwtAuthGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // First ensure JWT is valid
    const ok = await super.canActivate(context);
    if (!ok) return false;

    // Then check role
    const req = context.switchToHttp().getRequest();
    const user = req.user;
    return user && user.role === 'ADMIN';
  }
}
