/* eslint-disable @typescript-eslint/require-await */
/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
// src/admin/admin.controller.ts
import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { AdminGuard } from './admin.guard';

@Controller('admin') // All routes here start with '/admin'
export class AdminController {
  @UseGuards(AdminGuard) // Use AdminGuard to protect this route
  @Post('manage-users') // POST route for managing users
  async manageUsers(@Body() body: any) {
    // Implement logic for admin to manage users (e.g., CRUD operations)
    return { message: 'Admin is managing users', data: body };
  }
}
