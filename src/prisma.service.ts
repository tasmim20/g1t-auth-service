/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-unsafe-call */
import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client'; // Import Prisma Client

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  // This extends PrismaClient, allowing you to use all Prisma client features.

  async onModuleInit() {
    await this.$connect(); // Connect to the Prisma client when the module is initialized
  }

  async onModuleDestroy() {
    await this.$disconnect(); // Disconnect from the Prisma client when the module is destroyed
  }
}
