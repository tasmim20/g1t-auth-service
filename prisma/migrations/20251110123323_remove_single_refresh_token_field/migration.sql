/*
  Warnings:

  - You are about to drop the column `refreshToken` on the `Admin` table. All the data in the column will be lost.
  - You are about to drop the column `refreshToken` on the `Driver` table. All the data in the column will be lost.
  - You are about to drop the column `refreshToken` on the `Rider` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "Admin" DROP COLUMN "refreshToken";

-- AlterTable
ALTER TABLE "Driver" DROP COLUMN "refreshToken";

-- AlterTable
ALTER TABLE "Rider" DROP COLUMN "refreshToken";
