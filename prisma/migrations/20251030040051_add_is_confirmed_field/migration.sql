-- AlterTable
ALTER TABLE "Driver" ADD COLUMN     "isConfirmed" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "isConfirmed" BOOLEAN NOT NULL DEFAULT false;
