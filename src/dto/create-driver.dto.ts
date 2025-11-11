/* eslint-disable @typescript-eslint/no-unsafe-call */
import {
  IsString,
  IsEmail,
  IsNotEmpty,
  IsMobilePhone,
  IsEnum,
} from 'class-validator';
import { Role } from './role.enum'; // Import the Role Enum (if you use one)
import { CreateRiderDto } from './create-rider.dto';

export class CreateDriverDto {
  @IsString()
  @IsNotEmpty()
  firstName: string;

  @IsString()
  @IsNotEmpty()
  lastName: string;

  @IsEmail()
  email: string;

  @IsMobilePhone('en-US') // Ensure this decorator works by setting locale (like 'en-US')
  mobileNumber: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  drivingLicense: string;

  @IsEnum(Role) // Using @IsEnum for the 'role' field
  role: Role; // Validate the role field using the Role Enum
}

// In create-driver.dto.ts or in a separate utils file

export function isCreateDriverDto(
  dto: CreateRiderDto | CreateDriverDto,
): dto is CreateDriverDto {
  return (dto as CreateDriverDto).drivingLicense !== undefined;
}
