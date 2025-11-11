import { Role } from 'src/dto/role.enum';

// user.interface.ts
export interface User {
  email: string;
  role: string;
  // Add other fields if necessary
}
// src/auth/interfaces/jwt-payload.interface.ts
export interface JwtPayload {
  email: string;
  role: string;
  sub?: string; // optional, for user ID
  iat?: number;
  exp?: number;
}

export interface AuthenticatedUserSafe {
  id: number;
  email: string;
  role: Role;
  isConfirmed?: boolean;
  firstName?: string;
  lastName?: string;
  mobileNumber?: string;
  drivingLicense?: string;
  name?: string; // for admin
}
