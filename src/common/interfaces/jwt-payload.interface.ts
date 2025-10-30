// src/auth/interfaces/jwt-payload.interface.ts
export interface JwtPayload {
  email: string;
  role: string;
  sub?: string; // optional, for user ID
  iat?: number;
  exp?: number;
}
