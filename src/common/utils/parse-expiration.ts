import { StringValue } from 'ms';

export function parseExpiration(exp?: string): StringValue {
  if (!exp) {
    throw new Error('JWT expiration not set in .env');
  }

  // Must match formats like: 10m, 1h, 30s, 7d
  const match = exp.match(/^(\d+)([smhd])$/);
  if (!match) {
    throw new Error(
      `JWT expiration value '${exp}' is invalid. Expected formats: 30s, 10m, 1h, 7d`,
    );
  }

  return exp as StringValue; // Convert to ms.StringValue (what Nest JWT requires)
}
