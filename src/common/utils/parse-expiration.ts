export function parseExpiration(exp?: string): number {
  if (!exp) return 600;
  const match = exp.match(/^(\d+)([smhd])$/);
  if (!match) return 600;

  const value = parseInt(match[1], 10);
  const unit = match[2];

  return unit === 's'
    ? value
    : unit === 'm'
      ? value * 60
      : unit === 'h'
        ? value * 3600
        : unit === 'd'
          ? value * 86400
          : 600;
}
