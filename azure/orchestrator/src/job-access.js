import { createHash, timingSafeEqual } from 'node:crypto';

const TOKEN_PATTERN = /^[a-f0-9]{64}$/;

export function isValidJobAccessToken(value) {
  return typeof value === 'string' && TOKEN_PATTERN.test(value);
}

export function hashJobAccessToken(value) {
  if (!isValidJobAccessToken(value)) throw new Error('invalid job access token');
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function matchesJobAccessToken(value, expectedHash) {
  if (!isValidJobAccessToken(value) || typeof expectedHash !== 'string' || !/^[a-f0-9]{64}$/.test(expectedHash)) return false;
  const actual = Buffer.from(hashJobAccessToken(value), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  return timingSafeEqual(actual, expected);
}
