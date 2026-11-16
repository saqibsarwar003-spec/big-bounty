'use strict';

const crypto = require('node:crypto');

const TOKEN_PATTERN = /^[a-f0-9]{64}$/;
const BROWSER_ACCESS_COOKIE = 'bb_browser_access';
const BROWSER_ACCESS_MAX_AGE_SECONDS = 60 * 60 * 24 * 365;

function isValidJobAccessToken(value) {
  return typeof value === 'string' && TOKEN_PATTERN.test(value);
}

function hashJobAccessToken(value) {
  if (!isValidJobAccessToken(value)) throw new Error('invalid job access token');
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function matchesJobAccessToken(value, expectedHash) {
  if (!isValidJobAccessToken(value) || typeof expectedHash !== 'string' || !/^[a-f0-9]{64}$/.test(expectedHash)) return false;
  const actual = Buffer.from(hashJobAccessToken(value), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  return crypto.timingSafeEqual(actual, expected);
}

function readBrowserAccessToken(cookieHeader) {
  for (const part of String(cookieHeader || '').split(';')) {
    const trimmed = part.trim();
    const equals = trimmed.indexOf('=');
    if (equals < 0 || trimmed.slice(0, equals) !== BROWSER_ACCESS_COOKIE) continue;
    let value;
    try { value = decodeURIComponent(trimmed.slice(equals + 1)); } catch { return ''; }
    return isValidJobAccessToken(value) ? value : '';
  }
  return '';
}

function buildBrowserAccessCookie(token, secure = false) {
  if (!isValidJobAccessToken(token)) throw new Error('invalid job access token');
  return `${BROWSER_ACCESS_COOKIE}=${token}; Path=/; Max-Age=${BROWSER_ACCESS_MAX_AGE_SECONDS}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;
}

module.exports = {
  BROWSER_ACCESS_COOKIE,
  BROWSER_ACCESS_MAX_AGE_SECONDS,
  isValidJobAccessToken,
  hashJobAccessToken,
  matchesJobAccessToken,
  readBrowserAccessToken,
  buildBrowserAccessCookie,
};
