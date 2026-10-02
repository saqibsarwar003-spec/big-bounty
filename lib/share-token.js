'use strict';
/**
 * Big Bounty — secure shareable-report identifiers & tokens.
 *
 * Two distinct concepts, intentionally separate:
 *
 *   reportId   A cryptographically-strong, non-guessable public id for a scan
 *              record. Used in the stored record and in-app deep links. It is
 *              NOT an internal database row id — it is random, so exposing it in
 *              a URL leaks nothing about volume/order and cannot be enumerated.
 *
 *   shareToken A signed, expiring, individually-revocable grant that lets an
 *              unauthenticated recipient open ONE report via a public link
 *              (/report/<token>). Stateless HMAC signature (no DB hit to
 *              validate the signature) + an optional revocation check keyed on
 *              the token's random `jti`, so a link can be killed without
 *              rotating the signing key or touching other links.
 *
 * No secret value is ever embedded in a reportId or in the token payload.
 * The signing key lives only in server-side env (SHARE_SIGNING_KEY).
 */

const crypto = require('crypto');

const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_TTL_MS = 90 * 24 * 60 * 60 * 1000;    // hard cap: 90 days

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

/** URL-safe random identifier. 20 bytes = 160 bits of entropy by default. */
function randomId(bytes = 20) {
  return b64url(crypto.randomBytes(bytes));
}

/** Public, non-guessable id for a scan/report record. */
function newReportId() {
  return 'r_' + randomId(20);
}

function hmac(body, key) {
  return b64url(crypto.createHmac('sha256', key).update(body).digest());
}

function timingSafeEqualStr(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

/**
 * Create a signed share token for a report.
 * @param {string} reportId  the public report id this token grants access to
 * @param {string} signingKey  server-side HMAC key (env SHARE_SIGNING_KEY)
 * @param {object} [opts]
 * @param {number} [opts.ttlMs]  lifetime; clamped to (0, MAX_TTL_MS]
 * @param {number} [opts.now]    injectable clock for testing
 * @param {string} [opts.scope]  'view' (default) — reserved for future scopes
 * @returns {{token:string, jti:string, exp:number}}
 */
function createShareToken(reportId, signingKey, opts = {}) {
  if (!reportId || typeof reportId !== 'string') throw new Error('reportId required');
  if (!signingKey) throw new Error('signingKey required');
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  let ttl = Number.isFinite(opts.ttlMs) ? opts.ttlMs : DEFAULT_TTL_MS;
  if (ttl <= 0) ttl = DEFAULT_TTL_MS;
  if (ttl > MAX_TTL_MS) ttl = MAX_TTL_MS;
  const jti = randomId(12); // 96-bit token id for revocation
  const payload = {
    v: 1,
    rid: reportId,
    jti,
    scope: opts.scope === 'view' || !opts.scope ? 'view' : String(opts.scope),
    iat: Math.floor(now / 1000),
    exp: Math.floor((now + ttl) / 1000),
  };
  const body = b64url(JSON.stringify(payload));
  const sig = hmac(body, signingKey);
  return { token: `${body}.${sig}`, jti, exp: payload.exp * 1000 };
}

/**
 * Verify a share token.
 * @param {string} token
 * @param {string} signingKey
 * @param {object} [opts]
 * @param {number}  [opts.now]
 * @param {(jti:string)=>boolean} [opts.isRevoked]  optional revocation lookup
 * @returns {{valid:boolean, reason?:string, reportId?:string, jti?:string, payload?:object}}
 */
function verifyShareToken(token, signingKey, opts = {}) {
  if (!token || typeof token !== 'string' || !signingKey) return { valid: false, reason: 'missing' };
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) return { valid: false, reason: 'malformed' };
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = hmac(body, signingKey);
  if (!timingSafeEqualStr(sig, expected)) return { valid: false, reason: 'bad_signature' };
  let payload;
  try { payload = JSON.parse(b64urlDecode(body).toString('utf8')); }
  catch { return { valid: false, reason: 'bad_payload' }; }
  if (payload.v !== 1 || !payload.rid || !payload.jti) return { valid: false, reason: 'bad_payload' };
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  if (typeof payload.exp === 'number' && now / 1000 > payload.exp) return { valid: false, reason: 'expired' };
  if (typeof opts.isRevoked === 'function' && opts.isRevoked(payload.jti)) return { valid: false, reason: 'revoked' };
  return { valid: true, reportId: payload.rid, jti: payload.jti, payload };
}

module.exports = {
  randomId,
  newReportId,
  createShareToken,
  verifyShareToken,
  DEFAULT_TTL_MS,
  MAX_TTL_MS,
  _internal: { b64url, b64urlDecode, hmac, timingSafeEqualStr },
};
