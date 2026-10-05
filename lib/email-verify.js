'use strict';
/**
 * Ownership verification for the Email Exposure Check.
 *
 * A stateless, HMAC-signed one-time code — no database needed. We email an 8-char
 * code to the address and hand the browser an opaque token that binds (email,
 * codeHash, expiry). On verify we re-check the HMAC, the expiry, the email, and
 * the code. The plaintext code is NEVER placed in the token, so a user can only
 * pass verification by receiving the code at that mailbox — i.e. proving control.
 *
 * Reuses the server secret BIGBOUNTY_HMAC_SECRET. Pure/testable; no network.
 */
const crypto = require('crypto');

function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlDecode(str) { const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4)); return Buffer.from(String(str).replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64'); }
function hmac(body, key) { return b64url(crypto.createHmac('sha256', key).update(body).digest()); }
function eq(a, b) { const ab = Buffer.from(String(a)), bb = Buffer.from(String(b)); if (ab.length !== bb.length) return false; return crypto.timingSafeEqual(ab, bb); }

function normEmail(e) { return String(e || '').trim().toLowerCase(); }
function validEmail(e) { const v = normEmail(e); return v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }

// Unambiguous base32 (no 0/O/1/I) so codes are easy to read/type.
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function generateCode(len = 8) {
  const b = crypto.randomBytes(len); let s = '';
  for (let i = 0; i < len; i++) s += ALPHABET[b[i] % ALPHABET.length];
  return s;
}
function normCode(c) { return String(c || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, ''); }

const DEFAULT_TTL_MS = 10 * 60 * 1000;

/** Issue a challenge: returns { code, token, expiresAt }. Email the code; hand the token to the client. */
function issueChallenge(email, key, opts = {}) {
  if (!key) throw new Error('no signing key');
  const e = normEmail(email);
  const code = opts.code ? normCode(opts.code) : generateCode(8);
  const exp = Date.now() + (opts.ttlMs || DEFAULT_TTL_MS);
  const payload = { v: 1, eh: hmac(e, key), ch: hmac(code, key), exp, jti: b64url(crypto.randomBytes(9)) };
  const bodyB = b64url(JSON.stringify(payload));
  return { code, token: bodyB + '.' + hmac(bodyB, key), expiresAt: new Date(exp).toISOString() };
}

/** Verify a submitted code against the token for this email. Returns { ok, reason }. */
function verifyChallenge(email, code, token, key) {
  if (!key) return { ok: false, reason: 'server misconfigured' };
  if (typeof token !== 'string' || !token.includes('.')) return { ok: false, reason: 'missing or invalid token' };
  const [bodyB, sig] = token.split('.');
  if (!bodyB || !sig || !eq(sig, hmac(bodyB, key))) return { ok: false, reason: 'invalid token' };
  let p; try { p = JSON.parse(b64urlDecode(bodyB).toString('utf8')); } catch { return { ok: false, reason: 'malformed token' }; }
  if (!p || p.v !== 1) return { ok: false, reason: 'unsupported token' };
  if (Date.now() > Number(p.exp)) return { ok: false, reason: 'code expired' };
  if (!eq(p.eh, hmac(normEmail(email), key))) return { ok: false, reason: 'email mismatch' };
  if (!eq(p.ch, hmac(normCode(code), key))) return { ok: false, reason: 'incorrect code' };
  return { ok: true };
}

module.exports = { normEmail, validEmail, generateCode, normCode, issueChallenge, verifyChallenge };
