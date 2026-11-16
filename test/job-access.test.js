'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const A = require('../lib/job-access');

test('per-browser access tokens are validated, hashed, and compared safely', () => {
  const token = 'ab'.repeat(32);
  assert.equal(A.isValidJobAccessToken(token), true);
  const hash = A.hashJobAccessToken(token);
  assert.match(hash, /^[a-f0-9]{64}$/);
  assert.notEqual(hash, token);
  assert.equal(A.matchesJobAccessToken(token, hash), true);
  assert.equal(A.matchesJobAccessToken('cd'.repeat(32), hash), false);
  assert.equal(A.matchesJobAccessToken(token, null), false);
  assert.throws(() => A.hashJobAccessToken('invalid'), /invalid job access token/);
});

test('the browser owner key is set only as a host-only HttpOnly cookie', () => {
  const token = 'cd'.repeat(32);
  const cookie = A.buildBrowserAccessCookie(token, true);
  assert.match(cookie, /^bb_browser_access=/);
  assert.match(cookie, /Path=\//);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  assert.match(cookie, /Secure$/);
  assert.doesNotMatch(cookie, /Domain=/);
  assert.equal(A.readBrowserAccessToken(`other=value; ${cookie.split(';', 1)[0]}`), token);
  assert.equal(A.readBrowserAccessToken('bb_browser_access=not-a-token'), '');
  assert.equal(A.readBrowserAccessToken('bb_browser_access=%E0%A4%A'), '');
});

test('the Azure package helper matches the Vercel-side token verifier', async () => {
  const Azure = await import('../azure/orchestrator/src/job-access.js');
  const token = 'ef'.repeat(32);
  const hash = Azure.hashJobAccessToken(token);
  assert.equal(Azure.isValidJobAccessToken(token), true);
  assert.equal(Azure.matchesJobAccessToken(token, hash), true);
  assert.equal(A.matchesJobAccessToken(token, hash), true);
});
