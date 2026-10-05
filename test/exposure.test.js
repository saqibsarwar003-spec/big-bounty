'use strict';
// Email Exposure Check tests — ownership verification + the defensive allowlist.
// Run: node --test test/exposure.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const V = require('../lib/email-verify');
const { normalizeIntelBase } = require('../lib/sources/intelbase');
const { runExposureCheck } = require('../lib/exposure');

const KEY = 'test-signing-key-123';

// ---------------------------------------------------------------------------
// Ownership verification
// ---------------------------------------------------------------------------
test('email validation', () => {
  assert.equal(V.validEmail('bob@example.com'), true);
  assert.equal(V.validEmail('BOB@Example.COM'), true);
  assert.equal(V.validEmail('nope'), false);
  assert.equal(V.validEmail('a@b'), false);
  assert.equal(V.validEmail(''), false);
});

test('issue -> verify round-trips; plaintext code is NOT in the token', () => {
  const { code, token } = V.issueChallenge('bob@example.com', KEY);
  assert.ok(code && code.length === 8);
  assert.ok(!token.includes(code), 'token must not contain the plaintext code');
  assert.equal(V.verifyChallenge('bob@example.com', code, token, KEY).ok, true);
  // case-insensitive email + code
  assert.equal(V.verifyChallenge('BOB@example.com', code.toLowerCase(), token, KEY).ok, true);
});

test('verification rejects wrong code, wrong email, tampered token, expiry', () => {
  const { code, token } = V.issueChallenge('bob@example.com', KEY);
  assert.equal(V.verifyChallenge('bob@example.com', 'WRONGXXX', token, KEY).ok, false);
  assert.equal(V.verifyChallenge('eve@example.com', code, token, KEY).ok, false);     // can't verify someone else's email
  const tampered = token.slice(0, -2) + (token.slice(-1) === 'a' ? 'bb' : 'aa');
  assert.equal(V.verifyChallenge('bob@example.com', code, tampered, KEY).ok, false);
  const expired = V.issueChallenge('bob@example.com', KEY, { ttlMs: -1000 });
  assert.equal(V.verifyChallenge('bob@example.com', expired.code, expired.token, KEY).reason, 'code expired');
});

// ---------------------------------------------------------------------------
// Defensive allowlist — the security-critical test
// ---------------------------------------------------------------------------
const RAW_INTELBASE = {
  identifier: { accounts: [{ module: 'spotify', username: 'bob', full_name: 'Bob Smith', avatar_url: 'http://x/a.png' }] },
  validator: { registered: [{ name: 'spotify' }], unregistered: [{ name: 'netflix' }] },
  data_breaches: {
    amount: 2, sources: ['Collection1', 'LinkedIn'], redacted: false,
    results: [
      { source: 'LinkedIn', breach_date: '2012-05-01', domain: 'linkedin.com', email: 'bob@example.com', password: 'hunter2', username: 'bob', full_name: 'Bob Smith', ip_address: '1.2.3.4', phone_number: '+15551234', hash: '$2y$abcHASH' },
      { source: 'Collection1', date: '2019-01-07', email: 'bob@example.com', password: 'letmein99', hash: 'deadbeefHASH' },
    ],
  },
  stealer_logs: { count: 1, compromised: true, has_stealer_log_type: true, redacted: false,
    results: [{ data_type: 'credential', origin: 'C:/users/bob', login: 'bob@example.com', password: 'SuperSecretPW' }] },
  stealer_enrichment: { autofill: [{ name: 'card', value: '4111111111111111' }], accounts: [], user_info: { name: 'Bob' }, card_holders: [{ number: '4111111111111111' }] },
  meta: { email: 'bob@example.com', first_seen: '2012-05-01', last_seen: '2019-01-07', cloaked: false,
    timeline: [{ source: 'LinkedIn', name: 'LinkedIn breach', date: '2012-05-01' }, { source: 'Collection1', name: 'Collection #1', date: '2019-01-07' }] },
};

test('allowlist keeps defensive fields', () => {
  const out = normalizeIntelBase(RAW_INTELBASE);
  assert.equal(out.inBreaches, true);
  assert.equal(out.breachCount, 2);
  assert.equal(out.inStealerLogs, true);
  assert.equal(out.firstSeen, '2012-05-01');
  assert.ok(out.breaches.some((b) => b.source === 'LinkedIn' && b.date === '2012-05-01' && b.domain === 'linkedin.com'));
  assert.ok(out.exposureCategories.includes('Data breach exposure'));
  assert.ok(out.exposureCategories.some((c) => /infostealer/i.test(c)));
  assert.equal(out.timeline.length, 2);
  assert.ok(out.recommendations.length >= 3);
});

test('allowlist NEVER leaks credentials, stealer-logs, PII or enrichment', () => {
  const blob = JSON.stringify(normalizeIntelBase(RAW_INTELBASE));
  // No secret VALUES survive
  for (const secret of ['hunter2', 'letmein99', 'SuperSecretPW', '$2y$abcHASH', 'deadbeefHASH', '4111111111111111', '1.2.3.4', '+15551234', 'Bob Smith', 'C:/users/bob', 'http://x/a.png']) {
    assert.ok(!blob.includes(secret), `leaked secret value: ${secret}`);
  }
  // No sensitive structural KEYS survive
  for (const key of ['password', 'hash', 'ip_address', 'phone_number', 'full_name', 'avatar_url', 'autofill', 'card_holders', 'user_info', 'login', 'stealer_enrichment', 'origin']) {
    assert.ok(!new RegExp('"' + key + '"').test(blob), `leaked sensitive key: ${key}`);
  }
});

test('allowlist handles empty / clean results (no false exposure)', () => {
  const out = normalizeIntelBase({ data_breaches: { amount: 0, results: [] }, meta: {} });
  assert.equal(out.inBreaches, false);
  assert.equal(out.inStealerLogs, false);
  assert.ok(out.exposureCategories.includes('No known breach exposure found'));
});

// ---------------------------------------------------------------------------
// Orchestrator failure isolation (no network: IntelBase unconfigured)
// ---------------------------------------------------------------------------
test('orchestrator reports per-source failure without throwing', async () => {
  const saved = process.env.INTELBASE_API_KEY;
  delete process.env.INTELBASE_API_KEY;
  try {
    const r = await runExposureCheck('bob@example.com');
    assert.equal(r.ok, false);
    assert.equal(r.summary.sourcesOk, 0);
    assert.equal(r.sources[0].ok, false);
    assert.match(r.sources[0].error, /not configured/i);
    assert.equal(r.sources[0].name, 'IntelBase'); // source clearly attributed
  } finally {
    if (saved !== undefined) process.env.INTELBASE_API_KEY = saved;
  }
});
