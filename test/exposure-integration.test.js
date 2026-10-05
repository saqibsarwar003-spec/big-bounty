'use strict';
// Integration: the REAL IntelBase client path (lookupEmail -> HTTP parse ->
// normalizer -> orchestrator) with global.fetch stubbed. Proves secrets are
// stripped on the live path, and that timeouts / non-200s are handled safely.
// Run: node --test test/exposure-integration.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const { runExposureCheck } = require('../lib/exposure');

const RAW_SENSITIVE = {
  identifier: { accounts: [{ module: 'spotify', username: 'bob', full_name: 'Bob Smith', avatar_url: 'http://x/a.png' }] },
  data_breaches: {
    amount: 2, sources: ['Collection1', 'LinkedIn'],
    results: [
      { source: 'LinkedIn', breach_date: '2012-05-01', domain: 'linkedin.com', email: 'bob@example.com', password: 'hunter2', ip_address: '1.2.3.4', phone_number: '+15551234', hash: '$2y$abcHASH' },
      { source: 'Collection1', date: '2019-01-07', password: 'letmein99', hash: 'deadbeefHASH' },
    ],
  },
  stealer_logs: { count: 1, compromised: true, results: [{ login: 'bob@example.com', password: 'SuperSecretPW', origin: 'C:/users/bob' }] },
  stealer_enrichment: { autofill: [{ value: '4111111111111111' }], card_holders: [{ number: '4111111111111111' }], user_info: { name: 'Bob' } },
  meta: { email: 'bob@example.com', first_seen: '2012-05-01', last_seen: '2019-01-07',
    timeline: [{ source: 'LinkedIn', name: 'LinkedIn breach', date: '2012-05-01' }] },
};

const SECRETS = ['hunter2', 'letmein99', 'SuperSecretPW', '$2y$abcHASH', 'deadbeefHASH', '4111111111111111', '1.2.3.4', '+15551234', 'Bob Smith', 'C:/users/bob', 'http://x/a.png'];

// Sets up the fetch stub + key INSIDE the test callback (not at registration),
// then restores both afterward — so the four tests don't clobber each other.
function withFetch(fn, body) {
  return async () => {
    const saved = global.fetch;
    const savedKey = process.env.INTELBASE_API_KEY;
    process.env.INTELBASE_API_KEY = 'test-key';
    global.fetch = fn;
    try { return await body(); }
    finally {
      global.fetch = saved;
      if (savedKey === undefined) delete process.env.INTELBASE_API_KEY; else process.env.INTELBASE_API_KEY = savedKey;
    }
  };
}

test('live client path: breach result is returned WITHOUT any secret', withFetch(
  async () => ({ ok: true, status: 200, text: async () => JSON.stringify(RAW_SENSITIVE) }),
  async () => {
    const r = await runExposureCheck('bob@example.com');
    assert.equal(r.ok, true);
    assert.equal(r.summary.anyBreach, true);
    assert.equal(r.summary.anyStealer, true);
    const src = r.sources.find((s) => s.id === 'intelbase');
    assert.equal(src.ok, true);
    assert.equal(src.data.breachCount, 2);
    // The whole serialized result must contain none of the sensitive values.
    const blob = JSON.stringify(r);
    for (const s of SECRETS) assert.ok(!blob.includes(s), `leaked secret on live path: ${s}`);
    for (const k of ['password', 'hash', 'ip_address', 'phone_number', 'login', 'autofill', 'card_holders', 'stealer_enrichment', 'origin']) {
      assert.ok(!new RegExp('"' + k + '"').test(blob), `leaked key on live path: ${k}`);
    }
  },
));

test('non-200 from IntelBase is reported as a failed source, not thrown', withFetch(
  async () => ({ ok: false, status: 401, text: async () => JSON.stringify({ error: 'unauthorized' }) }),
  async () => {
    const r = await runExposureCheck('bob@example.com');
    assert.equal(r.ok, false);
    const src = r.sources.find((s) => s.id === 'intelbase');
    assert.equal(src.ok, false);
    assert.match(src.error, /invalid key|non-whitelisted|quota/i);
  },
));

test('timeout / aborted request is handled safely', withFetch(
  async () => { const e = new Error('aborted'); e.name = 'AbortError'; throw e; },
  async () => {
    const r = await runExposureCheck('bob@example.com');
    assert.equal(r.ok, false);
    const src = r.sources.find((s) => s.id === 'intelbase');
    assert.equal(src.ok, false);
    assert.match(src.error, /timed out/i);
  },
));

test('clean account (no breaches) on the live path reports no exposure', withFetch(
  async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ data_breaches: { amount: 0, results: [] }, meta: {} }) }),
  async () => {
    const r = await runExposureCheck('clean@example.com');
    assert.equal(r.ok, true);
    assert.equal(r.summary.anyBreach, false);
    assert.equal(r.summary.anyStealer, false);
    const src = r.sources.find((s) => s.id === 'intelbase');
    assert.ok(src.data.exposureCategories.includes('No known breach exposure found'));
  },
));
