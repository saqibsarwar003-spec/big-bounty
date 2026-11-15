'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

let modulePromise;
function loadConfig() {
  modulePromise ??= import('../azure/worker/config.mjs');
  return modulePromise;
}

test('worker timeout defaults to 30 minutes when unset or invalid', async () => {
  const { resolveJobTimeoutMs, DEFAULT_JOB_TIMEOUT_MS } = await loadConfig();
  assert.equal(DEFAULT_JOB_TIMEOUT_MS, 30 * 60 * 1000);
  assert.equal(resolveJobTimeoutMs({}), DEFAULT_JOB_TIMEOUT_MS);
  assert.equal(resolveJobTimeoutMs({ BIGBOUNTY_JOB_TIMEOUT_MS: '' }), DEFAULT_JOB_TIMEOUT_MS);
  assert.equal(resolveJobTimeoutMs({ BIGBOUNTY_JOB_TIMEOUT_MS: 'not-a-number' }), DEFAULT_JOB_TIMEOUT_MS);
  assert.equal(resolveJobTimeoutMs({ BIGBOUNTY_JOB_TIMEOUT_MS: '0' }), DEFAULT_JOB_TIMEOUT_MS);
});

test('worker timeout honors shorter positive overrides', async () => {
  const { resolveJobTimeoutMs } = await loadConfig();
  assert.equal(resolveJobTimeoutMs({ BIGBOUNTY_JOB_TIMEOUT_MS: '600000' }), 600000);
});

test('worker timeout never exceeds the approved 30-minute maximum', async () => {
  const { resolveJobTimeoutMs, MAX_JOB_TIMEOUT_MS } = await loadConfig();
  assert.equal(MAX_JOB_TIMEOUT_MS, 30 * 60 * 1000);
  assert.equal(resolveJobTimeoutMs({ BIGBOUNTY_JOB_TIMEOUT_MS: '3600000' }), MAX_JOB_TIMEOUT_MS);
});
