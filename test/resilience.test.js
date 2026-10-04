'use strict';
// Per-module timeout / failure-isolation tests. Run: node --test test/resilience.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const { withTimeout } = require('../lib/resilience');

test('resolves a fast promise with its value', async () => {
  assert.equal(await withTimeout(Promise.resolve(42), 1000, 'fast'), 42);
});

test('rejects a slow promise with __timeout flag', async () => {
  await assert.rejects(
    () => withTimeout(new Promise((r) => setTimeout(() => r('late'), 200)), 20, 'slow'),
    (e) => e.__timeout === true && /timed out/.test(e.message),
  );
});

test('ms=0 passes through with no timer', async () => {
  assert.equal(await withTimeout(Promise.resolve('x'), 0, 'none'), 'x');
});

test('propagates a real rejection (not flagged as timeout)', async () => {
  await assert.rejects(
    () => withTimeout(Promise.reject(new Error('boom')), 1000, 'err'),
    (e) => e.message === 'boom' && !e.__timeout,
  );
});
