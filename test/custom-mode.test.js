'use strict';
/**
 * Custom Mode regression tests.
 *
 * These cover the request-validation + mode-routing contract that was broken:
 *   - the UI sent "instructions" while the API read "custom" (hard 400), and
 *   - custom mode never ran the advanced pipeline (mode !== 'advanced').
 *
 * We test the pure shared helpers (lib/scan-plan.js) that BOTH the API route and
 * the scan engine use, so the assertions reflect real behavior without making any
 * network calls. Run with:  npm test   (node --test)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseScanRequest, scanPlan } = require('../lib/scan-plan');

// ---------------------------------------------------------------------------
// 1. A valid Custom Mode request is accepted
// ---------------------------------------------------------------------------
test('valid custom request is accepted and keeps its instructions', () => {
  const r = parseScanRequest({
    target: 'https://example.com',
    mode: 'custom',
    instructions: 'focus on /api/v1, test the session cookie',
  });
  assert.equal(r.error, undefined);
  assert.equal(r.target, 'https://example.com');
  assert.equal(r.mode, 'custom');
  assert.equal(r.instructions, 'focus on /api/v1, test the session cookie');
});

// ---------------------------------------------------------------------------
// 2. Missing / empty instructions is rejected with a clear error
// ---------------------------------------------------------------------------
test('custom mode without instructions is rejected', () => {
  const missing = parseScanRequest({ target: 'https://example.com', mode: 'custom' });
  assert.match(missing.error, /instructions/i);

  const empty = parseScanRequest({ target: 'https://example.com', mode: 'custom', instructions: '' });
  assert.match(empty.error, /instructions/i);

  const whitespace = parseScanRequest({ target: 'https://example.com', mode: 'custom', instructions: '   ' });
  assert.match(whitespace.error, /instructions/i);
});

test('a missing target is rejected regardless of mode', () => {
  const r = parseScanRequest({ mode: 'custom', instructions: 'x' });
  assert.match(r.error, /target/i);
});

// ---------------------------------------------------------------------------
// 3. Instructions reach the scanner
//    (a) the parser forwards them; (b) custom runs the advanced pipeline whose
//    Burp Intruder phase consumes them.
// ---------------------------------------------------------------------------
test('instructions are forwarded to the engine for custom mode', () => {
  const r = parseScanRequest({ target: 'https://x.io', mode: 'custom', instructions: '/admin\ntoken param' });
  // trimmed, non-empty, passed through as the engine's instructions argument
  assert.equal(r.instructions, '/admin\ntoken param');
});

test('legacy "custom" field is still accepted as an alias for instructions', () => {
  const r = parseScanRequest({ target: 'https://x.io', mode: 'custom', custom: '/legacy/path' });
  assert.equal(r.error, undefined);
  assert.equal(r.instructions, '/legacy/path');
});

test('custom mode executes the advanced pipeline (not a basic fallback)', () => {
  const plan = scanPlan('custom');
  assert.equal(plan.runAdvanced, true, 'custom must run advanced phases incl. the instruction-consuming Intruder');
  assert.equal(plan.isBasic, false);
  assert.equal(plan.isCustom, true);
});

// ---------------------------------------------------------------------------
// 4. Advanced Mode is unchanged
// ---------------------------------------------------------------------------
test('advanced mode behavior is preserved', () => {
  const plan = scanPlan('advanced');
  assert.deepEqual(plan, { isBasic: false, isAdvanced: true, isCustom: false, runAdvanced: true });

  // advanced does not require instructions
  const r = parseScanRequest({ target: 'https://example.com', mode: 'advanced' });
  assert.equal(r.error, undefined);
  assert.equal(r.mode, 'advanced');
  assert.equal(r.instructions, undefined);
});

test('custom and advanced run the same pipeline; only custom carries instructions', () => {
  assert.equal(scanPlan('custom').runAdvanced, scanPlan('advanced').runAdvanced);
});

// ---------------------------------------------------------------------------
// Basic mode stays non-intrusive
// ---------------------------------------------------------------------------
test('basic mode does not run the advanced pipeline', () => {
  const plan = scanPlan('basic');
  assert.equal(plan.runAdvanced, false);
  assert.equal(plan.isBasic, true);

  // unknown modes fall back to basic
  assert.equal(scanPlan('wat').runAdvanced, false);
  assert.equal(parseScanRequest({ target: 'https://x', mode: 'nope' }).mode, 'basic');
});
