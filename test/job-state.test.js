'use strict';
// Durable job-lifecycle tests. Run: node --test test/job-state.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const J = require('../lib/job-state');

test('transitions are forward-only; terminal is final; any active state can end', () => {
  assert.equal(J.canTransition(null, J.STATE.QUEUED), true);
  assert.equal(J.canTransition(J.STATE.QUEUED, J.STATE.RECON), true);
  assert.equal(J.canTransition(J.STATE.RECON, J.STATE.QUEUED), false);      // no going back
  assert.equal(J.canTransition(J.STATE.ACTIVE_TESTING, J.STATE.FAILED), true);
  assert.equal(J.canTransition(J.STATE.ACTIVE_TESTING, J.STATE.CANCELLED), true);
  assert.equal(J.canTransition(J.STATE.COMPLETED, J.STATE.RECON), false);   // terminal is final
  assert.equal(J.canTransition(J.STATE.FAILED, J.STATE.RUNNING), false);
});

test('mapPhaseToState groups engine phases into lifecycle states', () => {
  assert.equal(J.mapPhaseToState('recon'), J.STATE.RECON);
  assert.equal(J.mapPhaseToState('subdomains'), J.STATE.DISCOVERY);
  assert.equal(J.mapPhaseToState('sqli'), J.STATE.ACTIVE_TESTING);
  assert.equal(J.mapPhaseToState('browser-bypass'), J.STATE.BROWSER_TESTING);
  assert.equal(J.mapPhaseToState('verification'), J.STATE.CORRELATION);
  assert.equal(J.mapPhaseToState('something-new'), J.STATE.ACTIVE_TESTING); // safe default
});

test('normalizeStatus maps legacy coarse statuses', () => {
  assert.equal(J.normalizeStatus('running'), J.STATE.ACTIVE_TESTING);
  assert.equal(J.normalizeStatus('dispatched'), J.STATE.INITIALIZING);
  assert.equal(J.normalizeStatus('completed'), J.STATE.COMPLETED);
  assert.equal(J.normalizeStatus('queued'), J.STATE.QUEUED);
});

test('isStale flags orphaned non-terminal jobs only', () => {
  const now = Date.now();
  assert.equal(J.isStale({ status: 'running', updatedAt: now - 20 * 60 * 1000 }, now), true);
  assert.equal(J.isStale({ status: 'running', updatedAt: now - 60 * 1000 }, now), false);     // fresh
  assert.equal(J.isStale({ status: 'completed', updatedAt: now - 60 * 60 * 1000 }, now), false); // terminal
  assert.equal(J.isStale({ status: 'running', updatedAt: now - 5 * 60 * 1000 }, now, { staleMs: 60000 }), true);
});

test('isCancelRequested detects the cancel flag', () => {
  assert.equal(J.isCancelRequested({ cancelRequested: true }), true);
  assert.equal(J.isCancelRequested({ status: 'cancelling' }), true);
  assert.equal(J.isCancelRequested({ status: 'running' }), false);
  assert.equal(J.isCancelRequested(null), false);
});
