'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const S = require('../lib/job-status-ui');

test('phase-level lifecycle states remain active until an explicit terminal status', () => {
  for (const status of ['queued', 'running', 'dispatched', 'INITIALIZING', 'RECON', 'DISCOVERY', 'ACTIVE_TESTING', 'BROWSER_TESTING', 'CORRELATION', 'REPORTING', 'retrying']) {
    assert.equal(S.isTerminalJobStatus(status), false, status);
  }
});

test('failed, cancelled, completed and timed-out statuses are terminal regardless of casing', () => {
  for (const status of ['completed', 'FAILED', 'cancelled', 'CANCELED', 'TIMED_OUT', 'timeout']) {
    assert.equal(S.isTerminalJobStatus(status), true, status);
  }
  assert.equal(S.normalizeJobStatus('ACTIVE_TESTING'), 'active-testing');
});

test('late requests from a previous job or generation cannot update the current view', () => {
  assert.equal(S.isCurrentJobRequest('old-job', 1, 'new-job', 2), false);
  assert.equal(S.isCurrentJobRequest('new-job', 1, 'new-job', 2), false);
  assert.equal(S.isCurrentJobRequest('new-job', 2, 'new-job', 2), true);
});
