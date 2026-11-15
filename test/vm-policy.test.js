'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

let modulePromise;
function loadPolicy() {
  modulePromise ??= import('../azure/orchestrator/src/vm-policy.mjs');
  return modulePromise;
}

test('pending work wakes a deallocated or stopped worker', async () => {
  const { vmActionForWork } = await loadPolicy();
  assert.equal(vmActionForWork({ queueDepth: 1, powerState: 'deallocated' }), 'start');
  assert.equal(vmActionForWork({ activeJobs: 1, powerState: 'stopped' }), 'start');
});

test('pending work does not issue duplicate starts for a running or starting VM', async () => {
  const { vmActionForWork } = await loadPolicy();
  assert.equal(vmActionForWork({ queueDepth: 2, powerState: 'running' }), null);
  assert.equal(vmActionForWork({ activeJobs: 1, powerState: 'starting' }), null);
});

test('an idle running or starting worker is deallocated', async () => {
  const { vmActionForWork } = await loadPolicy();
  assert.equal(vmActionForWork({ powerState: 'running' }), 'deallocate');
  assert.equal(vmActionForWork({ powerState: 'starting' }), 'deallocate');
});

test('an idle stopped VM is left alone and unknown states are not guessed', async () => {
  const { vmActionForWork } = await loadPolicy();
  assert.equal(vmActionForWork({ powerState: 'deallocated' }), null);
  assert.equal(vmActionForWork({ queueDepth: 1, powerState: 'unknown' }), null);
});
