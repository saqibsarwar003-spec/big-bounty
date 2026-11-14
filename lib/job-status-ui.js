'use strict';

const TERMINAL_JOB_STATUSES = new Set([
  'completed', 'failed', 'cancelled', 'canceled', 'timed-out', 'timedout', 'timeout',
]);

function normalizeJobStatus(status) {
  return String(status || 'queued').trim().toLowerCase().replace(/_/g, '-');
}

function isTerminalJobStatus(status) {
  return TERMINAL_JOB_STATUSES.has(normalizeJobStatus(status));
}

// The worker currently emits coarse statuses, but future phase-level states
// remain active until an explicit terminal status arrives.
function isCurrentJobRequest(requestJobId, requestGeneration, activeJobId, activeGeneration) {
  return requestJobId === activeJobId && requestGeneration === activeGeneration;
}

module.exports = { normalizeJobStatus, isTerminalJobStatus, isCurrentJobRequest };
