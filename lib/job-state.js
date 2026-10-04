'use strict';
/**
 * Durable job lifecycle — a single source of truth for async-job recovery.
 *
 * Builds ON the existing worker/control-plane model (queued → dispatched → running
 * → completed|failed stays valid as coarse status) by adding the richer lifecycle
 * states, forward-only transition validation, engine-phase → state mapping,
 * stale/orphan detection (worker crash / VM deallocated mid-job), and a
 * cancellation check. Pure and testable; no Azure, no I/O.
 */

const STATE = {
  QUEUED: 'QUEUED',
  INITIALIZING: 'INITIALIZING',
  RECON: 'RECON',
  DISCOVERY: 'DISCOVERY',
  ACTIVE_TESTING: 'ACTIVE_TESTING',
  BROWSER_TESTING: 'BROWSER_TESTING',
  CORRELATION: 'CORRELATION',
  REPORTING: 'REPORTING',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
  CANCELLED: 'CANCELLED',
  TIMED_OUT: 'TIMED_OUT',
};

const TERMINAL = new Set([STATE.COMPLETED, STATE.FAILED, STATE.CANCELLED, STATE.TIMED_OUT]);

// Forward progression of the active pipeline. Any active state may also jump to a
// terminal state (fail/cancel/timeout/complete) at any time.
const ORDER = [
  STATE.QUEUED, STATE.INITIALIZING, STATE.RECON, STATE.DISCOVERY,
  STATE.ACTIVE_TESTING, STATE.BROWSER_TESTING, STATE.CORRELATION, STATE.REPORTING, STATE.COMPLETED,
];

function isTerminal(s) { return TERMINAL.has(s); }

function canTransition(from, to) {
  if (!STATE[String(to || '').toUpperCase()] && !TERMINAL.has(to)) return false;
  if (!from) return true;                    // first state
  if (isTerminal(from)) return false;        // terminal is final
  if (TERMINAL.has(to)) return true;         // any active state can end
  const i = ORDER.indexOf(from), j = ORDER.indexOf(to);
  if (i === -1 || j === -1) return false;
  return j >= i;                             // forward-only (same = idempotent re-emit)
}

// Map an engine phase name to a coarse lifecycle state for the UI/progress.
const PHASE_MAP = {
  'scope-guard': STATE.INITIALIZING, fetch: STATE.INITIALIZING,
  recon: STATE.RECON, headers: STATE.RECON, cors: STATE.RECON, tech: STATE.RECON, secrets: STATE.RECON,
  subdomains: STATE.DISCOVERY, dirs: STATE.DISCOVERY, exposure: STATE.DISCOVERY,
  reconx: STATE.DISCOVERY, 'endpoint-discovery-audit': STATE.DISCOVERY,
  xss: STATE.ACTIVE_TESTING, sqli: STATE.ACTIVE_TESTING, redirect: STATE.ACTIVE_TESTING, cves: STATE.ACTIVE_TESTING,
  nuclei: STATE.ACTIVE_TESTING, redteam: STATE.ACTIVE_TESTING, 'advanced-pack': STATE.ACTIVE_TESTING,
  attacks: STATE.ACTIVE_TESTING, intruder: STATE.ACTIVE_TESTING, ffuf: STATE.ACTIVE_TESTING,
  kiterunner: STATE.ACTIVE_TESTING, 'zap-fuzzer': STATE.ACTIVE_TESTING, 'burp-repeater': STATE.ACTIVE_TESTING,
  'browser-bypass': STATE.BROWSER_TESTING,
  'ai-triage': STATE.CORRELATION, verification: STATE.CORRELATION,
  report: STATE.REPORTING, reporting: STATE.REPORTING,
};
function mapPhaseToState(phase) { return PHASE_MAP[String(phase || '').toLowerCase()] || STATE.ACTIVE_TESTING; }

function toMs(v) { if (!v) return 0; if (typeof v === 'number') return v; const t = Date.parse(v); return isNaN(t) ? 0 : t; }

function normalizeStatus(s) {
  const u = String(s || '').toUpperCase();
  if (STATE[u]) return STATE[u];
  const legacy = {
    DISPATCHED: STATE.INITIALIZING, RUNNING: STATE.ACTIVE_TESTING,
    CANCELLING: STATE.CANCELLED, TIMEDOUT: STATE.TIMED_OUT, RETRYING: STATE.QUEUED,
  };
  return legacy[u] || STATE.QUEUED;
}

/**
 * Stale/orphan detection: a non-terminal job whose last update is older than the
 * threshold is presumed orphaned (worker crashed or VM deallocated mid-job) and
 * should be requeued or failed by a reaper.
 */
function isStale(job, now = Date.now(), opts = {}) {
  if (!job) return false;
  if (isTerminal(normalizeStatus(job.status))) return false;
  const last = toMs(job.updatedAt || job.heartbeatAt || job.startedAt || job.enqueuedAt);
  if (!last) return false;
  return (now - last) > (opts.staleMs || 15 * 60 * 1000);
}

/** Cancellation request flag — the worker checks this between phases to stop early. */
function isCancelRequested(job) {
  return !!(job && (job.cancelRequested === true || job.cancel === true || String(job.status).toLowerCase() === 'cancelling'));
}

module.exports = {
  STATE, TERMINAL, ORDER,
  isTerminal, canTransition, mapPhaseToState, isStale, isCancelRequested, normalizeStatus,
};
