const OFF_STATES = new Set(['deallocated', 'stopped']);
const ON_STATES = new Set(['running', 'starting']);

/** Decide whether pending work should wake the VM or idle state should park it. */
export function vmActionForWork({ queueDepth = 0, activeJobs = 0, powerState = 'unknown' } = {}) {
  const hasWork = Number(queueDepth) > 0 || Number(activeJobs) > 0;
  const state = String(powerState || 'unknown').toLowerCase();

  if (hasWork && OFF_STATES.has(state)) return 'start';
  if (!hasWork && ON_STATES.has(state)) return 'deallocate';
  return null;
}
