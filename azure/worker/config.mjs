export const DEFAULT_JOB_TIMEOUT_MS = 30 * 60 * 1000;
export const MAX_JOB_TIMEOUT_MS = 30 * 60 * 1000;

/** Resolve the worker deadline while enforcing the approved maximum cap. */
export function resolveJobTimeoutMs(env = process.env) {
  const raw = String(env?.BIGBOUNTY_JOB_TIMEOUT_MS ?? '').trim();
  if (!raw) return DEFAULT_JOB_TIMEOUT_MS;

  const configured = Number(raw);
  if (!Number.isSafeInteger(configured) || configured <= 0) {
    return DEFAULT_JOB_TIMEOUT_MS;
  }

  return Math.min(configured, MAX_JOB_TIMEOUT_MS);
}
