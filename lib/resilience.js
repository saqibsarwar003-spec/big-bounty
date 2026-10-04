'use strict';
/**
 * Small resilience helpers. A single slow or broken scan module must never stall
 * or kill the whole job — every module runs with a hard timeout and its failure
 * is isolated. Pure and testable.
 */

/**
 * Race a promise against a timeout. Resolves with the promise's value, or rejects
 * with an Error carrying `__timeout = true` if `ms` elapses first. The timer is
 * always cleared so it never keeps the event loop alive.
 */
function withTimeout(promise, ms, label) {
  if (!ms || ms <= 0) return Promise.resolve(promise);
  let t;
  const timeout = new Promise((_, reject) => {
    t = setTimeout(() => {
      const e = new Error(`${label || 'module'} timed out after ${ms}ms`);
      e.__timeout = true;
      reject(e);
    }, ms);
  });
  return Promise.race([Promise.resolve(promise).finally(() => clearTimeout(t)), timeout]);
}

module.exports = { withTimeout };
