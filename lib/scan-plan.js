'use strict';
/**
 * Single source of truth for how a /api/scan request maps to engine behavior.
 *
 * Pure functions only — no network, no side effects — so the request-validation
 * and mode-routing rules can be unit-tested cheaply and are shared by both the
 * API route (app/api/scan/route.js) and the scan engine (lib/scanner.js).
 */

/**
 * Normalize + validate an incoming scan request body.
 * @returns {{target:string,mode:string,instructions?:string}} on success,
 *          or {{error:string}} when the request is invalid.
 */
function parseScanRequest(body) {
  if (!body || typeof body !== 'object') {
    return { error: 'Invalid JSON body — send {"target":"https://example.com","mode":"basic|advanced|custom"}' };
  }

  const target = typeof body.target === 'string' ? body.target.trim() : '';
  const mode = body.mode === 'advanced' || body.mode === 'custom' ? body.mode : 'basic';

  // The UI sends "instructions"; "custom" is accepted as a legacy alias so older
  // clients keep working. Both carry the same meaning for custom mode.
  const raw = typeof body.instructions === 'string'
    ? body.instructions
    : typeof body.custom === 'string'
      ? body.custom
      : '';
  const instructions = raw.trim() ? raw.trim() : undefined;

  if (!target) return { error: 'target URL is required — e.g. https://example.com' };
  if (mode === 'custom' && !instructions) {
    return { error: 'custom mode requires a non-empty "instructions" field' };
  }

  return { target, mode, instructions };
}

/**
 * Decide which pipeline a mode runs. Custom runs the full advanced pipeline AND
 * additionally applies the user's instructions (consumed downstream, e.g. by the
 * Burp Intruder segment fuzzer). Advanced behavior is unchanged.
 */
function scanPlan(mode) {
  const isBasic = mode === 'basic';
  const isAdvanced = mode === 'advanced';
  const isCustom = mode === 'custom';
  const runAdvanced = isAdvanced || isCustom;
  return { isBasic, isAdvanced, isCustom, runAdvanced };
}

module.exports = { parseScanRequest, scanPlan };
