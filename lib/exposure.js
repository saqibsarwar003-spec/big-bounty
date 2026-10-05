'use strict';
/**
 * Email Exposure orchestrator — runs each configured DEFENSIVE breach source
 * independently and reports per-source status so one failing source never hides
 * another's result, and every finding is attributable to its source. Pluggable:
 * add a source to SOURCES and it participates automatically.
 *
 * Every source must return an already-allowlisted defensive view (no credentials,
 * stealer-log contents, PII or enrichment) — this layer only aggregates.
 */
const intelbase = require('./sources/intelbase');

const SOURCES = [
  { id: 'intelbase', name: 'IntelBase', run: intelbase.lookupEmail },
  // Add more defensive sources here later; they run independently.
];

async function runExposureCheck(email, opts = {}) {
  const sources = await Promise.all(SOURCES.map(async (s) => {
    try {
      const r = await s.run(email, opts);
      return { id: s.id, name: s.name, ok: !!r.ok, data: r.ok ? r.data : undefined, error: r.ok ? undefined : (r.error || 'source failed') };
    } catch {
      return { id: s.id, name: s.name, ok: false, error: 'source failed unexpectedly' };
    }
  }));

  const ok = sources.some((s) => s.ok);
  // High-level, source-attributed summary (booleans OR'd across sources).
  const anyBreach = sources.some((s) => s.ok && s.data && s.data.inBreaches);
  const anyStealer = sources.some((s) => s.ok && s.data && s.data.inStealerLogs);

  return {
    email: String(email).trim().toLowerCase(),
    checkedAt: new Date().toISOString(),
    ok,
    summary: {
      anyBreach,
      anyStealer,
      sourcesRun: sources.length,
      sourcesOk: sources.filter((s) => s.ok).length,
    },
    sources,
  };
}

module.exports = { runExposureCheck, SOURCES };
