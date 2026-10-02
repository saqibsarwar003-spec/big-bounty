'use strict';
/**
 * Big Bounty — scan-to-scan comparison (pre-release regression view).
 *
 * Lets a developer scan a staging site, fix issues, scan again, and see exactly
 * what changed: new / resolved / unchanged findings, severity changes, and the
 * coverage delta. Finding identity is a stable fingerprint over WHAT and WHERE
 * (tool + normalized title + location) but NOT severity — so a severity change
 * on the same underlying issue is reported as a change, not as one resolved +
 * one new finding.
 */

function norm(s) { return String(s == null ? '' : s).toLowerCase().trim(); }

/** Best-effort location extraction from a finding's evidence/detail. */
function locationOf(f) {
  const e = f && f.evidence;
  if (e && typeof e === 'object') {
    for (const k of ['url', 'endpoint', 'path', 'param', 'location', 'subdomain', 'host']) {
      if (e[k]) return norm(e[k]);
    }
  }
  if (f && f.location) return norm(f.location);
  return '';
}

/** Stable identity key: tool + normalized title + location (severity excluded). */
function identity(f) {
  const title = norm(f.title).replace(/\s+/g, ' ').replace(/[0-9]{2,}/g, '#');
  return `${norm(f.tool)}::${title}::${locationOf(f)}`;
}

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
function sevRank(s) { return SEV_RANK[norm(s)] ?? -1; }

function brief(f) {
  return { id: f.id, severity: norm(f.severity), tool: f.tool, title: f.title, location: locationOf(f) || undefined };
}

/**
 * @param {object} prev  previous scan record { findings, coverage? }
 * @param {object} curr  current scan record  { findings, coverage? }
 * @returns {object} diff summary
 */
function diffScans(prev, curr) {
  const prevF = (prev && prev.findings) || [];
  const currF = (curr && curr.findings) || [];
  const prevMap = new Map();
  for (const f of prevF) if (!prevMap.has(identity(f))) prevMap.set(identity(f), f);
  const currMap = new Map();
  for (const f of currF) if (!currMap.has(identity(f))) currMap.set(identity(f), f);

  const newFindings = [];
  const resolved = [];
  const unchanged = [];
  const severityChanges = [];

  for (const [key, f] of currMap) {
    if (!prevMap.has(key)) { newFindings.push(brief(f)); continue; }
    const p = prevMap.get(key);
    if (norm(p.severity) !== norm(f.severity)) {
      severityChanges.push({
        ...brief(f),
        from: norm(p.severity),
        to: norm(f.severity),
        direction: sevRank(f.severity) > sevRank(p.severity) ? 'worse' : 'better',
      });
    } else {
      unchanged.push(brief(f));
    }
  }
  for (const [key, f] of prevMap) {
    if (!currMap.has(key)) resolved.push(brief(f));
  }

  const coverageChange = (prev && curr && prev.coverage && curr.coverage &&
    Number.isFinite(prev.coverage.coveragePct) && Number.isFinite(curr.coverage.coveragePct))
    ? curr.coverage.coveragePct - prev.coverage.coveragePct
    : null;

  const sevDelta = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const count = (arr, sign) => { for (const f of arr) { const s = norm(f.severity); if (s in sevDelta) sevDelta[s] += sign; } };
  count(currF, 1); count(prevF, -1);

  return {
    summary: {
      new: newFindings.length,
      resolved: resolved.length,
      unchanged: unchanged.length,
      severityChanged: severityChanges.length,
      coverageChange,       // percentage points; null if unknown
      netSeverityDelta: sevDelta,
      improved: resolved.length > newFindings.length ||
                severityChanges.some(c => c.direction === 'better') && !severityChanges.some(c => c.direction === 'worse') && newFindings.length === 0,
    },
    newFindings,
    resolved,
    unchanged,
    severityChanges,
  };
}

module.exports = { diffScans, identity, locationOf };
