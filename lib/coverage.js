'use strict';
/**
 * Big Bounty — honest testing-coverage & confidence model.
 *
 * OWASP is explicit that security testing is an imperfect process: the absence
 * of findings never proves a target is secure. So this module deliberately does
 * NOT emit a "security score". It emits a *testing-coverage* metric — how much of
 * an OWASP-WSTG-aligned category catalog this scan actually exercised — plus a
 * separate evidence-confidence rating and an explicit list of what was not tested.
 *
 * All outputs are derived from real scan state (tools that ran, findings that
 * carried live evidence, categories skipped with reasons) — never an arbitrary
 * number.
 */

/**
 * Category catalog, aligned to OWASP WSTG families. `tools` are substrings
 * matched case-insensitively against toolsUsed and finding.tool. `tiers` says
 * which scan modes the category is considered *applicable* in — a category only
 * counts against coverage when it is applicable to the mode that ran, so a
 * passive "basic" scan is not penalised for skipping active injection tests.
 */
const CATEGORIES = [
  { id: 'INFO-01', label: 'Information gathering / recon', tools: ['recon', 'reconx', 'dns', 'crt', 'rdap'], tiers: ['basic', 'advanced', 'custom'] },
  { id: 'CONF-01', label: 'Configuration & deployment', tools: ['header', 'security-header', 'config', 'nuclei', 'advanced'], tiers: ['basic', 'advanced', 'custom'] },
  { id: 'CONF-02', label: 'Attack-surface / endpoint discovery', tools: ['dir', 'ffuf', 'kiterunner', 'endpoint', 'discovery'], tiers: ['basic', 'advanced', 'custom'] },
  { id: 'INFO-02', label: 'Technology fingerprinting', tools: ['tech', 'fingerprint', 'recon'], tiers: ['basic', 'advanced', 'custom'] },
  { id: 'INFO-03', label: 'Information disclosure / exposed secrets', tools: ['secret', 'exposure', 'recon'], tiers: ['basic', 'advanced', 'custom'] },
  { id: 'IDNT-01', label: 'Authentication / default credentials', tools: ['default-login', 'auth', 'redteam', 'nuclei'], tiers: ['advanced', 'custom'] },
  { id: 'SESS-01', label: 'Session management', tools: ['session', 'cookie', 'redteam'], tiers: ['advanced', 'custom'] },
  { id: 'AUTHZ-01', label: 'Authorization / access control', tools: ['authz', 'idor', 'redteam', 'attacks'], tiers: ['advanced', 'custom'] },
  { id: 'INPV-01', label: 'Injection (SQL / NoSQL / backend)', tools: ['sqli', 'sql', 'nosql', 'attacks'], tiers: ['advanced', 'custom'] },
  { id: 'INPV-02', label: 'Cross-site scripting (XSS/DOM)', tools: ['xss', 'browserbot', 'attacks'], tiers: ['advanced', 'custom'] },
  { id: 'INPV-03', label: 'Open redirect', tools: ['redirect', 'open-redirect', 'attacks'], tiers: ['advanced', 'custom'] },
  { id: 'INPV-04', label: 'Path traversal / file inclusion', tools: ['lfi', 'traversal', 'attacks', 'redteam'], tiers: ['advanced', 'custom'] },
  { id: 'INPV-05', label: 'SSRF / unsafe server-side requests', tools: ['ssrf', 'redteam', 'attacks'], tiers: ['advanced', 'custom'] },
  { id: 'CLNT-01', label: 'CORS / clickjacking / browser controls', tools: ['cors', 'clickjack', 'header'], tiers: ['basic', 'advanced', 'custom'] },
  { id: 'CONF-03', label: 'Known-CVE / version matching', tools: ['cve', 'nvd', 'advanced'], tiers: ['advanced', 'custom'] },
  { id: 'API-01', label: 'API / object-property authorization', tools: ['api', 'graphql', 'kiterunner'], tiers: ['advanced', 'custom'] },
  { id: 'BLGC-01', label: 'Business-logic / workflow', tools: ['logic', 'workflow'], tiers: ['custom'] },
];

const SEV_KEYS = ['critical', 'high', 'medium', 'low', 'info'];

function norm(s) { return String(s || '').toLowerCase(); }

function matchesCategory(cat, usedBlob, findingTools) {
  for (const t of cat.tools) {
    if (usedBlob.includes(t)) return true;
    for (const ft of findingTools) if (ft.includes(t)) return true;
  }
  return false;
}

/**
 * @param {object} inp
 * @param {string}   inp.mode                 basic|advanced|custom
 * @param {string[]} [inp.toolsUsed]          tool ids that actually ran
 * @param {object[]} [inp.findings]           finding objects {severity, tool, evidence, curl, ...}
 * @param {string[]} [inp.extraSkipped]       explicit category ids skipped (e.g. worker could not reach target)
 * @param {string[]} [inp.limitations]        free-text environmental limitations to surface verbatim
 * @returns {object} coverage report
 */
function computeCoverage(inp = {}) {
  const mode = ['basic', 'advanced', 'custom'].includes(inp.mode) ? inp.mode : 'basic';
  const toolsUsed = Array.isArray(inp.toolsUsed) ? inp.toolsUsed.map(norm) : [];
  const findings = Array.isArray(inp.findings) ? inp.findings : [];
  const usedBlob = ' ' + toolsUsed.join(' ') + ' ';
  const findingTools = findings.map(f => norm(f.tool));
  const extraSkipped = new Set((inp.extraSkipped || []).map(String));

  const applicable = CATEGORIES.filter(c => c.tiers.includes(mode));
  const exercised = [];
  const notTested = [];
  for (const cat of applicable) {
    const done = !extraSkipped.has(cat.id) && matchesCategory(cat, usedBlob, findingTools);
    (done ? exercised : notTested).push({ id: cat.id, label: cat.label });
  }

  const coveragePct = applicable.length ? Math.round((exercised.length / applicable.length) * 100) : 0;

  // severity counts
  const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const s = norm(f.severity);
    if (s in severity) severity[s]++;
  }

  // evidence confidence: share of non-info findings backed by concrete evidence
  const material = findings.filter(f => norm(f.severity) !== 'info');
  const withEvidence = material.filter(f => {
    const e = f.evidence;
    const hasE = e != null && (typeof e === 'string' ? e.length > 0 : Object.keys(e).length > 0);
    return hasE || (typeof f.curl === 'string' && f.curl.length > 0);
  });
  let confidence = 'N/A';
  if (material.length > 0) {
    const ratio = withEvidence.length / material.length;
    confidence = ratio >= 0.85 ? 'High' : ratio >= 0.5 ? 'Medium' : 'Low';
  } else {
    // no material findings — confidence reflects how much we actually tested
    confidence = coveragePct >= 70 ? 'High (no material findings)' : coveragePct >= 40 ? 'Medium (limited testing)' : 'Low (minimal testing)';
  }

  // non-guaranteeing posture label, derived purely from severity presence
  let posture;
  if (severity.critical > 0) posture = 'Critical issues require immediate attention';
  else if (severity.high > 0) posture = 'High-severity issues present';
  else if (severity.medium > 0) posture = 'Moderate issues present';
  else if (severity.low > 0 || severity.info > 0) posture = 'Only low/informational observations';
  else posture = 'No issues observed in the tests that ran';

  const areasNotTested = notTested.map(c => c.label);
  for (const lim of (inp.limitations || [])) if (lim) areasNotTested.push(String(lim));

  return {
    coveragePct,                 // LABELLED: testing coverage, not a security guarantee
    coverageLabel: 'Testing coverage (share of applicable OWASP-aligned categories exercised)',
    confidence,
    confidenceLabel: 'Evidence confidence across material findings',
    categoriesApplicable: applicable.length,
    categoriesExercised: exercised.length,
    checksCompleted: exercised,
    checksSkipped: notTested,
    severity,
    totalFindings: findings.length,
    posture,
    areasNotTested,
    disclaimer:
      'Automated security testing is inherently incomplete. These results reflect only the ' +
      'checks that ran against a live target at scan time; they cannot prove the absence of ' +
      'vulnerabilities. Coverage is a measure of testing breadth, NOT a guarantee of security. ' +
      'Treat findings as leads to verify, and combine with manual testing and code review.',
  };
}

module.exports = { computeCoverage, CATEGORIES, SEV_KEYS };
