'use strict';
/**
 * Secret redaction for findings and reports. Scrubs credential-looking values so
 * tokens / cookies / API keys / JWTs / session identifiers / passwords never
 * appear in evidence, curl reproductions, PoCs, or downloadable reports.
 * Pure, defensive, conservative (aims not to mangle ordinary prose).
 */

const PATTERNS = [
  [/(authorization\s*[:=]\s*)(bearer\s+)?[A-Za-z0-9._~+/=-]{12,}/gi, '$1$2[REDACTED]'],
  [/(set-cookie\s*[:=]\s*)[^\n\r'"]{4,}/gi, '$1[REDACTED]'],
  [/(cookie\s*[:=]\s*)[^\n\r'"]{4,}/gi, '$1[REDACTED]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g, '[REDACTED_JWT]'],
  [/\b(?:sk|rk)-[A-Za-z0-9]{16,}\b/g, '[REDACTED_KEY]'],
  [/\bnvapi-[A-Za-z0-9_-]{16,}\b/g, '[REDACTED_KEY]'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, '[REDACTED_TOKEN]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED_AWS_KEY]'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, '[REDACTED_SLACK]'],
  [/(password["']?\s*[:=]\s*["']?)[^\s"',}]{3,}/gi, '$1[REDACTED]'],
  [/(["'](?:api[_-]?key|secret|token|passwd|pwd|client[_-]?secret)["']\s*:\s*["'])[^"']{4,}(["'])/gi, '$1[REDACTED]$2'],
];

function redactString(s) {
  if (typeof s !== 'string') return s;
  let out = s;
  for (const [re, rep] of PATTERNS) out = out.replace(re, rep);
  return out;
}

// Evidence keys whose string values are always masked wholesale.
const SENSITIVE_KEYS = /^(cookie|cookiepreview|setcookie|set-cookie|authorization|auth|token|jwt|session|sessionid|session_id|apikey|api_key|secret|password|passwd|pwd|credential|credentials)$/i;

function redactEvidence(val, depth = 0) {
  if (depth > 6 || val == null) return val;
  if (typeof val === 'string') return redactString(val);
  if (Array.isArray(val)) return val.map((v) => redactEvidence(v, depth + 1));
  if (typeof val === 'object') {
    const out = {};
    for (const k of Object.keys(val)) {
      out[k] = (SENSITIVE_KEYS.test(k) && typeof val[k] === 'string') ? '[REDACTED]' : redactEvidence(val[k], depth + 1);
    }
    return out;
  }
  return val;
}

function redactFinding(f) {
  if (!f || typeof f !== 'object') return f;
  const g = { ...f };
  if (g.evidence != null) g.evidence = redactEvidence(g.evidence);
  if (typeof g.curl === 'string') g.curl = redactString(g.curl);
  if (typeof g.desc === 'string') g.desc = redactString(g.desc);
  if (g.poc && typeof g.poc === 'object') {
    g.poc = { ...g.poc };
    if (typeof g.poc.curl === 'string') g.poc.curl = redactString(g.poc.curl);
    if (g.poc.request != null) g.poc.request = redactEvidence(g.poc.request);
    if (g.poc.evidence != null) g.poc.evidence = redactEvidence(g.poc.evidence);
  }
  return g;
}

module.exports = { redactString, redactEvidence, redactFinding };
