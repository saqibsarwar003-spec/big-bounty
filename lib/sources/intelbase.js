'use strict';
/**
 * IntelBase — defensive breach-exposure source (server-side only).
 *
 * SECURITY: IntelBase returns highly sensitive material — data_breaches.results[]
 * carry email/password/username/full_name/ip_address/phone_number/hash,
 * stealer_logs.results[] carry login/password, and stealer_enrichment carries
 * autofill/cards/user_info. NONE of that may reach the browser.
 *
 * normalizeIntelBase() is a strict ALLOWLIST: it constructs a brand-new object
 * containing ONLY defensive fields (breach source names, dates, affected domains,
 * high-level categories, a dated timeline, and generated recommendations). It
 * never copies raw IntelBase objects through, so credentials/PII/stealer-log
 * contents cannot leak even if IntelBase adds new sensitive fields later.
 */

const INTELBASE_BASE = process.env.INTELBASE_BASE_URL || 'https://api.intelbase.is';

async function fetchWithTimeout(url, opts, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(t); }
}

function toDomain(s) {
  if (!s || typeof s !== 'string') return undefined;
  try {
    if (s.includes('@')) return s.split('@').pop();
    const u = s.includes('://') ? new URL(s) : new URL('https://' + s);
    return u.hostname;
  } catch { return s.slice(0, 80); }
}
function str(x, n = 120) { return x == null ? undefined : String(x).slice(0, n); }

function buildRecommendations(inBreaches, inStealer) {
  const r = [];
  if (inBreaches) {
    r.push('Change your password on any affected service — and anywhere you reused that password.');
    r.push('Turn on two-factor authentication (authenticator app or hardware key) for those accounts.');
  }
  if (inStealer) {
    r.push('This address appears in infostealer/stealer-log data — treat the associated device and accounts as compromised.');
    r.push('Run a reputable anti-malware scan, then rotate all important passwords from a known-clean device and sign out all active sessions.');
  }
  if (!inBreaches && !inStealer) {
    r.push('No known breach exposure was found for this address. Keep using unique passwords and 2FA as a precaution.');
  }
  r.push('Use a password manager with a unique password per site to limit the blast radius of any future breach.');
  return r;
}

/**
 * Build the defensive, allowlisted view. Only the fields below ever leave here.
 */
function normalizeIntelBase(raw) {
  raw = raw && typeof raw === 'object' ? raw : {};
  const db = raw.data_breaches && typeof raw.data_breaches === 'object' ? raw.data_breaches : {};
  const results = Array.isArray(db.results) ? db.results : [];

  // Per-breach: ONLY source name + date + domain. Everything else is dropped.
  const seen = new Set();
  const breaches = [];
  for (const r of results) {
    if (!r || typeof r !== 'object') continue;
    const meta = r.source_meta && typeof r.source_meta === 'object' ? r.source_meta : {};
    const source = str(r.source || r.name || meta.name || meta.title || 'Unknown source', 120);
    const date = str(r.date || r.breach_date || meta.date, 40);
    const domain = toDomain(r.domain || meta.domain || source);
    const key = String(source).toLowerCase() + '|' + (date || '');
    if (seen.has(key)) continue;
    seen.add(key);
    breaches.push({ source, date, domain });
  }

  const sourceNames = Array.isArray(db.sources)
    ? db.sources.map((s) => (typeof s === 'string' ? str(s) : (s && str(s.name)))).filter(Boolean).slice(0, 50)
    : [];

  const amount = Number(db.amount) || 0;
  const inBreaches = amount > 0 || breaches.length > 0;

  const sl = raw.stealer_logs && typeof raw.stealer_logs === 'object' ? raw.stealer_logs : {};
  const inStealerLogs = !!(sl.compromised || (Number(sl.count) || 0) > 0 || (Array.isArray(sl.results) && sl.results.length > 0));

  const meta = raw.meta && typeof raw.meta === 'object' ? raw.meta : {};
  const timeline = Array.isArray(meta.timeline)
    ? meta.timeline.map((t) => ({ source: t && str(t.source), name: t && str(t.name, 160), date: t && str(t.date, 40) }))
        .filter((x) => x.source || x.name || x.date).slice(0, 100)
    : [];

  const exposureCategories = [];
  if (inBreaches) exposureCategories.push('Data breach exposure');
  if (inStealerLogs) exposureCategories.push('Infostealer / stealer-log exposure (treat as compromised)');
  if (!inBreaches && !inStealerLogs) exposureCategories.push('No known breach exposure found');

  return {
    inBreaches,
    breachCount: breaches.length || amount,
    inStealerLogs,          // boolean only — NO stealer-log contents are ever included
    firstSeen: str(meta.first_seen, 40),
    lastSeen: str(meta.last_seen, 40),
    breaches: breaches.slice(0, 200),
    sourceNames,
    timeline,
    exposureCategories,
    recommendations: buildRecommendations(inBreaches, inStealerLogs),
  };
}

async function lookupEmail(email, opts = {}) {
  const key = process.env.INTELBASE_API_KEY;
  if (!key) return { source: 'IntelBase', ok: false, error: 'IntelBase is not configured (missing API key).' };
  const timeoutMs = Math.min(Math.max(opts.timeoutMs || 12000, 2000), 30000);
  try {
    const res = await fetchWithTimeout(`${INTELBASE_BASE}/lookup/email`, {
      method: 'POST',
      headers: { 'x-api-key': key, 'content-type': 'application/json' },
      body: JSON.stringify({ email: String(email).trim().toLowerCase(), timeout_ms: timeoutMs, include_data_breaches: true }),
    }, timeoutMs + 3000);
    if (!res.ok) {
      let msg = `IntelBase error (HTTP ${res.status}).`;
      if (res.status === 401) msg = 'IntelBase rejected the request — invalid key, non-whitelisted IP, or quota exceeded.';
      else if (res.status === 403) msg = 'This email is blacklisted by IntelBase.';
      else if (res.status === 429) msg = 'IntelBase rate limit exceeded — please try again shortly.';
      else if (res.status === 400) msg = 'IntelBase rejected the request as malformed.';
      return { source: 'IntelBase', ok: false, error: msg };
    }
    const rawText = await res.text();
    let raw; try { raw = JSON.parse(rawText); } catch { return { source: 'IntelBase', ok: false, error: 'IntelBase returned an unreadable response.' }; }
    return { source: 'IntelBase', ok: true, data: normalizeIntelBase(raw) };
  } catch (e) {
    const timedOut = e && (e.name === 'AbortError' || /abort/i.test(e.message || ''));
    return { source: 'IntelBase', ok: false, error: timedOut ? 'IntelBase request timed out.' : 'IntelBase request failed.' };
  }
}

module.exports = { lookupEmail, normalizeIntelBase, buildRecommendations };
