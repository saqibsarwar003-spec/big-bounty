'use strict';
/**
 * Engine-level scope & SSRF guard.
 *
 * Mirrors the Azure control-plane policy (azure/orchestrator/src/lib.js) so the
 * scanner refuses internal / loopback / link-local / cloud-metadata / non-HTTP
 * targets even on the legacy /api/scan path and inside the worker — defense in
 * depth so Big Bounty can never be turned into an SSRF proxy. Pure, no network.
 */

// Same hostname blocklist the control plane uses — keep them in sync.
const BLOCKED_HOST_RX = /^(localhost|.*\.local|.*\.internal|0\.0\.0\.0|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?|\[?fc00:|\[?fe80:)/i;
const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

function normalizeTarget(input) {
  let h = String(input || '').trim();
  if (!h) return { error: 'empty target' };
  const schemeMatch = h.match(/^([a-z][a-z0-9+.\-]*):/i);
  if (schemeMatch && !/^https?$/i.test(schemeMatch[1])) {
    return { error: `scheme "${schemeMatch[1]}:" is not allowed — only http/https targets can be scanned (blocks file://, gopher://, dict://, etc.)` };
  }
  if (!/^https?:\/\//i.test(h)) h = 'https://' + h;
  let u;
  try { u = new URL(h); } catch { return { error: 'invalid URL' }; }
  if (!ALLOWED_SCHEMES.has(u.protocol)) return { error: `scheme "${u.protocol}" is not allowed` };
  return { url: u.toString(), hostname: u.hostname.toLowerCase(), origin: u.origin };
}

function isPublicHost(hostname) {
  if (!hostname) return false;
  const h = String(hostname).toLowerCase();
  if (BLOCKED_HOST_RX.test(h)) return false;
  if (!h.includes('.')) return false;            // single-label / bare hostnames
  if (/^0x[0-9a-f]+$/i.test(h) || /^\d{8,}$/.test(h)) return false; // hex/decimal localhost tricks
  return true;
}

const THIRD_PARTY = [
  'google.com', 'googleapis.com', 'gstatic.com', 'google-analytics.com', 'googletagmanager.com',
  'doubleclick.net', 'vercel.com', 'cloudflare.com', 'cloudflareinsights.com', 'amazonaws.com',
  'azureedge.net', 'fbcdn.net', 'facebook.com', 'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
  'fonts.googleapis.com', 'fonts.gstatic.com',
];

function scopeManifest(hostname) {
  const root = String(hostname || '').replace(/^www\./, '');
  return {
    root,
    inScope: [root, 'www.' + root],
    outOfScopeExamples: THIRD_PARTY,
    policy: 'First-party only. Discovered subdomains of the root are tracked separately; third-party CDN/SaaS hosts are out of scope and are not actively tested.',
  };
}

/** True when `hostname` belongs to the authorized root scope. */
function inScope(hostname, manifest) {
  if (!hostname || !manifest || !manifest.root) return false;
  const h = String(hostname).toLowerCase();
  return h === manifest.root || h.endsWith('.' + manifest.root);
}

/** Entry-point assessment. Returns { ok, url, hostname, origin, manifest } or { ok:false, reason }. */
function assessTarget(input) {
  const n = normalizeTarget(input);
  if (n.error) return { ok: false, reason: n.error };
  if (!isPublicHost(n.hostname)) {
    return {
      ok: false, hostname: n.hostname, url: n.url,
      reason: `target "${n.hostname}" is a private, loopback, link-local, cloud-metadata, or single-label host and is refused by the scope/SSRF policy. Only public, authorized targets can be scanned.`,
    };
  }
  return { ok: true, url: n.url, hostname: n.hostname, origin: n.origin, manifest: scopeManifest(n.hostname) };
}

module.exports = { normalizeTarget, isPublicHost, assessTarget, scopeManifest, inScope, BLOCKED_HOST_RX };
