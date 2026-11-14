'use strict';

const HISTORY_COOKIE = 'bb_history_v1';
const LEGACY_HISTORY_KEY = 'bb_history';
const LEGACY_ACTIVE_JOB_KEY = 'bb_job';
const MAX_HISTORY = 5;
const MAX_COOKIE_VALUE_LENGTH = 3000;
const COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function canonicalTarget(value) {
  const text = String(value == null ? '' : value).trim();
  if (!text) return '';
  try {
    const url = new URL(text);
    url.username = '';
    url.password = '';
    url.hash = '';
    return url.href;
  } catch {
    return text.split(/[?#]/, 1)[0].slice(0, 512);
  }
}

function hashPart(text, seed) {
  let hash = seed >>> 0;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

// A compact, non-security identifier lets comparison match the exact URL without
// putting query parameters (which may contain tokens) into the browser cookie.
function historyTargetKey(value) {
  const target = canonicalTarget(value);
  if (!target) return '';
  return hashPart(target, 0x811c9dc5) + hashPart(target, 0x9e3779b9);
}

function historyTargetLabel(value) {
  const text = String(value == null ? '' : value).trim();
  if (!text) return '';
  try {
    const url = new URL(text);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return `${url.origin}${url.pathname}`.slice(0, 180);
  } catch {
    return text.split(/[?#]/, 1)[0].slice(0, 180);
  }
}

function normalizeWhen(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.max(0, Math.floor(value));
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return Math.max(0, parsed);
  }
  return 0;
}

function normalizeSummary(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const summary = {};
  for (const severity of SEVERITIES) {
    const count = Number(value[severity]);
    if (Number.isFinite(count) && count > 0) summary[severity] = Math.min(9999, Math.floor(count));
  }
  return Object.keys(summary).length ? summary : undefined;
}

function normalizeEntry(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const jobId = String(value.jobId || '').trim();
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(jobId)) return null;
  const rawTarget = String(value.target || '').trim().slice(0, 2048);
  const mode = String(value.mode || 'basic').toLowerCase().slice(0, 16);
  const status = String(value.status || 'queued').toLowerCase().replace(/_/g, '-').slice(0, 24);
  const target = historyTargetLabel(rawTarget);
  const targetKey = String(value.targetKey || historyTargetKey(rawTarget)).slice(0, 32);
  const entry = { jobId, target, targetKey, mode, status, when: normalizeWhen(value.when) };
  const summary = normalizeSummary(value.summary);
  if (summary) entry.summary = summary;
  return entry;
}

function cookieValue(entries) {
  return encodeURIComponent(JSON.stringify(entries));
}

function limitHistory(entries) {
  const byId = new Map();
  for (const value of Array.isArray(entries) ? entries : []) {
    const entry = normalizeEntry(value);
    if (entry) byId.set(entry.jobId, { ...(byId.get(entry.jobId) || {}), ...entry });
  }
  let result = [...byId.values()].sort((a, b) => b.when - a.when).slice(0, MAX_HISTORY);
  while (result.length && cookieValue(result).length > MAX_COOKIE_VALUE_LENGTH) result = result.slice(0, -1);
  return result;
}

function readCookieValue(cookieHeader) {
  for (const part of String(cookieHeader || '').split(';')) {
    const trimmed = part.trim();
    const equals = trimmed.indexOf('=');
    if (equals < 0 || trimmed.slice(0, equals) !== HISTORY_COOKIE) continue;
    try { return decodeURIComponent(trimmed.slice(equals + 1)); } catch { return ''; }
  }
  return '';
}

function parseHistoryCookie(cookieHeader) {
  const raw = readCookieValue(cookieHeader);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? limitHistory(parsed) : [];
  } catch {
    return [];
  }
}

function migrateHistory(cookieHeader, legacyJson) {
  const current = parseHistoryCookie(cookieHeader);
  let legacy = [];
  try {
    const parsed = JSON.parse(String(legacyJson || '[]'));
    if (Array.isArray(parsed)) legacy = parsed;
  } catch { /* corrupt legacy data is discarded */ }
  // Current cookie entries win if an ID exists in both stores.
  return limitHistory([...legacy, ...current]);
}

function buildHistoryCookie(entries, secure = false) {
  const value = cookieValue(limitHistory(entries));
  return `${HISTORY_COOKIE}=${value}; Path=/; Max-Age=${COOKIE_MAX_AGE_SECONDS}; SameSite=Lax${secure ? '; Secure' : ''}`;
}

function loadBrowserHistory() {
  if (typeof document === 'undefined') return [];
  return parseHistoryCookie(document.cookie);
}

function saveBrowserHistory(entries) {
  const limited = limitHistory(entries);
  if (typeof document !== 'undefined') {
    const secure = typeof window !== 'undefined' && window.location && window.location.protocol === 'https:';
    try { document.cookie = buildHistoryCookie(limited, secure); } catch { /* cookies may be disabled */ }
  }
  return limited;
}

function migrateBrowserHistory() {
  if (typeof document === 'undefined') return [];
  let legacy = '[]';
  try {
    legacy = localStorage.getItem(LEGACY_HISTORY_KEY) || '[]';
    localStorage.removeItem(LEGACY_HISTORY_KEY);
    localStorage.removeItem(LEGACY_ACTIVE_JOB_KEY);
  } catch { /* storage may be disabled */ }
  const migrated = migrateHistory(document.cookie, legacy);
  if (migrated.length) saveBrowserHistory(migrated);
  return migrated;
}

module.exports = {
  HISTORY_COOKIE,
  MAX_HISTORY,
  MAX_COOKIE_VALUE_LENGTH,
  historyTargetKey,
  limitHistory,
  parseHistoryCookie,
  migrateHistory,
  buildHistoryCookie,
  loadBrowserHistory,
  saveBrowserHistory,
  migrateBrowserHistory,
};
