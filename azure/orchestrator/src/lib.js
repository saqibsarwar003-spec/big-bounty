// Shared helpers for the Big Bounty control plane.
// Scope: orchestration + ENFORCED authorization. Every active job must be tied
// to a server-side authorization record before it can be dispatched. This layer
// performs no security testing itself.
//
// Authorization model (v2): the user-facing "I am authorized to test this
// target" checkbox is recorded SERVER-SIDE as a signed attestation keyed to the
// target domain, the authenticated caller (HMAC from Vercel), and a timestamp,
// with a TTL. The checkbox value alone is never trusted by the worker: the
// Function App writes the attestation record, createJob gates on it, and the VM
// worker independently re-reads it from the auth table before testing. The old
// DNS-TXT / .well-known proof-of-control workflow has been removed.

import crypto from 'node:crypto';
import { QueueServiceClient } from '@azure/storage-queue';
import { TableClient } from '@azure/data-tables';
import { BlobServiceClient } from '@azure/storage-blob';
import { ManagedIdentityCredential } from '@azure/identity';

const CONN = process.env.AzureWebJobsStorage;
const JOBS_QUEUE = process.env.BIGBOUNTY_JOBS_QUEUE || 'bigbounty-jobs';
const JOBS_TABLE = process.env.BIGBOUNTY_JOBS_TABLE || 'bigbountyjobs';
const AUTH_TABLE = process.env.BIGBOUNTY_AUTH_TABLE || 'bigbountyauth';
const HMAC_SECRET = process.env.BIGBOUNTY_HMAC_SECRET || '';
const REPLAY_WINDOW_SEC = 300;

export const PARTITION = 'job';
export const AUTH_PARTITION = 'target';
export const AUTH_TTL_DAYS = Number(process.env.BIGBOUNTY_AUTH_TTL_DAYS || '30');
export const SUBSCRIPTION_ID = process.env.BIGBOUNTY_SUBSCRIPTION_ID;
export const VM_RG = process.env.BIGBOUNTY_VM_RG || 'New_group';
export const VM_NAME = process.env.BIGBOUNTY_VM_NAME || 'New';
export const RESULTS_CONTAINER = process.env.BIGBOUNTY_RESULTS_CONTAINER || 'bigbounty-results';

/** Read a stored scan result blob (full findings/evidence/AI) as a JSON string. */
export async function readResultBlob(blobName) {
  const c = BlobServiceClient.fromConnectionString(CONN).getContainerClient(RESULTS_CONTAINER);
  const dl = await c.getBlockBlobClient(blobName).download();
  const chunks = [];
  for await (const ch of dl.readableStreamBody) chunks.push(Buffer.isBuffer(ch) ? ch : Buffer.from(ch));
  return Buffer.concat(chunks).toString('utf8');
}

// Private/reserved ranges a target must never resolve into (anti-SSRF / stop the
// VM being used to pivot into internal infra). Hostname-level guard; the worker
// enforces the authoritative resolved-IP check too.
const BLOCKED_HOST_RX = /^(localhost|.*\.local|.*\.internal|0\.0\.0\.0|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?|\[?fc00:|\[?fe80:)/i;

export function queueClient(name = JOBS_QUEUE) {
  return QueueServiceClient.fromConnectionString(CONN).getQueueClient(name);
}
export function jobsTable() { return TableClient.fromConnectionString(CONN, JOBS_TABLE); }
export function authTable() { return TableClient.fromConnectionString(CONN, AUTH_TABLE); }

// ---- HMAC (Vercel <-> Function App) ----
export function verifyHmac(rawBody, signature, timestamp) {
  if (!HMAC_SECRET) return { ok: false, reason: 'server misconfigured: no HMAC secret' };
  if (!signature || !timestamp) return { ok: false, reason: 'missing signature/timestamp' };
  const skew = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!Number.isFinite(skew) || skew > REPLAY_WINDOW_SEC) return { ok: false, reason: 'stale timestamp' };
  const expected = crypto.createHmac('sha256', HMAC_SECRET).update(`${timestamp}.${rawBody}`).digest('hex');
  const a = Buffer.from(expected), b = Buffer.from(String(signature));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, reason: 'bad signature' };
  return { ok: true };
}

export async function readBody(request) {
  const raw = await request.text();
  let json = null;
  try { json = raw ? JSON.parse(raw) : null; } catch { /* leave null */ }
  return { raw, json };
}

// ---- Target normalization + scope guard ----
export function normalizeDomain(target) {
  let h = String(target || '').trim();
  if (!h) return null;
  if (!/^https?:\/\//i.test(h)) h = 'https://' + h;
  try { return new URL(h).hostname.toLowerCase(); } catch { return null; }
}

/** True when a hostname is a public, testable target (not loopback/private/internal). */
export function isPublicHost(domain) {
  if (!domain) return false;
  if (BLOCKED_HOST_RX.test(domain)) return false;
  if (!domain.includes('.')) return false; // bare hostnames / single-label
  return true;
}

// ---- Authorization attestation ----
// A record is authorized when it is in state 'authorized' and not past its TTL.
export function isAuthorizedRecord(rec) {
  if (!rec || rec.state !== 'authorized') return false;
  if (!rec.expiresAt) return false;
  return new Date(rec.expiresAt).getTime() > Date.now();
}

/**
 * Record (or refresh) a server-side authorization attestation for a domain.
 * Returns the stored record. Caller must have passed HMAC auth AND an explicit
 * authorized===true confirmation before calling this.
 */
export async function recordAttestation(domain, { requester, userAgent, sourceIp } = {}) {
  const table = authTable();
  let prev = null;
  try { prev = await table.getEntity(AUTH_PARTITION, domain); } catch { prev = null; }
  const now = new Date().toISOString();
  const attestationId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + AUTH_TTL_DAYS * 86400000).toISOString();
  const entity = {
    partitionKey: AUTH_PARTITION, rowKey: domain,
    state: 'authorized',
    method: 'attestation',
    attestationId,
    requester: String(requester || '').slice(0, 128),
    userAgent: String(userAgent || '').slice(0, 256),
    sourceIp: String(sourceIp || '').slice(0, 64),
    verifiedAt: now,          // kept for schema compatibility with existing readers
    expiresAt,
    createdAt: prev?.createdAt || now,
    updatedAt: now,
  };
  await table.upsertEntity(entity, 'Replace');
  return entity;
}

// ---- VM power (managed identity + ARM) ----
export function managementToken() {
  return new ManagedIdentityCredential().getToken('https://management.azure.com/.default');
}
export async function vmPowerState() {
  const tok = await managementToken();
  const url = `https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${VM_RG}/providers/Microsoft.Compute/virtualMachines/${VM_NAME}/instanceView?api-version=2023-09-01`;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${tok.token}` } });
  if (!r.ok) throw new Error(`instanceView ${r.status}`);
  const d = await r.json();
  const ps = (d.statuses || []).map(s => s.code).find(c => c && c.startsWith('PowerState/'));
  return ps ? ps.replace('PowerState/', '') : 'unknown';
}
export async function vmAction(action) {
  const tok = await managementToken();
  const url = `https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${VM_RG}/providers/Microsoft.Compute/virtualMachines/${VM_NAME}/${action}?api-version=2023-09-01`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${tok.token}` } });
  return { status: r.status, ok: r.status === 200 || r.status === 202 };
}
