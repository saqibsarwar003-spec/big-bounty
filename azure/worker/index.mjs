// Big Bounty VM worker (runs on the Linux VM "New").
//
//   queue(bigbounty-jobs) --> [auth re-check] --> existing engine --> results
//
// Responsibilities (project steps 9, 10, 20):
//   - async job consumption from an Azure Storage queue
//   - durable job state + progress + logs in Table Storage
//   - independent, server-side authorization re-check (never trusts the queue
//     message alone — re-reads the auth table)
//   - result collection to Blob storage; findings summary + coverage to the job
//   - retries (via queue visibility), poison handling, duplicate protection
//   - resource-aware: bounded concurrency + per-job timeout for a small VM
//
// The browser can close/refresh freely: this process owns the job to completion.

import { QueueClient } from '@azure/storage-queue';
import { TableClient } from '@azure/data-tables';
import { BlobServiceClient } from '@azure/storage-blob';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { runEngine } from './engine-adapter.mjs';

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const { computeCoverage } = require(path.resolve(HERE, '../../lib/coverage.js'));

const CONN = process.env.AzureWebJobsStorage || process.env.BIGBOUNTY_STORAGE_CONNECTION;
const QUEUE = process.env.BIGBOUNTY_JOBS_QUEUE || 'bigbounty-jobs';
const JOBS_TABLE = process.env.BIGBOUNTY_JOBS_TABLE || 'bigbountyjobs';
const AUTH_TABLE = process.env.BIGBOUNTY_AUTH_TABLE || 'bigbountyauth';
const RESULTS = process.env.BIGBOUNTY_RESULTS_CONTAINER || 'bigbounty-results';
const JOB_PART = 'job', AUTH_PART = 'target';

const MAX_CONCURRENCY = Math.max(1, Number(process.env.BIGBOUNTY_MAX_CONCURRENCY || '1'));   // tiny VM -> 1
const JOB_TIMEOUT_MS = Number(process.env.BIGBOUNTY_JOB_TIMEOUT_MS || '600000');             // 10 min
const MAX_ATTEMPTS = Number(process.env.BIGBOUNTY_MAX_ATTEMPTS || '3');
const IDLE_MS = Number(process.env.BIGBOUNTY_POLL_IDLE_MS || '5000');
const PROGRESS_THROTTLE_MS = 3000;

if (!CONN) { console.error('FATAL: AzureWebJobsStorage/BIGBOUNTY_STORAGE_CONNECTION not set'); process.exit(1); }

const queue = new QueueClient(CONN, QUEUE);
const jobs = TableClient.fromConnectionString(CONN, JOBS_TABLE);
const auth = TableClient.fromConnectionString(CONN, AUTH_TABLE);
const blobSvc = BlobServiceClient.fromConnectionString(CONN);

const log = (...a) => console.log(new Date().toISOString(), ...a);

async function mergeJob(jobId, patch) {
  try {
    await jobs.updateEntity({ partitionKey: JOB_PART, rowKey: jobId, updatedAt: new Date().toISOString(), ...patch }, 'Merge');
  } catch (e) { log('mergeJob failed', jobId, e.message); }
}

function authorized(rec, domain) {
  if (!rec || rec.state !== 'authorized' || !rec.expiresAt) return false;
  if (new Date(rec.expiresAt).getTime() <= Date.now()) return false;
  // scope: the attestation row key IS the domain; enforce exact-host scope.
  return String(rec.rowKey).toLowerCase() === String(domain).toLowerCase();
}

async function writeResult(jobId, result) {
  const container = blobSvc.getContainerClient(RESULTS);
  await container.createIfNotExists();
  const name = `${jobId}.json`;
  const body = JSON.stringify(result);
  const blob = container.getBlockBlobClient(name);
  await blob.upload(body, Buffer.byteLength(body), { blobHTTPHeaders: { blobContentType: 'application/json' } });
  return name;
}

async function processMessage(msg) {
  let payload;
  try { payload = JSON.parse(Buffer.from(msg.messageText, 'base64').toString('utf8')); }
  catch { log('poison: unparseable message', msg.messageId); await queue.deleteMessage(msg.messageId, msg.popReceipt); return; }

  const { jobId, domain } = payload;
  if (!jobId) { await queue.deleteMessage(msg.messageId, msg.popReceipt); return; }
  const attempt = msg.dequeueCount || 1;
  log(`job ${jobId} (${domain}) attempt ${attempt}`);

  // Already-finished? (dup protection / idempotency)
  try {
    const existing = await jobs.getEntity(JOB_PART, jobId);
    if (existing.status === 'completed' || existing.status === 'failed') {
      log(`job ${jobId} already ${existing.status}; dropping message`);
      await queue.deleteMessage(msg.messageId, msg.popReceipt);
      return;
    }
  } catch { /* no job row yet; proceed */ }

  // INDEPENDENT authorization re-check — do not trust the queue message alone.
  let authRec = null;
  try { authRec = await auth.getEntity(AUTH_PART, domain); } catch { authRec = null; }
  if (!authorized(authRec, domain)) {
    log(`job ${jobId} REJECTED: no current authorization for ${domain}`);
    await mergeJob(jobId, { status: 'failed', error: 'authorization missing or expired at execution time', stage: 'authorization' });
    await queue.deleteMessage(msg.messageId, msg.popReceipt); // not retryable
    return;
  }

  // Too many attempts -> poison
  if (attempt > MAX_ATTEMPTS) {
    log(`job ${jobId} exceeded ${MAX_ATTEMPTS} attempts; failing`);
    await mergeJob(jobId, { status: 'failed', error: `exceeded ${MAX_ATTEMPTS} attempts`, attempts: attempt });
    await queue.deleteMessage(msg.messageId, msg.popReceipt);
    return;
  }

  await mergeJob(jobId, { status: 'running', stage: 'starting', progress: 5, attempts: attempt, startedAt: new Date().toISOString() });

  // Throttled progress persistence
  let lastWrite = 0, pending = null;
  const onProgress = (u) => {
    pending = u;
    const now = Date.now();
    if (now - lastWrite >= PROGRESS_THROTTLE_MS) { lastWrite = now; const p = pending; pending = null; mergeJob(jobId, p); }
  };

  try {
    const result = await runEngine(
      { target: payload.target, mode: payload.mode, custom: payload.params?.custom, domain },
      onProgress, JOB_TIMEOUT_MS,
    );

    const coverage = computeCoverage({ mode: payload.mode, toolsUsed: result.toolsUsed, findings: result.findings });
    const blobName = await writeResult(jobId, { ...result, jobId, coverage });

    await mergeJob(jobId, {
      status: 'completed', progress: 100, stage: 'done',
      resultBlob: blobName,
      findingsSummary: JSON.stringify(result.summary || {}),
      coverage: JSON.stringify({ coveragePct: coverage.coveragePct, confidence: coverage.confidence, severity: coverage.severity }),
      completedAt: new Date().toISOString(),
    });
    await queue.deleteMessage(msg.messageId, msg.popReceipt);
    log(`job ${jobId} completed -> ${blobName}`);
  } catch (e) {
    const retryable = attempt < MAX_ATTEMPTS && e.message !== 'engine timeout';
    log(`job ${jobId} error: ${e.message} (retryable=${retryable})`);
    if (retryable) {
      // Leave the message to reappear after its visibility timeout; mark queued.
      await mergeJob(jobId, { status: 'queued', stage: 'retrying', error: e.message });
    } else {
      await mergeJob(jobId, { status: 'failed', stage: 'error', error: e.message, attempts: attempt });
      await queue.deleteMessage(msg.messageId, msg.popReceipt);
    }
  }
}

let shuttingDown = false;
process.on('SIGTERM', () => { shuttingDown = true; log('SIGTERM; draining'); });
process.on('SIGINT', () => { shuttingDown = true; log('SIGINT; draining'); });

async function main() {
  await queue.createIfNotExists();
  try { await blobSvc.getContainerClient(RESULTS).createIfNotExists(); } catch {}
  log(`worker up. queue=${QUEUE} concurrency=${MAX_CONCURRENCY} jobTimeout=${JOB_TIMEOUT_MS}ms`);
  const inflight = new Set();

  while (!shuttingDown) {
    const slots = MAX_CONCURRENCY - inflight.size;
    if (slots <= 0) { await new Promise(r => setTimeout(r, 250)); continue; }
    let resp;
    try {
      // visibility timeout must exceed the max job runtime so a message doesn't
      // reappear while still being worked.
      resp = await queue.receiveMessages({ numberOfMessages: Math.min(slots, 8), visibilityTimeout: Math.ceil(JOB_TIMEOUT_MS / 1000) + 60 });
    } catch (e) { log('receive error', e.message); await new Promise(r => setTimeout(r, IDLE_MS)); continue; }

    const msgs = resp?.receivedMessageItems || [];
    if (!msgs.length) { await new Promise(r => setTimeout(r, IDLE_MS)); continue; }

    for (const m of msgs) {
      const p = processMessage(m).catch(e => log('unhandled', e.message)).finally(() => inflight.delete(p));
      inflight.add(p);
    }
  }
  await Promise.allSettled([...inflight]);
  log('worker stopped');
}

main().catch(e => { console.error('worker fatal', e); process.exit(1); });
