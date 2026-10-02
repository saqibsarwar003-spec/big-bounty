// Big Bounty control plane (Azure Functions v4, Node 22+).
//
// Vercel --(HMAC)--> Function App --(queue)--> VM "New" worker
//
// Authorization model (v2 — attestation):
//   The site UI shows ONE checkbox ("I confirm I am authorized to test this
//   target"). createJob requires authorized===true, records a SERVER-SIDE
//   attestation (keyed to domain + caller + time, with a TTL), and gates every
//   job on that record. The VM worker re-reads the attestation from the auth
//   table before testing, so the client's checkbox value is never trusted on
//   its own. The old DNS-TXT / .well-known proof-of-control workflow has been
//   removed per product direction.
//
// Job states: queued -> dispatched -> running -> completed | failed

import { app } from '@azure/functions';
import { randomUUID } from 'node:crypto';
import {
  PARTITION, AUTH_PARTITION, AUTH_TTL_DAYS,
  queueClient, jobsTable, authTable, verifyHmac, readBody,
  normalizeDomain, isPublicHost, isAuthorizedRecord, recordAttestation,
  vmPowerState, vmAction, readResultBlob,
} from './lib.js';

async function auth(request, context) {
  const { raw, json } = await readBody(request);
  const v = verifyHmac(raw, request.headers.get('x-signature'), request.headers.get('x-timestamp'));
  if (!v.ok) {
    context.warn(`auth rejected: ${v.reason}`);
    return { ok: false, res: { status: 401, jsonBody: { error: 'unauthorized' } } };
  }
  return { ok: true, raw, json };
}

function authView(rec) {
  return {
    domain: rec.rowKey,
    state: isAuthorizedRecord(rec) ? 'authorized' : (rec.state === 'authorized' ? 'expired' : rec.state),
    method: rec.method ?? null,
    verifiedAt: rec.verifiedAt ?? null,
    expiresAt: rec.expiresAt ?? null,
    createdAt: rec.createdAt,
  };
}

// ---- GET /api/targets/{domain} : report server-side authorization state ----
// Read-only; lets the UI show "authorized until <date>" so a repeat scan within
// the TTL needn't re-tick anything. No verification workflow is involved.
app.http('getTarget', {
  methods: ['GET'], authLevel: 'function', route: 'targets/{domain}',
  handler: async (request, context) => {
    const v = verifyHmac('', request.headers.get('x-signature'), request.headers.get('x-timestamp'));
    if (!v.ok) return { status: 401, jsonBody: { error: 'unauthorized' } };
    const domain = normalizeDomain(request.params.domain);
    if (!domain) return { status: 400, jsonBody: { error: 'invalid domain' } };
    try {
      const rec = await authTable().getEntity(AUTH_PARTITION, domain);
      return { status: 200, jsonBody: authView(rec) };
    } catch {
      return { status: 404, jsonBody: { domain, state: 'authorization_required' } };
    }
  },
});

// ---- POST /api/jobs : create a job (records attestation, then gates on it) ----
app.http('createJob', {
  methods: ['POST'], authLevel: 'function', route: 'jobs',
  handler: async (request, context) => {
    const a = await auth(request, context);
    if (!a.ok) return a.res;
    const b = a.json || {};
    if (!b.target || !b.mode) return { status: 400, jsonBody: { error: 'target and mode are required' } };

    // The single user-facing confirmation. Required, and recorded server-side.
    if (b.authorized !== true) {
      return { status: 403, jsonBody: { error: 'authorization confirmation required', field: 'authorized' } };
    }

    const domain = normalizeDomain(b.target);
    if (!domain) return { status: 400, jsonBody: { error: 'invalid target' } };
    if (!isPublicHost(domain)) {
      return { status: 400, jsonBody: { error: 'target must be a public host (loopback/private/internal addresses are not permitted)', domain } };
    }

    // Record (or refresh) the server-side attestation, then enforce the gate.
    // Writing then checking keeps a single code path for the worker's independent
    // re-read and for direct-to-queue safety.
    let rec;
    try {
      rec = await recordAttestation(domain, {
        requester: b.requester || b.account || 'vercel',
        userAgent: b.clientUserAgent,
        sourceIp: b.clientIp,
      });
    } catch (e) {
      context.error(`attestation write failed: ${e.message}`);
      return { status: 503, jsonBody: { error: 'could not record authorization; try again' } };
    }
    if (!isAuthorizedRecord(rec)) {
      return { status: 403, jsonBody: { error: 'target not authorized', domain } };
    }

    const jobId = randomUUID();
    const now = new Date().toISOString();
    const table = jobsTable();

    // Duplicate-job protection: a client can pass a stable clientJobKey so a
    // retried/refreshed request returns the SAME job instead of starting a new one.
    if (b.clientJobKey) {
      const dupes = table.listEntities({ queryOptions: { filter: `PartitionKey eq '${PARTITION}' and clientJobKey eq '${String(b.clientJobKey).replace(/'/g, "''")}'` } });
      for await (const d of dupes) return { status: 200, jsonBody: { jobId: d.rowKey, status: d.status, deduped: true } };
    }

    await table.createEntity({
      partitionKey: PARTITION, rowKey: jobId,
      status: 'queued', target: b.target, mode: b.mode, domain,
      authScope: domain, authAttestationId: rec.attestationId, authVerifiedAt: rec.verifiedAt,
      clientJobKey: b.clientJobKey ?? '', progress: 0, attempts: 0, createdAt: now, updatedAt: now,
    });

    // The queue message carries the attestation so the worker can independently
    // confirm it against the auth table before doing anything active.
    const msg = {
      jobId, target: b.target, mode: b.mode, domain, params: b.params ?? {},
      authorization: { attestationId: rec.attestationId, verifiedAt: rec.verifiedAt, expiresAt: rec.expiresAt, scope: domain },
      enqueuedAt: now,
    };
    await queueClient().sendMessage(Buffer.from(JSON.stringify(msg)).toString('base64'));

    // Wake the worker VM if it's asleep (fire-and-forget; idleVmStopper parks it later).
    (async () => {
      try {
        const ps = await vmPowerState();
        if (ps === 'deallocated' || ps === 'stopped') await vmAction('start');
      } catch (e) { context.warn(`VM start skipped: ${e.message}`); }
    })();

    return { status: 202, jsonBody: { jobId, status: 'queued', domain, authorizedUntil: rec.expiresAt } };
  },
});

// ---- GET /api/jobs/{id} : status + result pointer ----
app.http('getJob', {
  methods: ['GET'], authLevel: 'function', route: 'jobs/{id}',
  handler: async (request, context) => {
    const v = verifyHmac('', request.headers.get('x-signature'), request.headers.get('x-timestamp'));
    if (!v.ok) return { status: 401, jsonBody: { error: 'unauthorized' } };
    try {
      const e = await jobsTable().getEntity(PARTITION, request.params.id);
      return { status: 200, jsonBody: {
        jobId: e.rowKey, status: e.status, mode: e.mode, target: e.target, domain: e.domain,
        progress: e.progress ?? 0, stage: e.stage ?? null,
        findingsSummary: e.findingsSummary ? JSON.parse(e.findingsSummary) : null,
        coverage: e.coverage ? JSON.parse(e.coverage) : null,
        resultBlob: e.resultBlob ?? null, error: e.error ?? null,
        createdAt: e.createdAt, updatedAt: e.updatedAt, attempts: e.attempts ?? 0,
      } };
    } catch { return { status: 404, jsonBody: { error: 'not found' } }; }
  },
});

// ---- GET /api/jobs/{id}/result : full stored result (findings/evidence/AI) ----
app.http('getJobResult', {
  methods: ['GET'], authLevel: 'function', route: 'jobs/{id}/result',
  handler: async (request, context) => {
    const v = verifyHmac('', request.headers.get('x-signature'), request.headers.get('x-timestamp'));
    if (!v.ok) return { status: 401, jsonBody: { error: 'unauthorized' } };
    let e;
    try { e = await jobsTable().getEntity(PARTITION, request.params.id); }
    catch { return { status: 404, jsonBody: { error: 'not found' } }; }
    if (!e.resultBlob) return { status: 409, jsonBody: { error: 'result not ready', status: e.status } };
    try {
      const json = await readResultBlob(e.resultBlob);
      return { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }, body: json };
    } catch (err) {
      context.error(`result read failed: ${err.message}`);
      return { status: 500, jsonBody: { error: 'could not read result' } };
    }
  },
});

// ---- Timer: deallocate the worker VM when there is nothing to do ----
app.timer('idleVmStopper', {
  schedule: '0 */5 * * * *',
  handler: async (_timer, context) => {
    try {
      const depth = (await queueClient().getProperties()).approximateMessagesCount ?? 0;
      let active = 0;
      const it = jobsTable().listEntities({ queryOptions: { filter: `PartitionKey eq '${PARTITION}' and (status eq 'queued' or status eq 'running' or status eq 'dispatched')` } });
      for await (const _ of it) { active++; break; }
      if (depth === 0 && active === 0) {
        const ps = await vmPowerState();
        if (ps === 'running' || ps === 'starting') { await vmAction('deallocate'); context.log('idle: deallocated VM'); }
      }
    } catch (e) { context.warn(`idleVmStopper: ${e.message}`); }
  },
});
