'use strict';
/**
 * Server-only client for the Big Bounty Azure control plane (Function App).
 *
 * Every call is authenticated two ways, exactly as the Function App expects:
 *   - Azure function key   -> x-functions-key header
 *   - HMAC-SHA256 over "{timestamp}.{rawBody}" with BIGBOUNTY_HMAC_SECRET
 *     -> x-signature + x-timestamp (300s replay window on the server)
 *
 * NEVER import this into client components. All three env vars are server-side
 * secrets and must never reach the browser:
 *   BIGBOUNTY_FUNCTIONS_BASE  e.g. https://<app>.azurewebsites.net/api
 *   BIGBOUNTY_FUNCTION_KEY    the host function key
 *   BIGBOUNTY_HMAC_SECRET     shared secret with the Function App
 */

const crypto = require('crypto');

function cfg() {
  const base = process.env.BIGBOUNTY_FUNCTIONS_BASE;
  const key = process.env.BIGBOUNTY_FUNCTION_KEY;
  const secret = process.env.BIGBOUNTY_HMAC_SECRET;
  if (!base || !key || !secret) {
    const miss = ['BIGBOUNTY_FUNCTIONS_BASE', 'BIGBOUNTY_FUNCTION_KEY', 'BIGBOUNTY_HMAC_SECRET'].filter(k => !process.env[k]);
    const e = new Error('control plane not configured: missing ' + miss.join(', '));
    e.code = 'CONTROL_PLANE_UNCONFIGURED';
    throw e;
  }
  return { base: base.replace(/\/+$/, ''), key, secret };
}

function sign(secret, timestamp, rawBody) {
  return crypto.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
}

async function call(method, path, bodyObj) {
  const { base, key, secret } = cfg();
  const raw = bodyObj === undefined ? '' : JSON.stringify(bodyObj);
  const ts = Math.floor(Date.now() / 1000).toString();
  const headers = {
    'x-functions-key': key,
    'x-signature': sign(secret, ts, raw),
    'x-timestamp': ts,
  };
  if (bodyObj !== undefined) headers['content-type'] = 'application/json';

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 15000);
  let res;
  try {
    res = await fetch(`${base}${path}`, { method, headers, body: bodyObj === undefined ? undefined : raw, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  return { status: res.status, ok: res.ok, data };
}

/** Create a durable scan job. Returns { jobId, status } or throws on transport error. */
async function createJob({ target, mode = 'basic', authorized, clientJobKey, params, requester, clientUserAgent, clientIp }) {
  return call('POST', '/jobs', { target, mode, authorized, clientJobKey, params, requester, clientUserAgent, clientIp });
}

/** Poll job status + result pointer. */
async function getJob(jobId) {
  return call('GET', `/jobs/${encodeURIComponent(jobId)}`);
}

/** Full stored result (findings/evidence/AI/coverage) once a job has completed. */
async function getJobResult(jobId) {
  return call('GET', `/jobs/${encodeURIComponent(jobId)}/result`);
}

/** Read-only server-side authorization state for a domain. */
async function getTarget(domain) {
  return call('GET', `/targets/${encodeURIComponent(domain)}`);
}

function controlPlaneConfigured() {
  try { cfg(); return true; } catch { return false; }
}

module.exports = { createJob, getJob, getJobResult, getTarget, controlPlaneConfigured };
