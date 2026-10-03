import { runScan } from '../../../lib/scanner';
import { parseScanRequest } from '../../../lib/scan-plan';

// Vercel Fluid Compute: up to 300s allowed on Hobby. Browser attacks + heavy
// scans need this headroom; a hard kill here was the source of "[object Object]".
export const maxDuration = 300;
export const dynamic = 'force-dynamic';

function bad(msg, status = 400) {
  return Response.json({ error: String(msg) }, { status, headers: { 'Cache-Control': 'no-store' } });
}

export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return bad('Invalid JSON body — send {"target":"https://example.com","mode":"basic|advanced|custom"}');
  }

  // Validation + field normalization (accepts "instructions" or legacy "custom").
  const parsed = parseScanRequest(body);
  if (parsed.error) return bad(parsed.error);
  const { target, mode, instructions } = parsed;

  const enc = new TextEncoder();
  const started = Date.now();

  const stream = new ReadableStream({
    async start(controller) {
      let closed = false;
      const send = (obj) => { if (!closed) { try { controller.enqueue(enc.encode(JSON.stringify(obj) + '\n')); } catch { closed = true; } } };
      try {
        const result = await runScan(target, mode, instructions, {
          onPhase: (p) => send({ type: 'phase', ...p }),
        });
        send({ type: 'done', result: { ...result, apiDurationMs: Date.now() - started } });
      } catch (e) {
        send({ type: 'error', error: 'Scan error: ' + (e && e.message ? e.message : String(e)) });
      }
      closed = true;
      try { controller.close(); } catch {}
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Cache-Control': 'no-store, no-transform',
      'X-Accel-Buffering': 'no',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

export async function GET() {
  return Response.json({
    service: 'Big Bounty',
    version: '3.1',
    real: true,
    streaming: true,
    note: 'All findings are backed by live HTTP/DNS/RDAP evidence + PoC curl commands. No simulated data.',
    usage: {
      'POST /api/scan': { target: 'https://example.com', mode: 'basic|advanced|custom', instructions: '(custom mode)' },
    },
    modes: {
      basic: 'recon, dirs, headers, CORS, tech, secrets — non-intrusive',
      advanced: 'basic + subdomains, XSS, SQLi, redirect, CVEs, real bypass attacks (auth bypass, LFI, SSRF, takeover) with PoC',
      custom: 'advanced + your own instructions (paths, params, notes)',
    },
    browser: process.env.BROWSERBASE_API_KEY ? 'enabled (Browserbase remote browser)' : 'disabled (no BROWSERBASE_API_KEY)',
  });
}