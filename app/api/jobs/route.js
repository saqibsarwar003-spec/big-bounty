import { createJob } from '../../../lib/control-plane';

export const dynamic = 'force-dynamic';

// POST /api/jobs  { target, mode, authorized, clientJobKey? }
// Creates a durable, server-side scan job via the Azure control plane and
// returns its id immediately. The scan then runs on the worker regardless of
// what the browser does (close/refresh safe). The single "authorized" flag is
// the user-facing confirmation; the backend records and enforces it server-side.
export async function POST(request) {
  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400, headers: { 'Cache-Control': 'no-store' } }); }

  const target = (body.target || '').trim();
  const mode = ['basic', 'advanced', 'custom'].includes(body.mode) ? body.mode : 'basic';

  if (!target) return Response.json({ error: 'A target URL is required — e.g. https://example.com' }, { status: 400 });
  if (body.authorized !== true) {
    return Response.json({ error: 'You must confirm you are authorized to test this target.' }, { status: 400 });
  }

  const clientIp = (request.headers.get('x-forwarded-for') || '').split(',')[0].trim();
  const clientUserAgent = request.headers.get('user-agent') || '';

  try {
    const r = await createJob({
      target, mode, authorized: true,
      clientJobKey: body.clientJobKey, params: body.params,
      requester: 'web', clientUserAgent, clientIp,
    });
    return Response.json(r.data || { error: 'control plane error' }, { status: r.status, headers: { 'Cache-Control': 'no-store' } });
  } catch (e) {
    if (e.code === 'CONTROL_PLANE_UNCONFIGURED') {
      return Response.json({ error: 'The scanning backend is not configured yet.' }, { status: 503 });
    }
    return Response.json({ error: 'Could not reach the scanning backend. Please retry.' }, { status: 502 });
  }
}
