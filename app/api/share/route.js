import { createShareToken } from '../../../lib/share-token';

export const dynamic = 'force-dynamic';

function signingKey() {
  const k = process.env.BIGBOUNTY_HMAC_SECRET;
  if (!k) { const e = new Error('no signing secret'); e.code = 'NO_SECRET'; throw e; }
  return k;
}

// POST /api/share  { jobId, ttlDays? }  -> a signed, expiring share link.
// The token is a cryptographically-signed grant over the jobId (no internal
// ids or secrets exposed) and is independently revocable by its embedded jti.
export async function POST(request) {
  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  const jobId = (body.jobId || '').trim();
  if (!jobId) return Response.json({ error: 'jobId required' }, { status: 400 });
  const ttlDays = Math.min(Math.max(Number(body.ttlDays) || 7, 1), 90);

  try {
    const { token, exp, jti } = createShareToken(jobId, signingKey(), { ttlMs: ttlDays * 86400000 });
    return Response.json({
      token, jti,
      url: `/report/${token}`,
      expiresAt: new Date(exp).toISOString(),
    }, { headers: { 'Cache-Control': 'no-store' } });
  } catch (e) {
    return Response.json({ error: 'Share links are not available (backend not configured).' }, { status: 503 });
  }
}
