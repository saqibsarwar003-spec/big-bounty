import { validEmail, normEmail, verifyChallenge } from '../../../../lib/email-verify';
import { runExposureCheck } from '../../../../lib/exposure';

export const dynamic = 'force-dynamic';
export const maxDuration = 40;

// POST /api/exposure/check  { email, code, token }
// Results are returned ONLY after the one-time code is verified for that email —
// i.e. proof the caller controls the mailbox. The exposure data is allowlisted
// server-side (no credentials / stealer-log contents / PII / enrichment).
export async function POST(request) {
  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid request.' }, { status: 400 }); }

  const email = normEmail(body && body.email);
  const code = body && body.code;
  const token = body && body.token;
  if (!validEmail(email)) return Response.json({ error: 'Enter a valid email address.' }, { status: 400 });

  const key = process.env.BIGBOUNTY_HMAC_SECRET;
  const v = verifyChallenge(email, code, token, key);
  if (!v.ok) return Response.json({ verified: false, error: 'Verification failed: ' + v.reason }, { status: 401 });

  try {
    const result = await runExposureCheck(email);
    return Response.json({ verified: true, ...result }, { headers: { 'Cache-Control': 'no-store' } });
  } catch {
    return Response.json({ verified: true, error: 'The exposure check could not be completed. Please try again.' }, { status: 502 });
  }
}
