import { validEmail, normEmail, issueChallenge } from '../../../../lib/email-verify';
import { sendVerificationEmail } from '../../../../lib/mailer';

export const dynamic = 'force-dynamic';
export const maxDuration = 20;

// POST /api/exposure/start  { email }
// Validates the email, issues a one-time code, emails it, and returns an opaque
// token (NOT the code). The browser later submits code + token to /check.
export async function POST(request) {
  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid request.' }, { status: 400 }); }

  const email = normEmail(body && body.email);
  if (!validEmail(email)) return Response.json({ error: 'Enter a valid email address.' }, { status: 400 });

  const key = process.env.BIGBOUNTY_HMAC_SECRET;
  if (!key) return Response.json({ error: 'Verification is not available right now (server not configured).' }, { status: 503 });

  const { token, expiresAt, code } = issueChallenge(email, key);
  const delivery = await sendVerificationEmail(email, code);
  // The code is never returned to the client or logged.

  return Response.json({
    ok: true,
    token,
    expiresAt,
    delivery: delivery.sent ? 'sent' : 'not_configured',
    message: delivery.sent
      ? 'We sent a verification code to your email. Enter it to view your exposure results.'
      : 'Email delivery is not configured on this deployment, so the code cannot be sent. Verification is required before any results are shown.',
    deliveryReason: delivery.sent ? undefined : delivery.reason,
  }, { headers: { 'Cache-Control': 'no-store' } });
}
