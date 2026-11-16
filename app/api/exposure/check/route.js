import { validEmail, normEmail } from '../../../../lib/email';
import { runExposureCheck } from '../../../../lib/exposure';

export const dynamic = 'force-dynamic';
export const maxDuration = 40;

// POST /api/exposure/check  { email }
// Exposure results are server-allowlisted (no credentials, stealer-log contents,
// personal data, or enrichment).
export async function POST(request) {
  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid request.' }, { status: 400 }); }

  const email = normEmail(body && body.email);
  if (!validEmail(email)) return Response.json({ error: 'Enter a valid email address.' }, { status: 400 });

  try {
    const result = await runExposureCheck(email);
    return Response.json(result, { headers: { 'Cache-Control': 'no-store' } });
  } catch {
    return Response.json({ error: 'The exposure check could not be completed. Please try again.' }, { status: 502 });
  }
}
