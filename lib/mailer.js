'use strict';
/**
 * Transactional email for the ownership-verification code.
 *
 * Uses the Resend HTTP API when configured (no npm dependency, works on Vercel
 * serverless). If not configured it returns { sent:false } so the flow degrades
 * safely — without delivery the user can't get the code, so no exposure data is
 * ever shown. Set RESEND_API_KEY and EMAIL_FROM to enable. The code is never
 * logged.
 */

async function sendVerificationEmail(to, code) {
  const from = process.env.EMAIL_FROM;
  const resendKey = process.env.RESEND_API_KEY;
  if (!from || !resendKey) {
    return { sent: false, reason: 'email delivery not configured (set RESEND_API_KEY and EMAIL_FROM)' };
  }
  const subject = 'Your Big Bounty verification code';
  const text = `Your Big Bounty Email Exposure Check verification code is:\n\n    ${code}\n\nIt expires in 10 minutes. If you did not request this, you can ignore this email.`;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 10000);
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { authorization: `Bearer ${resendKey}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from, to, subject, text }),
      signal: ctrl.signal,
    });
    clearTimeout(t);
    if (!res.ok) return { sent: false, reason: `email provider error (HTTP ${res.status})` };
    return { sent: true };
  } catch {
    return { sent: false, reason: 'email send failed' };
  }
}

module.exports = { sendVerificationEmail };
