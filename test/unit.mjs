// Standalone unit tests for the pure platform modules. Run: node test/unit.mjs
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const share = require('../lib/share-token.js');
const { computeCoverage } = require('../lib/coverage.js');
const { diffScans } = require('../lib/compare.js');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); pass++; console.log('  ok  ' + name); }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e && e.message)); }
}

console.log('\n# share-token');
t('reportId is non-guessable and prefixed', () => {
  const a = share.newReportId(), b = share.newReportId();
  assert.notEqual(a, b);
  assert.match(a, /^r_[A-Za-z0-9_-]{20,}$/);
});
t('randomId entropy & charset', () => {
  assert.match(share.randomId(20), /^[A-Za-z0-9_-]+$/);
  assert.equal(new Set(Array.from({ length: 200 }, () => share.randomId(16))).size, 200);
});
t('token round-trips and carries reportId', () => {
  const rid = share.newReportId();
  const { token } = share.createShareToken(rid, 'secretkey');
  const v = share.verifyShareToken(token, 'secretkey');
  assert.equal(v.valid, true);
  assert.equal(v.reportId, rid);
});
t('tampered body fails signature', () => {
  const { token } = share.createShareToken('r_abc', 'secretkey');
  const [body, sig] = token.split('.');
  const forged = Buffer.from('{"v":1,"rid":"r_HACK","jti":"x","iat":1,"exp":9999999999}').toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'') + '.' + sig;
  assert.equal(share.verifyShareToken(forged, 'secretkey').valid, false);
  assert.equal(share.verifyShareToken(body + '.' + sig.slice(0, -2) + 'xx', 'secretkey').reason, 'bad_signature');
});
t('wrong key fails', () => {
  const { token } = share.createShareToken('r_abc', 'key-one');
  assert.equal(share.verifyShareToken(token, 'key-two').valid, false);
});
t('expiry enforced', () => {
  const now = 1_000_000_000_000;
  const { token } = share.createShareToken('r_abc', 'k', { ttlMs: 1000, now });
  assert.equal(share.verifyShareToken(token, 'k', { now: now + 500 }).valid, true);
  assert.equal(share.verifyShareToken(token, 'k', { now: now + 2000 }).reason, 'expired');
});
t('revocation by jti', () => {
  const { token, jti } = share.createShareToken('r_abc', 'k');
  const revoked = new Set([jti]);
  assert.equal(share.verifyShareToken(token, 'k', { isRevoked: (j) => revoked.has(j) }).reason, 'revoked');
});
t('ttl is capped at MAX_TTL', () => {
  const now = 1_000_000_000_000;
  const { exp } = share.createShareToken('r_abc', 'k', { ttlMs: share.MAX_TTL_MS * 10, now });
  assert.ok(exp <= now + share.MAX_TTL_MS + 1000);
});

console.log('\n# coverage');
t('basic mode: passive categories, no false penalty for injection', () => {
  const c = computeCoverage({ mode: 'basic', toolsUsed: ['reconx', 'tech', 'headers', 'cors', 'secrets'], findings: [] });
  assert.ok(c.coveragePct > 0 && c.coveragePct <= 100);
  assert.ok(!c.checksSkipped.some(x => x.id === 'INPV-01')); // injection not applicable in basic
  assert.match(c.disclaimer, /cannot prove the absence/i);
});
t('coverage rises as more categories are exercised', () => {
  const lo = computeCoverage({ mode: 'advanced', toolsUsed: ['reconx'] });
  const hi = computeCoverage({ mode: 'advanced', toolsUsed: ['reconx', 'xss', 'sqli', 'redirect', 'cors', 'nuclei', 'cve', 'ffuf', 'redteam', 'api'] });
  assert.ok(hi.coveragePct > lo.coveragePct);
});
t('never emits a security score / 100%-secure claim', () => {
  const c = computeCoverage({ mode: 'advanced', toolsUsed: ['reconx', 'xss'], findings: [] });
  assert.equal('securityScore' in c, false);
  assert.ok(!/100% secure|guaranteed secure/i.test(JSON.stringify(c)));
});
t('confidence High when findings carry evidence', () => {
  const findings = [
    { severity: 'high', tool: 'xss', title: 'Reflected XSS', evidence: { url: 'https://x/y?q=', payload: '..' } },
    { severity: 'medium', tool: 'headers', title: 'Missing HSTS', curl: 'curl -I https://x' },
  ];
  assert.match(computeCoverage({ mode: 'advanced', toolsUsed: ['xss', 'headers'], findings }).confidence, /High/);
});
t('confidence Low when evidence is mostly absent', () => {
  const findings = [
    { severity: 'high', tool: 'xss', title: 'Maybe XSS' },
    { severity: 'high', tool: 'sqli', title: 'Maybe SQLi' },
    { severity: 'medium', tool: 'x', title: 'z', evidence: { url: 'u' } },
  ];
  assert.equal(computeCoverage({ mode: 'advanced', toolsUsed: ['xss'], findings }).confidence, 'Low');
});
t('severity counts + posture', () => {
  const c = computeCoverage({ mode: 'advanced', toolsUsed: ['xss'], findings: [{ severity: 'critical', tool: 'x', title: 'a', evidence: { u: 1 } }] });
  assert.equal(c.severity.critical, 1);
  assert.match(c.posture, /immediate/i);
});
t('extraSkipped marks a category not-tested', () => {
  const c = computeCoverage({ mode: 'advanced', toolsUsed: ['xss'], extraSkipped: ['INPV-02'] });
  assert.ok(c.checksSkipped.some(x => x.id === 'INPV-02'));
});

console.log('\n# compare');
const prev = {
  coverage: { coveragePct: 60 },
  findings: [
    { id: 'f1', severity: 'high', tool: 'xss', title: 'Reflected XSS', evidence: { url: 'https://s/search' } },
    { id: 'f2', severity: 'medium', tool: 'headers', title: 'Missing HSTS', evidence: { url: 'https://s/' } },
    { id: 'f3', severity: 'low', tool: 'cors', title: 'Permissive CORS', evidence: { url: 'https://s/api' } },
  ],
};
const curr = {
  coverage: { coveragePct: 75 },
  findings: [
    { id: 'g1', severity: 'critical', tool: 'xss', title: 'Reflected XSS', evidence: { url: 'https://s/search' } }, // severity worse
    { id: 'g2', severity: 'medium', tool: 'headers', title: 'Missing HSTS', evidence: { url: 'https://s/' } },       // unchanged
    { id: 'g4', severity: 'high', tool: 'sqli', title: 'SQL injection', evidence: { url: 'https://s/item' } },       // new
  ],
};
t('diff classifies new / resolved / unchanged / severity change', () => {
  const d = diffScans(prev, curr);
  assert.equal(d.summary.new, 1);          // sqli
  assert.equal(d.summary.resolved, 1);     // cors
  assert.equal(d.summary.unchanged, 1);    // hsts
  assert.equal(d.summary.severityChanged, 1); // xss high->critical
  assert.equal(d.severityChanges[0].direction, 'worse');
  assert.equal(d.summary.coverageChange, 15);
});
t('identical scans => all unchanged', () => {
  const d = diffScans(prev, prev);
  assert.equal(d.summary.new, 0);
  assert.equal(d.summary.resolved, 0);
  assert.equal(d.summary.severityChanged, 0);
  assert.equal(d.summary.unchanged, prev.findings.length);
});
t('empty previous => everything new', () => {
  const d = diffScans({ findings: [] }, curr);
  assert.equal(d.summary.new, curr.findings.length);
  assert.equal(d.summary.resolved, 0);
});

console.log(`\n${fail ? 'FAILED' : 'PASSED'}: ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
