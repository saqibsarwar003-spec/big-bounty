'use strict';
/**
 * Verification-layer tests, calibrated against the real Big Bounty report for
 * saqibsarwar.net (1 critical XXE + 4 high zap-fuzzer, all actually WAF/Vercel
 * challenge pages; 39 low endpoint-discovery 403s). Run: node --test test/verify.test.js
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const V = require('../lib/verify');

// Representative Vercel Security Checkpoint body (the kind the real report captured).
const VERCEL_CHALLENGE = 'Vercel Security Checkpoint — Authentication Required. Please enable JavaScript. _vercel/sso-api challenge token …';
const CLOUDFLARE_CHALLENGE = '<!DOCTYPE html><title>Just a moment...</title> Checking your browser before accessing. cf-ray: 8ab… __cf_chl';
const NORMAL_PAGE = '<!doctype html><html><head><title>My App</title></head><body><h1>Welcome</h1><p>Dashboard</p></body></html>';

// ---------------------------------------------------------------------------
test('fingerprintResponse flags vendor challenge pages, not normal pages', () => {
  assert.equal(V.fingerprintResponse({ status: 403, body: VERCEL_CHALLENGE }).isChallenge, true);
  assert.equal(V.fingerprintResponse({ status: 403, body: VERCEL_CHALLENGE }).vendor, 'Vercel');
  assert.equal(V.fingerprintResponse({ status: 503, body: CLOUDFLARE_CHALLENGE }).isChallenge, true);
  assert.equal(V.fingerprintResponse({ status: 200, body: NORMAL_PAGE }).isChallenge, false);
  // header-based cloudflare
  assert.equal(V.fingerprintResponse({ status: 403, headers: { 'cf-ray': 'abc' }, body: '' }).isChallenge, true);
});

// ---------------------------------------------------------------------------
test('zap-fuzzer null-byte finding on a Vercel 403 is rejected, not HIGH', () => {
  const finding = {
    tool: 'zap-fuzzer', severity: 'high',
    title: "OWASP ZAP Fuzzer: Vulnerability Triggered via [Null Byte Injection] on parameter 'q'",
    evidence: { statusCode: 403, payload: '%00', matchSnippet: VERCEL_CHALLENGE },
  };
  const c = V.classifyFinding(finding, { rootFingerprint: { isChallenge: true, vendor: 'Vercel' }, wafPresent: true, wafVendor: 'Vercel' });
  assert.equal(c.severity, 'info');
  assert.equal(c.status, V.STATUS.BLOCKED);
  assert.equal(c.confidence, V.CONFIDENCE.REJECTED);
  assert.equal(c.originalSeverity, 'high');
  assert.match(c.whyClassified, /Vercel/);
});

// ---------------------------------------------------------------------------
test('XXE with no verified file-read content is down-ranked to manual-verify', () => {
  const finding = {
    tool: 'xxe', severity: 'critical', title: 'XXE: external entity resolved (file read)',
    evidence: { match: 'some ordinary words from the page body that matched the broad regex' },
  };
  const c = V.classifyFinding(finding, { rootFingerprint: { isChallenge: false }, wafPresent: false });
  assert.equal(c.status, V.STATUS.MANUAL);
  assert.equal(c.confidence, V.CONFIDENCE.POSSIBLE);
  assert.notEqual(c.severity, 'critical');
});

test('XXE WITH real /etc/passwd content stays critical', () => {
  const finding = {
    tool: 'xxe', severity: 'critical', title: 'XXE: external entity resolved (file read)',
    evidence: { match: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:' },
  };
  const c = V.classifyFinding(finding, { rootFingerprint: { isChallenge: false }, wafPresent: false });
  assert.equal(c.severity, 'critical');
  assert.equal(c.status, V.STATUS.SUSPECTED);
});

// ---------------------------------------------------------------------------
test('a genuine SQL-error finding (200, no WAF) is kept as a strong lead', () => {
  const finding = {
    tool: 'sqli', severity: 'high', title: 'Database error signatures returned',
    evidence: { statusCode: 200, matchSnippet: "You have an error in your SQL syntax near '1''" },
  };
  const c = V.classifyFinding(finding, { rootFingerprint: { isChallenge: false }, wafPresent: false });
  assert.notEqual(c.severity, 'info');
  assert.equal(c.status, V.STATUS.SUSPECTED);
});

// ---------------------------------------------------------------------------
test('observed config facts (missing CSP) keep severity with high confidence', () => {
  const c = V.classifyFinding({ tool: 'headers', severity: 'medium', title: 'Missing content-security-policy' }, {});
  assert.equal(c.severity, 'medium');
  assert.equal(c.status, V.STATUS.OBSERVED);
  assert.equal(c.confidence, V.CONFIDENCE.HIGH);
});

// ---------------------------------------------------------------------------
test('endpoint-discovery 403s collapse into one attack-surface finding', () => {
  const findings = [];
  for (let i = 0; i < 39; i++) {
    findings.push({ tool: 'kiterunner', severity: 'low', title: `Kiterunner: Discovered API Endpoint /api/x${i} (HTTP 403)`, evidence: { statusCode: 403 }, url: `https://t/api/x${i}` });
  }
  const classified = findings.map((f) => V.classifyFinding(f, { rootFingerprint: { isChallenge: true, vendor: 'Vercel' }, wafPresent: true }));
  const out = V.correlateFindings(classified);
  const surface = out.filter((f) => f.tool === 'attack-surface');
  assert.equal(surface.length, 1);
  assert.equal(surface[0].evidence.blocked, 39);
  assert.ok(out.length < 5, 'should collapse 39 findings to a handful');
});

// ---------------------------------------------------------------------------
test('END TO END: the saqibsarwar.net report shape loses its false crit/highs', () => {
  const findings = [
    { tool: 'waf', severity: 'info', title: 'Edge/WAF detected: Vercel', evidence: { detection: 'Vercel' } },
    { tool: 'xxe', severity: 'critical', title: 'XXE: external entity resolved (file read)', evidence: { match: 'challenge page words here' } },
    { tool: 'zap-fuzzer', severity: 'high', title: "Null Byte Injection on 'q'", evidence: { statusCode: 403, matchSnippet: VERCEL_CHALLENGE } },
    { tool: 'zap-fuzzer', severity: 'high', title: "Buffer Overflow Probe on 'q'", evidence: { statusCode: 403, matchSnippet: VERCEL_CHALLENGE } },
    { tool: 'zap-fuzzer', severity: 'high', title: "Null Byte Injection on 'id'", evidence: { statusCode: 403, matchSnippet: VERCEL_CHALLENGE } },
    { tool: 'zap-fuzzer', severity: 'high', title: "Buffer Overflow Probe on 'id'", evidence: { statusCode: 403, matchSnippet: VERCEL_CHALLENGE } },
    { tool: 'headers', severity: 'medium', title: 'Weak CSP (unsafe-inline / unsafe-eval)' },
    { tool: 'cors', severity: 'low', title: 'CORS allows all origins (ACAO: *)' },
  ];
  // add 39 blocked endpoint-discovery findings
  for (let i = 0; i < 39; i++) findings.push({ tool: 'kiterunner', severity: 'low', title: `Discovered API Endpoint /api/x${i} (HTTP 403)`, evidence: { statusCode: 403 }, url: `https://saqibsarwar.net/api/x${i}` });

  const phases = [{ phase: 'recon', status: 'ok' }, { phase: 'xxe', status: 'ok' }, { phase: 'zap-fuzzer', status: 'ok' }, { phase: 'headers', status: 'ok' }];
  const result = V.runVerification(
    { findings, phases },
    { mainResponse: { status: 403, headers: { server: 'Vercel' }, body: VERCEL_CHALLENGE } }
  );

  // The headline false positives are gone.
  assert.equal(result.summary.critical, 0, 'XXE false-crit removed');
  assert.equal(result.summary.high, 0, 'all 4 WAF-challenge highs removed');
  // Real config findings survive.
  assert.equal(result.summary.medium, 1, 'weak CSP kept');
  // 39 endpoint findings collapsed.
  assert.ok(result.findings.length < 12, `collapsed noisy findings (got ${result.findings.length})`);
  // Verification metadata present.
  assert.equal(result.verification.wafPresent, true);
  assert.equal(result.verification.wafVendor, 'Vercel');
  assert.ok(result.verification.falsePositivesRejected >= 4, '4 WAF-challenge highs rejected');
  assert.ok(result.verification.reclassified >= 5, 'XXE + 4 highs (+ discovery) reclassified');
  // Structured coverage present.
  assert.equal(result.coverageModel.model, 'structured');
  assert.ok(result.coverageModel.credentialDependentNotRun > 0);
});

test('runVerification never throws on empty / malformed input', () => {
  assert.doesNotThrow(() => V.runVerification({}, {}));
  assert.doesNotThrow(() => V.runVerification({ findings: [{}, { tool: null }] }, {}));
});
