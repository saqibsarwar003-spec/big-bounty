'use strict';
// Scope/SSRF guard + secret-redaction tests. Run: node --test test/safety.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const scope = require('../lib/scope');
const redact = require('../lib/redact');

// ---------------------------------------------------------------------------
test('scope guard allows public targets', () => {
  const a = scope.assessTarget('https://example.com/path');
  assert.equal(a.ok, true);
  assert.equal(a.hostname, 'example.com');
  assert.equal(a.manifest.root, 'example.com');
  assert.equal(scope.assessTarget('big-bounty.vercel.app').ok, true);
});

test('scope guard blocks loopback / private / metadata / link-local', () => {
  for (const t of ['http://localhost', 'http://127.0.0.1', 'http://10.0.0.5',
                   'http://192.168.1.1', 'http://172.16.0.1', 'http://169.254.169.254',
                   'http://[::1]', 'http://intranet.local', 'http://svc.internal']) {
    assert.equal(scope.assessTarget(t).ok, false, `${t} must be refused`);
  }
});

test('scope guard blocks dangerous schemes and bare hosts', () => {
  assert.equal(scope.assessTarget('file:///etc/passwd').ok, false);
  assert.equal(scope.assessTarget('gopher://x/_').ok, false);
  assert.equal(scope.assessTarget('dict://127.0.0.1:11211/').ok, false);
  assert.equal(scope.assessTarget('bareword').ok, false);     // single-label
  assert.equal(scope.assessTarget('').ok, false);
});

test('inScope distinguishes first-party subdomains from third parties', () => {
  const m = scope.scopeManifest('example.com');
  assert.equal(scope.inScope('api.example.com', m), true);
  assert.equal(scope.inScope('example.com', m), true);
  assert.equal(scope.inScope('google.com', m), false);
  assert.equal(scope.inScope('example.com.evil.net', m), false);
});

// ---------------------------------------------------------------------------
test('redaction scrubs JWTs, bearer tokens, API keys', () => {
  assert.match(redact.redactString('token eyJhbGciOiJ.abc123def.sig456xyz here'), /REDACTED_JWT/);
  assert.match(redact.redactString('Authorization: Bearer sk-ABCDEFGHIJKLMNOPQRST'), /REDACTED/);
  assert.match(redact.redactString('key nvapi-abcdefghijklmnopqrstuvwx'), /REDACTED_KEY/);
  assert.match(redact.redactString('gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), /REDACTED_TOKEN/);
});

test('redaction masks sensitive evidence keys and curl, keeps prose intact', () => {
  const f = {
    tool: 'attacks', severity: 'high', title: 'Session cookie issue',
    evidence: { cookiePreview: 'SESSIONID=abcdef123456; Path=/', note: 'the quick brown fox' },
    curl: "curl -H 'Cookie: SESSIONID=abcdef123456' https://t/",
  };
  const r = redact.redactFinding(f);
  assert.equal(r.evidence.cookiePreview, '[REDACTED]');
  assert.equal(r.evidence.note, 'the quick brown fox');   // ordinary text untouched
  assert.match(r.curl, /\[REDACTED\]/);
  assert.ok(!/abcdef123456/.test(JSON.stringify(r)), 'raw secret must not survive anywhere');
});

test('redaction is safe on malformed / empty input', () => {
  assert.doesNotThrow(() => redact.redactFinding(null));
  assert.doesNotThrow(() => redact.redactFinding({}));
  assert.equal(redact.redactString(42), 42);
});
