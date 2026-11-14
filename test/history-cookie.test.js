'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('../lib/history-cookie');

function entry(n, when = n) {
  return { jobId: `job-${n}`, target: `https://site${n}.example/path?token=secret${n}`, mode: 'basic', status: 'completed', when, summary: { high: n, info: 0 } };
}

test('history cookie round-trips compact records without putting query secrets in the value', () => {
  const list = H.limitHistory([entry(1)]);
  const cookie = H.buildHistoryCookie(list, true);
  assert.match(cookie, /^bb_history_v1=/);
  assert.match(cookie, /Path=\/; Max-Age=31536000; SameSite=Lax; Secure$/);
  assert.doesNotMatch(decodeURIComponent(cookie.split(';', 1)[0].split('=').slice(1).join('=')), /secret1/);
  assert.deepEqual(H.parseHistoryCookie(`${cookie.split(';', 1)[0]}; other=value`), list);
  assert.match(list[0].target, /^https:\/\/site1\.example\/path$/);
  assert.equal(list[0].targetKey, H.historyTargetKey(entry(1).target));
});

test('only the five newest unique entries are retained', () => {
  const values = Array.from({ length: 8 }, (_, i) => entry(i + 1));
  values.push({ ...entry(8), target: 'https://newer.example/', when: 99 });
  const result = H.limitHistory(values);
  assert.equal(result.length, H.MAX_HISTORY);
  assert.deepEqual(result.map((x) => x.jobId), ['job-8', 'job-7', 'job-6', 'job-5', 'job-4']);
  assert.equal(result[0].target, 'https://newer.example/');
});

test('malformed cookie, malformed JSON, and invalid job IDs are safely ignored', () => {
  assert.deepEqual(H.parseHistoryCookie('bb_history_v1=%E0%A4%A'), []);
  assert.deepEqual(H.parseHistoryCookie('bb_history_v1=not-json'), []);
  assert.deepEqual(H.limitHistory([{ ...entry(1), jobId: '../unsafe' }, null]), []);
});

test('legacy localStorage history migrates into the cookie index with a strict size cap', () => {
  const old = Array.from({ length: 25 }, (_, i) => entry(i + 1));
  const migrated = H.migrateHistory('', JSON.stringify(old));
  assert.equal(migrated.length, 5);
  assert.deepEqual(migrated.map((x) => x.jobId), ['job-25', 'job-24', 'job-23', 'job-22', 'job-21']);
  const cookie = H.buildHistoryCookie(migrated);
  const value = cookie.split(';', 1)[0].slice('bb_history_v1='.length);
  assert.ok(value.length <= H.MAX_COOKIE_VALUE_LENGTH);
});

test('different query-bearing scan targets have distinct comparison keys without exposing queries', () => {
  const one = 'https://example.test/search?q=one';
  const two = 'https://example.test/search?q=two';
  assert.notEqual(H.historyTargetKey(one), H.historyTargetKey(two));
  const cookie = H.buildHistoryCookie(H.limitHistory([{ ...entry(1), target: one }]));
  assert.doesNotMatch(decodeURIComponent(cookie.split(';', 1)[0]), /q=one/);
});
