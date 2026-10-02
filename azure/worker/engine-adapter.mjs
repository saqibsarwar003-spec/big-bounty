// Thin adapter around the EXISTING Big Bounty engine.
//
// Per project direction we do NOT reimplement or fork the engine (attacks.js,
// redteam.js, scanner.js, the fuzzers, nuclei, browserbot, …). We invoke its
// real programmatic entry point — runScan(target, mode, custom, { onPhase }) —
// exported by ../../lib/scanner.js, and translate its phase events + result
// into the shape the worker persists.

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER_PATH = path.resolve(HERE, '../../lib/scanner.js');

let _scanner = null;
function scanner() {
  if (!_scanner) _scanner = require(SCANNER_PATH); // lazy so import errors surface at run time with context
  return _scanner;
}

// Coarse progress map so the UI has a meaningful bar. Unknown phases nudge
// progress forward without overshooting 95% (100% is set only on completion).
const PHASE_PROGRESS = {
  fetch: 8, recon: 15, subdomains: 22, dirs: 30, exposure: 34, headers: 38,
  cors: 42, tech: 46, secrets: 50, xss: 56, sqli: 60, redirect: 63, cves: 66,
  nuclei: 72, reconx: 75, redteam: 79, 'advanced-pack': 82, attacks: 85,
  intruder: 87, ffuf: 89, kiterunner: 90, 'zap-fuzzer': 91, 'burp-repeater': 92,
  'endpoint-discovery-audit': 93, 'browser-bypass': 94, 'ai-triage': 96,
};

/**
 * Run the existing engine.
 * @param {object} job   { target, mode, custom, domain }
 * @param {(u:{progress:number,stage:string})=>void} onProgress throttled by caller
 * @param {number} timeoutMs hard ceiling; rejects with Error('engine timeout')
 */
export async function runEngine(job, onProgress, timeoutMs) {
  const { runScan } = scanner();
  let maxProgress = 5;

  const onPhase = (p) => {
    if (!p || !p.phase) return;
    const base = PHASE_PROGRESS[p.phase];
    if (typeof base === 'number' && base > maxProgress) maxProgress = Math.min(base, 95);
    try { onProgress?.({ progress: maxProgress, stage: `${p.phase}${p.status ? ':' + p.status : ''}` }); } catch {}
  };

  const run = Promise.resolve().then(() => runScan(job.target, job.mode, job.custom ?? null, { onPhase }));
  let timer;
  const timeout = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('engine timeout')), timeoutMs); });
  try {
    const result = await Promise.race([run, timeout]);
    return result;
  } finally {
    clearTimeout(timer);
  }
}
