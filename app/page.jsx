"use client";
import { useState, useEffect, useRef, useCallback } from "react";
import ScanResult from "./_components/ScanResult";
import ScanCompare from "./_components/ScanCompare";
import EmailExposure from "./_components/EmailExposure";
import { historyTargetKey, loadBrowserHistory, migrateBrowserHistory, saveBrowserHistory } from "../lib/history-cookie";
import { isCurrentJobRequest, isTerminalJobStatus, normalizeJobStatus } from "../lib/job-status-ui";

const MODES = [
  { id: "basic", label: "Basic", desc: "Recon, dirs, headers, CORS, tech, secrets — non-intrusive" },
  { id: "advanced", label: "Advanced", desc: "Everything + XSS, SQLi, redirect, CVEs, real bypass attempts + remote browser", hot: true },
  { id: "custom", label: "Custom", desc: "Advanced + your own paths / instructions" },
  { id: "exposure", label: "Email Exposure", desc: "Check if your own email is in known breaches — ownership-verified, defensive" },
];
const SEV_COLOR = { critical: "#ff2b4e", high: "#ff7a1a", medium: "#eab308", low: "#38bdf8", info: "#8b8b8b" };

export default function Home() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("basic");
  const [instructions, setInstructions] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [job, setJob] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState("");
  const [share, setShare] = useState(null);
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState([]);
  const [compare, setCompare] = useState(null);
  const [comparing, setComparing] = useState(false);
  const pollRef = useRef(null);
  const activeJobRef = useRef(null);
  const jobGenerationRef = useRef(0);

  const stopPoll = () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } };

  const saveHistory = useCallback((list) => {
    const trimmed = saveBrowserHistory(list);
    setHistory(trimmed);
  }, []);
  const upsertHistory = useCallback((entry) => {
    const current = loadBrowserHistory();
    const list = current.filter((h) => h.jobId !== entry.jobId);
    const prev = current.find((h) => h.jobId === entry.jobId) || {};
    list.unshift({ ...prev, ...entry });
    saveHistory(list);
  }, [saveHistory]);

  const loadResult = useCallback(async (jobId, meta, generation = jobGenerationRef.current) => {
    const isCurrent = () => isCurrentJobRequest(jobId, generation, activeJobRef.current, jobGenerationRef.current);
    if (!isCurrent()) return;
    try {
      const r = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/result`, { cache: "no-store" });
      if (r.ok) {
        const data = await r.json();
        if (!isCurrent()) return;
        if (data.jobId && data.jobId !== jobId) throw new Error("The returned report does not match this scan.");
        setResult(data);
        upsertHistory({ jobId, target: data.target || data.finalTarget || meta?.target, mode: data.mode || meta?.mode,
          status: "completed", summary: data.summary || null, when: data.completedAt || Date.now() });
      } else if (isCurrent()) {
        setError("Scan finished, but its report could not be loaded. Select this scan from history to retry.");
      }
    } catch (e) { if (isCurrent()) setError(e.message || "Could not load the scan report."); }
  }, [upsertHistory]);

  const poll = useCallback((jobId) => {
    stopPoll();
    const generation = jobGenerationRef.current;
    const isCurrent = () => isCurrentJobRequest(jobId, generation, activeJobRef.current, jobGenerationRef.current);
    let inFlight = false;
    let failures = 0;
    const tick = async () => {
      if (!isCurrent() || inFlight) return;
      inFlight = true;
      try {
        const r = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, { cache: "no-store" });
        const j = await r.json().catch(() => ({}));
        if (!isCurrent()) return;
        if (!r.ok) {
          const message = j.error || `Status check failed (HTTP ${r.status})`;
          if (r.status >= 500 || r.status === 429) {
            failures += 1;
            setError(`Temporary status-check problem; retrying (${failures}). ${message}`);
            return;
          }
          setError(message);
          setJob((current) => current?.jobId === jobId ? { ...current, status: "failed", error: message } : current);
          upsertHistory({ jobId, target: j.target, mode: j.mode, status: "failed", when: Date.now() });
          stopPoll(); return;
        }
        failures = 0;
        setError("");
        setJob(j);
        const status = normalizeJobStatus(j.status);
        if (isTerminalJobStatus(status)) {
          stopPoll();
          if (status === "completed") await loadResult(jobId, j, generation);
          else {
            setError(`Scan ${status}: ${j.error || "no additional details were returned."}`);
            upsertHistory({ jobId, target: j.target, mode: j.mode, status, when: Date.now() });
          }
        }
      } catch (e) {
        if (isCurrent()) {
          failures += 1;
          setError(`Temporary status-check problem; retrying (${failures}). ${e.message || "Network error"}`);
        }
      } finally { inFlight = false; }
    };
    tick();
    pollRef.current = setInterval(tick, 3000);
  }, [loadResult, upsertHistory]);

  const resumeJob = useCallback((jid) => {
    stopPoll();
    const generation = ++jobGenerationRef.current;
    activeJobRef.current = jid;
    setBusy(true); setResult(null); setCompare(null); setShare(null); setError("");
    const u = new URL(window.location.href); u.searchParams.set("job", jid); window.history.replaceState({}, "", u);
    fetch(`/api/jobs/${encodeURIComponent(jid)}`, { cache: "no-store" }).then((r) => r.json()).then((j) => {
      if (!isCurrentJobRequest(jid, generation, activeJobRef.current, jobGenerationRef.current)) return;
      if (j && j.jobId) {
        setJob(j); setTarget(j.target || ""); setMode(j.mode || "basic");
        const status = normalizeJobStatus(j.status);
        if (status === "completed") loadResult(j.jobId, j, generation);
        else if (!isTerminalJobStatus(status)) poll(j.jobId);
        else setError(`This scan ${status}: ${j.error || "no additional details were returned."}`);
      } else if (generation === jobGenerationRef.current) {
        setError(j.error || "This scan could not be found.");
      }
    }).catch((e) => { if (generation === jobGenerationRef.current) setError(e.message || "Could not resume this scan."); })
      .finally(() => { if (generation === jobGenerationRef.current) setBusy(false); });
  }, [poll, loadResult]);

  useEffect(() => {
    setHistory(migrateBrowserHistory());
    const url = new URL(window.location.href);
    const jid = url.searchParams.get("job");
    if (jid) resumeJob(jid);
    return () => { jobGenerationRef.current += 1; activeJobRef.current = null; stopPoll(); };
  }, [resumeJob]);

  async function start() {
    if (!target.trim()) { setError("Enter a target URL"); return; }
    if (!authorized) { setError("Please confirm you are authorized to test this target."); return; }
    if (mode === "custom" && !instructions.trim()) { setError("Custom mode needs instructions"); return; }
    stopPoll();
    const generation = ++jobGenerationRef.current;
    activeJobRef.current = null;
    setBusy(true); setError(""); setResult(null); setJob(null); setShare(null); setCompare(null);
    try {
      const body = { target: target.trim(), mode, authorized: true, clientJobKey: `${target.trim()}|${mode}|${Date.now()}` };
      if (mode === "custom") body.params = { custom: instructions };
      const res = await fetch("/api/jobs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const j = await res.json();
      if (generation !== jobGenerationRef.current) return;
      if (!res.ok) throw new Error(j.error || `HTTP ${res.status}`);
      if (!j.jobId) throw new Error("The scanning service did not return a job ID.");
      activeJobRef.current = j.jobId;
      const u = new URL(window.location.href); u.searchParams.set("job", j.jobId); window.history.replaceState({}, "", u);
      setJob({ jobId: j.jobId, status: j.status || "queued", progress: 0 });
      upsertHistory({ jobId: j.jobId, target: target.trim(), mode, status: j.status || "queued", when: Date.now() });
      poll(j.jobId);
    } catch (e) { if (generation === jobGenerationRef.current) setError(e.message || "Could not start scan"); }
    finally { if (generation === jobGenerationRef.current) setBusy(false); }
  }

  function reset() {
    stopPoll(); jobGenerationRef.current += 1; activeJobRef.current = null;
    setJob(null); setResult(null); setError(""); setShare(null); setCompare(null); setAuthorized(false); setBusy(false);
    const u = new URL(window.location.href); u.searchParams.delete("job"); window.history.replaceState({}, "", u);
  }

  async function makeShare() {
    if (!job?.jobId) return;
    try {
      const res = await fetch("/api/share", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jobId: job.jobId }) });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || "share failed");
      const full = window.location.origin + j.url;
      setShare({ url: full, expiresAt: j.expiresAt });
      try { await navigator.clipboard.writeText(full); } catch {}
    } catch (e) { setError(e.message); }
  }

  async function compareWithPrevious() {
    if (!job?.jobId || !result) return;
    const tgt = result.target || result.finalTarget;
    const targetKey = historyTargetKey(tgt);
    const prior = loadBrowserHistory().find((h) => h.jobId !== job.jobId && h.status === "completed" && h.targetKey === targetKey);
    if (!prior) { setError("No previous completed scan of this target in your history to compare against."); return; }
    setComparing(true); setError(""); setCompare(null);
    try {
      const r = await fetch(`/api/compare?a=${encodeURIComponent(prior.jobId)}&b=${encodeURIComponent(job.jobId)}`, { cache: "no-store" });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "compare failed");
      setCompare(d);
    } catch (e) { setError(e.message); }
    finally { setComparing(false); }
  }

  async function downloadReport(fmt) {
    if (!result || downloading) return;
    setDownloading(fmt); setError("");
    try {
      let blob, ext = fmt;
      if (fmt === "json") blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
      else {
        const res = await fetch("/api/report?format=" + fmt, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(result) });
        if (!res.ok) { let m = "HTTP " + res.status; try { const j = await res.json(); if (j.error) m = j.error; } catch {} throw new Error(m); }
        blob = await res.blob();
      }
      const host = (result.finalTarget || result.target || "scan").replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]/gi, "");
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "bigbounty-" + host + "-" + new Date().toISOString().slice(0, 10) + "." + ext;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
    } catch (e) { setError("Report download failed: " + (e.message || e)); }
    finally { setDownloading(""); }
  }

  const scanning = job && !isTerminalJobStatus(job.status);
  const resultTargetKey = result && historyTargetKey(result.target || result.finalTarget);
  const priorExists = result && history.some((h) => h.jobId !== job?.jobId && h.status === "completed" && h.targetKey === resultTargetKey);

  return (
    <div className="bb-root">
      <style>{`
        * { box-sizing: border-box; }
        .bb-root { min-height: 100vh; background: #0a0e14; color: #d7dce3; font-family: ui-monospace, Menlo, monospace; padding: 16px; }
        .bb-wrap { max-width: 860px; margin: 0 auto; }
        .bb-panel { border: 1px solid #1f2733; border-radius: 10px; padding: 16px; background: #0d1219; }
        .bb-btn { border: 0; border-radius: 8px; padding: 10px 22px; font-size: 14px; font-weight: 700; cursor: pointer; min-height: 44px; }
        .bb-mode { background: transparent; border: 1px solid #2a3441; color: #7d8590; border-radius: 8px; padding: 8px 14px; font-size: 12px; cursor: pointer; text-align: left; flex: 1 1 220px; min-height: 44px; }
        .bb-dl { display: flex; flex-direction: column; gap: 8px; width: 100%; }
        .bb-dl-btn { display: flex; align-items: center; justify-content: center; gap: 8px; background: #111a26; color: #58a6ff; border: 1px solid #1f6feb; border-radius: 8px; padding: 12px; cursor: pointer; font-size: 13px; font-weight: 600; min-height: 46px; width: 100%; }
        .bb-dl-btn:disabled { opacity: 0.5; cursor: wait; }
        .bb-finding { border-radius: 8px; padding: 12px; background: #0d1219; }
        .bb-pre { background: #0a0e14; border: 1px solid #1f2733; border-radius: 6px; padding: 10px; font-size: 11px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
        .bb-bar { height: 8px; background: #0a0e14; border: 1px solid #1f2733; border-radius: 6px; overflow: hidden; }
        .bb-bar > div { height: 100%; background: linear-gradient(90deg,#16a34a,#58a6ff); transition: width .4s; }
        .bb-hrow { display:flex; gap:10px; align-items:center; flex-wrap:wrap; padding:8px 0; border-bottom:1px solid #141a22; font-size:12px; }
        .bb-foot { text-align: center; color: #7d8590; font-size: 12px; padding: 26px 0 10px; }
        .bb-foot .heart { color: #ff2b4e; }
        @media (min-width: 640px) { .bb-root { padding: 24px; } .bb-dl { flex-direction: row; } .bb-dl-btn { width: auto; flex: 1; padding: 10px 14px; } }
        @media (max-width: 480px) { .bb-root { padding: 10px; } .bb-panel { padding: 12px; } .bb-wrap h1 { font-size: 24px !important; } .bb-frow { flex-direction: column !important; align-items: flex-start !important; gap: 6px !important; } }
      `}</style>
      <div className="bb-wrap">
        <header style={{ marginBottom: 24 }}>
          <h1 style={{ fontSize: 30, margin: 0, color: "#ff2b4e", letterSpacing: 2 }}>⚔ BIG BOUNTY</h1>
          <p style={{ color: "#7d8590", fontSize: 13, margin: "8px 0 0", lineHeight: 1.5 }}>
            Real-evidence security testing. Enter a URL, confirm you&apos;re authorized, and press Start — the scan runs
            on dedicated infrastructure, survives refreshes, and you can share or download the report. Only test targets you own or are authorized to assess.
          </p>
        </header>

        <section className="bb-panel">
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {MODES.map((m) => (
              <button key={m.id} onClick={() => !scanning && setMode(m.id)} className="bb-mode"
                style={{ background: mode === m.id ? (m.hot ? "rgba(255,43,78,.12)" : "rgba(22,163,74,.12)") : "transparent",
                  borderColor: mode === m.id ? (m.hot ? "#ff2b4e" : "#16a34a") : "#2a3441",
                  color: mode === m.id ? (m.hot ? "#ff2b4e" : "#16a34a") : "#7d8590" }}>
                <b>{m.label}</b> — {m.desc}
              </button>
            ))}
          </div>

          {mode !== "exposure" && (
            <>
              <label style={{ display: "block", fontSize: 12, color: "#7d8590", margin: "14px 0 6px" }}>TARGET URL</label>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <input
                  value={target} onChange={(e) => setTarget(e.target.value)} disabled={scanning}
                  onKeyDown={(e) => e.key === "Enter" && !scanning && authorized && start()}
                  placeholder="https://your-site.com"
                  inputMode="url" autoCapitalize="none" autoCorrect="off" spellCheck={false}
                  style={{ flex: 1, minWidth: 200, background: "#0a0e14", border: "1px solid #2a3441", borderRadius: 8, padding: "10px 12px", color: "#d7dce3", fontSize: 16, minHeight: 44 }}
                />
                <button onClick={scanning ? undefined : start} disabled={scanning || busy || !authorized} className="bb-btn"
                  style={{ background: (scanning || !authorized) ? "#1f2733" : "#16a34a", color: "#fff", cursor: scanning ? "wait" : (!authorized ? "not-allowed" : "pointer") }}>
                  {scanning ? `SCANNING… ${job.progress || 0}%` : busy ? "…" : "START SCAN"}
                </button>
              </div>

              {mode === "custom" && (
                <textarea value={instructions} onChange={(e) => setInstructions(e.target.value)} disabled={scanning}
                  placeholder={"e.g. focus on /api/v1, test the session cookie, check the login at /auth/login"}
                  rows={3} style={{ width: "100%", marginTop: 10, background: "#0a0e14", border: "1px solid #2a3441", borderRadius: 8, padding: 10, color: "#d7dce3", fontSize: 13 }} />
              )}

              <label style={{ display: "flex", gap: 10, alignItems: "flex-start", marginTop: 14, cursor: "pointer", fontSize: 13, color: "#d7dce3" }}>
                <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} disabled={scanning}
                  style={{ width: 18, height: 18, marginTop: 1, accentColor: "#16a34a", flexShrink: 0 }} />
                <span>I confirm that I am authorized to test this target.</span>
              </label>
            </>
          )}
        </section>

        {mode === "exposure" && <EmailExposure />}

        {mode !== "exposure" && error && (
          <div style={{ marginTop: 16, border: "1px solid #ff2b4e", borderRadius: 8, padding: 14, color: "#ff2b4e", fontSize: 13, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>✗ {error}</div>
        )}

        {mode !== "exposure" && scanning && (
          <div style={{ marginTop: 16, border: "1px solid #1f2733", borderRadius: 8, padding: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "#7d8590", marginBottom: 8 }}>
              <span>{job.status === "queued" ? "Queued — starting worker…" : `Running · ${job.stage || "…"}`}</span>
              <span>{job.progress || 0}%</span>
            </div>
            <div className="bb-bar"><div style={{ width: `${Math.max(5, job.progress || 0)}%` }} /></div>
            <div style={{ fontSize: 11, color: "#6b7580", marginTop: 8 }}>You can close this page — the scan keeps running. Return any time; it reloads automatically.</div>
          </div>
        )}

        {mode !== "exposure" && (result || (job && !scanning)) && (
          <>
            <div style={{ marginTop: 16, display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button className="bb-btn" onClick={makeShare} style={{ background: "#1f6feb", color: "#fff" }}>🔗 Share report link</button>
              {result && priorExists && (
                <button className="bb-btn" onClick={compareWithPrevious} disabled={comparing} style={{ background: "#24303f", color: "#58a6ff" }}>
                  {comparing ? "comparing…" : "↕ Compare with previous"}
                </button>
              )}
              <button className="bb-btn" onClick={reset} style={{ background: "#1f2733", color: "#d7dce3" }}>New scan</button>
            </div>
            {share && (
              <div className="bb-panel" style={{ marginTop: 10, borderColor: "#1f6feb" }}>
                <div style={{ fontSize: 12, color: "#58a6ff", marginBottom: 6 }}>Shareable link (copied) — expires {new Date(share.expiresAt).toLocaleString()}</div>
                <div className="bb-pre" style={{ color: "#c9d1d9" }}>{share.url}</div>
              </div>
            )}
          </>
        )}

        {mode !== "exposure" && compare && <ScanCompare data={compare} />}
        {mode !== "exposure" && result && <ScanResult result={result} />}

        {mode !== "exposure" && result && (
          <div className="bb-panel" style={{ marginTop: 16 }}>
            <div style={{ fontSize: 12, color: "#7d8590", marginBottom: 10 }}>DOWNLOAD CLIENT REPORT</div>
            <div className="bb-dl">
              {[["pdf", "⬇ PDF Report"], ["md", "⬇ Markdown"], ["html", "⬇ HTML"], ["json", "⬇ JSON"]].map(([fmt, label]) => (
                <button key={fmt} className="bb-dl-btn" onClick={() => downloadReport(fmt)} disabled={!!downloading}>
                  {downloading === fmt ? "generating…" : label}
                </button>
              ))}
            </div>
          </div>
        )}

        {mode !== "exposure" && history.length > 0 && (
          <div className="bb-panel" style={{ marginTop: 18 }}>
            <div style={{ fontSize: 12, color: "#7d8590", marginBottom: 6 }}>SCAN HISTORY (this browser)</div>
            {history.map((h) => (
              <div key={h.jobId} className="bb-hrow">
                <button onClick={() => resumeJob(h.jobId)} style={{ background: "none", border: 0, color: "#58a6ff", cursor: "pointer", padding: 0, fontSize: 12, textAlign: "left", flex: 1, minWidth: 160, wordBreak: "break-all" }}>
                  {h.target || h.jobId}
                </button>
                <span style={{ color: "#6b7580" }}>{h.mode}</span>
                <span style={{ color: h.status === "completed" ? "#16a34a" : h.status === "failed" ? "#ff2b4e" : "#eab308" }}>{h.status}</span>
                {h.summary && (
                  <span style={{ display: "flex", gap: 6 }}>
                    {["critical", "high", "medium", "low"].map((s) => (h.summary[s] ? <span key={s} style={{ color: SEV_COLOR[s] }}>{s[0].toUpperCase()}{h.summary[s]}</span> : null))}
                  </span>
                )}
                <span style={{ color: "#6b7580" }}>{h.when ? new Date(h.when).toLocaleDateString() : ""}</span>
              </div>
            ))}
          </div>
        )}

        <footer className="bb-foot">
          Developed with <span className="heart">♥</span> by <b style={{ color: "#d7dce3" }}>Saqib Sarwar</b>
        </footer>
      </div>
    </div>
  );
}
