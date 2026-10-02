"use client";
import { useState, useEffect, useRef, useCallback } from "react";
import ScanResult from "./_components/ScanResult";

const MODES = [
  { id: "basic", label: "Basic", desc: "Recon, dirs, headers, CORS, tech, secrets — non-intrusive" },
  { id: "advanced", label: "Advanced", desc: "Everything + XSS, SQLi, redirect, CVEs, real bypass attempts + remote browser", hot: true },
  { id: "custom", label: "Custom", desc: "Advanced + your own paths / instructions" },
];

const RUNNING = new Set(["queued", "running", "dispatched"]);

export default function Home() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("basic");
  const [instructions, setInstructions] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [job, setJob] = useState(null);        // {jobId,status,progress,stage,findingsSummary,coverage,error}
  const [result, setResult] = useState(null);   // full result once completed
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState("");
  const [share, setShare] = useState(null);     // {url, expiresAt}
  const [busy, setBusy] = useState(false);
  const pollRef = useRef(null);

  const stopPoll = () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } };

  const loadResult = useCallback(async (jobId) => {
    try {
      const r = await fetch(`/api/jobs/${jobId}/result`, { cache: "no-store" });
      if (r.ok) setResult(await r.json());
    } catch {}
  }, []);

  const poll = useCallback((jobId) => {
    stopPoll();
    const tick = async () => {
      try {
        const r = await fetch(`/api/jobs/${jobId}`, { cache: "no-store" });
        const j = await r.json();
        if (!r.ok) { setError(j.error || "status check failed"); stopPoll(); return; }
        setJob(j);
        if (!RUNNING.has(j.status)) {
          stopPoll();
          if (j.status === "completed") await loadResult(jobId);
          else if (j.status === "failed") setError("Scan failed: " + (j.error || "unknown error"));
        }
      } catch (e) { /* transient; keep polling */ }
    };
    tick();
    pollRef.current = setInterval(tick, 3000);
  }, [loadResult]);

  // Refresh / return recovery: resume the job from the URL (?job=) or localStorage.
  useEffect(() => {
    const url = new URL(window.location.href);
    let jid = url.searchParams.get("job");
    if (!jid) { try { jid = localStorage.getItem("bb_job"); } catch {} }
    if (jid) {
      setBusy(true);
      fetch(`/api/jobs/${jid}`, { cache: "no-store" }).then(r => r.json()).then(j => {
        if (j && j.jobId) {
          setJob(j); setTarget(j.target || ""); setMode(j.mode || "basic");
          if (j.status === "completed") loadResult(j.jobId);
          else if (RUNNING.has(j.status)) poll(j.jobId);
          else if (j.status === "failed") setError("Previous scan failed: " + (j.error || ""));
        }
      }).catch(() => {}).finally(() => setBusy(false));
    }
    return stopPoll;
  }, [poll, loadResult]);

  async function start() {
    if (!target.trim()) { setError("Enter a target URL"); return; }
    if (!authorized) { setError("Please confirm you are authorized to test this target."); return; }
    if (mode === "custom" && !instructions.trim()) { setError("Custom mode needs instructions"); return; }
    setBusy(true); setError(""); setResult(null); setJob(null); setShare(null);
    try {
      const body = { target: target.trim(), mode, authorized: true, clientJobKey: `${target.trim()}|${mode}|${Date.now()}` };
      if (mode === "custom") body.params = { custom: instructions };
      const res = await fetch("/api/jobs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || `HTTP ${res.status}`);
      try { localStorage.setItem("bb_job", j.jobId); } catch {}
      const u = new URL(window.location.href); u.searchParams.set("job", j.jobId); window.history.replaceState({}, "", u);
      setJob({ jobId: j.jobId, status: j.status || "queued", progress: 0 });
      poll(j.jobId);
    } catch (e) {
      setError(e.message || "Could not start scan");
    } finally { setBusy(false); }
  }

  function reset() {
    stopPoll(); setJob(null); setResult(null); setError(""); setShare(null);
    try { localStorage.removeItem("bb_job"); } catch {}
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

  const scanning = job && RUNNING.has(job.status);

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
          <label style={{ display: "block", fontSize: 12, color: "#7d8590", marginBottom: 6 }}>TARGET URL</label>
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
              {scanning ? `SCANNING… ${job.progress || 0}%` : busy ? "…" : "START"}
            </button>
          </div>

          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
            {MODES.map((m) => (
              <button key={m.id} onClick={() => !scanning && setMode(m.id)} className="bb-mode"
                style={{ background: mode === m.id ? (m.hot ? "rgba(255,43,78,.12)" : "rgba(22,163,74,.12)") : "transparent",
                  borderColor: mode === m.id ? (m.hot ? "#ff2b4e" : "#16a34a") : "#2a3441",
                  color: mode === m.id ? (m.hot ? "#ff2b4e" : "#16a34a") : "#7d8590" }}>
                <b>{m.label}</b> — {m.desc}
              </button>
            ))}
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
        </section>

        {error && (
          <div style={{ marginTop: 16, border: "1px solid #ff2b4e", borderRadius: 8, padding: 14, color: "#ff2b4e", fontSize: 13, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
            ✗ {error}
          </div>
        )}

        {scanning && (
          <div style={{ marginTop: 16, border: "1px solid #1f2733", borderRadius: 8, padding: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "#7d8590", marginBottom: 8 }}>
              <span>{job.status === "queued" ? "Queued — starting worker…" : `Running · ${job.stage || "…"}`}</span>
              <span>{job.progress || 0}%</span>
            </div>
            <div className="bb-bar"><div style={{ width: `${Math.max(5, job.progress || 0)}%` }} /></div>
            <div style={{ fontSize: 11, color: "#6b7580", marginTop: 8 }}>You can close this page — the scan keeps running. Return any time; it will reload automatically.</div>
          </div>
        )}

        {(result || (job && !scanning)) && (
          <>
            <div style={{ marginTop: 16, display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button className="bb-btn" onClick={makeShare} style={{ background: "#1f6feb", color: "#fff" }}>🔗 Share report link</button>
              <button className="bb-btn" onClick={reset} style={{ background: "#1f2733", color: "#d7dce3" }}>New scan</button>
            </div>
            {share && (
              <div className="bb-panel" style={{ marginTop: 10, borderColor: "#1f6feb" }}>
                <div style={{ fontSize: 12, color: "#58a6ff", marginBottom: 6 }}>Shareable link (copied to clipboard) — expires {new Date(share.expiresAt).toLocaleString()}</div>
                <div className="bb-pre" style={{ color: "#c9d1d9" }}>{share.url}</div>
              </div>
            )}
          </>
        )}

        {result && <ScanResult result={result} />}

        {result && (
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

        <footer className="bb-foot">
          Developed with <span className="heart">♥</span> by <b style={{ color: "#d7dce3" }}>Saqib Sarwar</b>
        </footer>
      </div>
    </div>
  );
}
