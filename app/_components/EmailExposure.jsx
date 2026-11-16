"use client";
import { useState, useCallback } from "react";

// Defensive Email Exposure Check. Results are server-allowlisted: no passwords,
// stealer-log contents, personal data, or enrichment are shown.

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function EmailExposure() {
  const [step, setStep] = useState("email"); // email | results
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  const reset = useCallback(() => {
    setStep("email"); setError(""); setResult(null);
  }, []);

  async function runCheck() {
    const e = email.trim().toLowerCase();
    if (!EMAIL_RE.test(e) || e.length > 254) { setError("Enter a valid email address."); return; }
    setBusy(true); setError(""); setResult(null);
    try {
      const res = await fetch("/api/exposure/check", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: e }),
      });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || `HTTP ${res.status}`);
      setResult(j);
      setStep("results");
    } catch (err) { setError(err.message || "The exposure check could not be completed."); }
    finally { setBusy(false); }
  }

  const anyBreach = result?.summary?.anyBreach;
  const anyStealer = result?.summary?.anyStealer;
  const clean = result && result.ok && !anyBreach && !anyStealer;

  return (
    <div className="ee">
      <style>{`
        .ee { margin-top: 16px; }
        .ee-card { border: 1px solid #1f2733; border-radius: 10px; background: #0d1219; padding: 16px; }
        .ee-steps { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
        .ee-step { display: flex; align-items: center; gap: 8px; font-size: 11px; color: #6b7580; letter-spacing: .5px; }
        .ee-dot { width: 20px; height: 20px; border-radius: 50%; border: 1px solid #2a3441; display: inline-flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; color: #6b7580; }
        .ee-dot.on { background: #ff2b4e; border-color: #ff2b4e; color: #fff; }
        .ee-dot.done { background: #16a34a; border-color: #16a34a; color: #fff; }
        .ee-sep { flex: 1; height: 1px; background: #1f2733; min-width: 12px; }
        .ee-label { display: block; font-size: 12px; color: #7d8590; margin-bottom: 6px; letter-spacing: .5px; }
        .ee-input { width: 100%; background: #0a0e14; border: 1px solid #2a3441; border-radius: 8px; padding: 10px 12px; color: #d7dce3; font-size: 16px; min-height: 44px; font-family: inherit; }
        .ee-btn { border: 0; border-radius: 8px; padding: 12px 22px; font-size: 14px; font-weight: 700; cursor: pointer; min-height: 46px; font-family: inherit; }
        .ee-btn.primary { background: #ff2b4e; color: #fff; width: 100%; }
        .ee-btn.primary:disabled { background: #1f2733; color: #7d8590; cursor: wait; }
        .ee-btn.ghost { background: #1f2733; color: #d7dce3; }
        .ee-code { letter-spacing: 6px; font-size: 20px; text-align: center; text-transform: uppercase; }
        .ee-msg { border-radius: 8px; padding: 12px; font-size: 13px; line-height: 1.5; }
        .ee-err { border: 1px solid #ff2b4e; color: #ff7a8c; background: rgba(255,43,78,.06); }
        .ee-info { border: 1px solid #1f6feb; color: #9ecbff; background: rgba(31,111,235,.06); }
        .ee-warn { border: 1px solid #eab308; color: #f2d675; background: rgba(234,179,8,.06); }
        .ee-hint { font-size: 11px; color: #6b7580; margin-top: 10px; line-height: 1.5; }
        .ee-ov { display: flex; gap: 10px; flex-wrap: wrap; margin: 4px 0 14px; }
        .ee-badge { flex: 1 1 200px; border-radius: 10px; padding: 14px; border: 1px solid #1f2733; background: #0a0e14; }
        .ee-badge .big { font-size: 20px; font-weight: 800; letter-spacing: .5px; }
        .ee-badge .sub { font-size: 11px; color: #7d8590; margin-top: 4px; }
        .ee-sechead { font-size: 12px; color: #7d8590; letter-spacing: 1px; margin: 18px 0 8px; text-transform: uppercase; }
        .ee-src { border: 1px solid #1f2733; border-radius: 10px; background: #0a0e14; padding: 14px; margin-bottom: 10px; }
        .ee-src-top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .ee-pill { font-size: 10px; font-weight: 700; letter-spacing: .5px; padding: 3px 8px; border-radius: 999px; }
        .ee-pill.ok { background: rgba(22,163,74,.14); color: #35d07f; border: 1px solid #16a34a; }
        .ee-pill.bad { background: rgba(255,43,78,.12); color: #ff7a8c; border: 1px solid #ff2b4e; }
        .ee-breach { display: flex; gap: 10px; align-items: baseline; padding: 8px 0; border-bottom: 1px solid #141a22; font-size: 13px; flex-wrap: wrap; }
        .ee-breach .nm { color: #d7dce3; font-weight: 600; }
        .ee-breach .dm { color: #58a6ff; font-size: 12px; }
        .ee-breach .dt { color: #7d8590; font-size: 12px; margin-left: auto; }
        .ee-rec { display: flex; gap: 8px; padding: 7px 0; font-size: 13px; color: #c3ccd6; line-height: 1.5; }
        .ee-rec .tick { color: #35d07f; flex-shrink: 0; }
        .ee-mono { font-family: inherit; color: #d7dce3; word-break: break-all; }
      `}</style>

      <div className="ee-card">
        <div className="ee-steps">
          <span className="ee-step"><span className={`ee-dot ${step === "email" ? "on" : "done"}`}>{step === "email" ? "1" : "✓"}</span>EMAIL</span>
          <span className="ee-sep" />
          <span className="ee-step"><span className={`ee-dot ${step === "results" ? "on" : ""}`}>2</span>RESULTS</span>
        </div>

        <p style={{ fontSize: 12, color: "#7d8590", lineHeight: 1.55, margin: "0 0 16px" }}>
          Check whether an email address appears in known data breaches. Only check addresses you own or are authorized to assess.
          Passwords and other sensitive data are never displayed — only breach names, dates, affected services, and security guidance.
        </p>

        {step === "email" && (
          <>
            <label className="ee-label">EMAIL ADDRESS</label>
            <input
              className="ee-input" value={email} onChange={(e) => setEmail(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !busy && runCheck()}
              type="email" inputMode="email" autoCapitalize="none" autoCorrect="off" spellCheck={false}
              placeholder="you@example.com" disabled={busy}
            />
            <div style={{ marginTop: 14 }}>
              <button className="ee-btn primary" onClick={runCheck} disabled={busy}>
                {busy ? "CHECKING…" : "CHECK EMAIL EXPOSURE"}
              </button>
            </div>
            <div className="ee-hint">
              This check does not require mailbox verification. Use it only for an address you own or have permission to assess.
            </div>
          </>
        )}

        {step === "results" && result && (
          <>
            <div style={{ fontSize: 13, color: "#7d8590", marginBottom: 4 }}>
              Exposure results for <span className="ee-mono" style={{ color: "#d7dce3" }}>{result.email}</span>
            </div>

            <div className="ee-ov">
              {clean ? (
                <div className="ee-badge" style={{ borderColor: "#16a34a" }}>
                  <div className="big" style={{ color: "#35d07f" }}>✓ No known exposure</div>
                  <div className="sub">This address wasn&apos;t found in the breach data we checked.</div>
                </div>
              ) : (
                <>
                  <div className="ee-badge" style={{ borderColor: anyBreach ? "#ff2b4e" : "#1f2733" }}>
                    <div className="big" style={{ color: anyBreach ? "#ff7a8c" : "#7d8590" }}>{anyBreach ? "⚠ Found in breaches" : "No breach records"}</div>
                    <div className="sub">{anyBreach ? "Your address appears in one or more known data breaches." : "Not seen in known data breaches."}</div>
                  </div>
                  <div className="ee-badge" style={{ borderColor: anyStealer ? "#ff7a1a" : "#1f2733" }}>
                    <div className="big" style={{ color: anyStealer ? "#ffa352" : "#7d8590" }}>{anyStealer ? "⚠ Infostealer exposure" : "No stealer-log records"}</div>
                    <div className="sub">{anyStealer ? "Seen in infostealer/stealer-log data — treat associated accounts as compromised." : "Not seen in stealer-log data."}</div>
                  </div>
                </>
              )}
            </div>

            {!result.ok && (
              <div className="ee-msg ee-warn" style={{ marginBottom: 14 }}>
                No source could be reached right now, so this result may be incomplete. See source status below.
              </div>
            )}

            {result.sources && result.sources.map((s) => (
              <SourceCard key={s.id} source={s} />
            ))}

            <div style={{ display: "flex", gap: 10, marginTop: 16, flexWrap: "wrap" }}>
              <button className="ee-btn ghost" onClick={reset}>Check another address</button>
            </div>
          </>
        )}

        {error && <div className="ee-msg ee-err" style={{ marginTop: 14 }}>✗ {error}</div>}
      </div>
    </div>
  );
}

function SourceCard({ source }) {
  const d = source.data;
  return (
    <div className="ee-src">
      <div className="ee-src-top">
        <b style={{ color: "#d7dce3", fontSize: 14 }}>{source.name}</b>
        <span className={`ee-pill ${source.ok ? "ok" : "bad"}`}>{source.ok ? "SOURCE OK" : "UNAVAILABLE"}</span>
        {source.ok && d && (
          <span style={{ marginLeft: "auto", fontSize: 12, color: "#7d8590" }}>
            {d.inBreaches ? `${d.breachCount} breach${d.breachCount === 1 ? "" : "es"}` : "clean"}
            {d.firstSeen ? ` · first seen ${d.firstSeen}` : ""}
          </span>
        )}
      </div>

      {!source.ok && (
        <div style={{ fontSize: 12, color: "#8b949e", marginTop: 8 }}>{source.error || "This source could not be reached."}</div>
      )}

      {source.ok && d && (
        <>
          {d.exposureCategories && d.exposureCategories.length > 0 && (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
              {d.exposureCategories.map((c, i) => (
                <span key={i} style={{ fontSize: 11, color: "#c3ccd6", border: "1px solid #2a3441", borderRadius: 6, padding: "3px 8px" }}>{c}</span>
              ))}
            </div>
          )}

          {d.breaches && d.breaches.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div className="ee-sechead" style={{ margin: "0 0 4px" }}>Affected breaches</div>
              {d.breaches.map((b, i) => (
                <div key={i} className="ee-breach">
                  <span className="nm">{b.source || "Unknown source"}</span>
                  {b.domain && <span className="dm">{b.domain}</span>}
                  {b.date && <span className="dt">{b.date}</span>}
                </div>
              ))}
            </div>
          )}

          {d.timeline && d.timeline.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div className="ee-sechead" style={{ margin: "0 0 4px" }}>Exposure timeline</div>
              {d.timeline.map((t, i) => (
                <div key={i} className="ee-breach">
                  <span className="nm">{t.name || t.source || "Event"}</span>
                  {t.date && <span className="dt">{t.date}</span>}
                </div>
              ))}
            </div>
          )}

          {d.recommendations && d.recommendations.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div className="ee-sechead" style={{ margin: "0 0 4px" }}>Recommended actions</div>
              {d.recommendations.map((r, i) => (
                <div key={i} className="ee-rec"><span className="tick">→</span><span>{r}</span></div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
