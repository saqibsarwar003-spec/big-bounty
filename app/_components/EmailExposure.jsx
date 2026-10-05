"use client";
import { useState, useCallback } from "react";

// Defensive Email Exposure Check.
// Flow: enter email -> verify ownership with an emailed one-time code -> results.
// No sensitive material (passwords, stealer-log contents, PII, enrichment) is ever
// requested from or shown by this component — the server allowlists everything.

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function EmailExposure() {
  const [step, setStep] = useState("email"); // email | code | results
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [delivered, setDelivered] = useState(true);
  const [result, setResult] = useState(null);

  const reset = useCallback(() => {
    setStep("email"); setCode(""); setToken(""); setError(""); setNotice("");
    setResult(null); setDelivered(true);
  }, []);

  async function sendCode() {
    const e = email.trim().toLowerCase();
    if (!EMAIL_RE.test(e) || e.length > 254) { setError("Enter a valid email address."); return; }
    setBusy(true); setError(""); setNotice(""); setResult(null);
    try {
      const res = await fetch("/api/exposure/start", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: e }),
      });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || `HTTP ${res.status}`);
      setToken(j.token);
      setDelivered(j.delivery === "sent");
      setNotice(j.message || "Enter the verification code we sent to your email.");
      setStep("code");
    } catch (err) { setError(err.message || "Could not start the check."); }
    finally { setBusy(false); }
  }

  async function verifyAndScan() {
    const c = code.trim().toUpperCase();
    if (c.length < 6) { setError("Enter the code from your email."); return; }
    setBusy(true); setError("");
    try {
      const res = await fetch("/api/exposure/check", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim().toLowerCase(), code: c, token }),
      });
      const j = await res.json();
      if (res.status === 401) { setError(j.error || "Verification failed. Check the code and try again."); return; }
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
          <span className="ee-step"><span className={`ee-dot ${step === "code" ? "on" : step === "results" ? "done" : ""}`}>{step === "results" ? "✓" : "2"}</span>VERIFY</span>
          <span className="ee-sep" />
          <span className="ee-step"><span className={`ee-dot ${step === "results" ? "on" : ""}`}>3</span>RESULTS</span>
        </div>

        <p style={{ fontSize: 12, color: "#7d8590", lineHeight: 1.55, margin: "0 0 16px" }}>
          Check whether <b style={{ color: "#d7dce3" }}>your own</b> email address appears in known data breaches.
          To protect privacy, you must verify you control the mailbox before any results are shown. Passwords and other
          sensitive data are never displayed — only breach names, dates, affected services, and security guidance.
        </p>

        {step === "email" && (
          <>
            <label className="ee-label">YOUR EMAIL ADDRESS</label>
            <input
              className="ee-input" value={email} onChange={(e) => setEmail(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !busy && sendCode()}
              type="email" inputMode="email" autoCapitalize="none" autoCorrect="off" spellCheck={false}
              placeholder="you@example.com" disabled={busy}
            />
            <div style={{ marginTop: 14 }}>
              <button className="ee-btn primary" onClick={sendCode} disabled={busy}>
                {busy ? "SENDING CODE…" : "SEND VERIFICATION CODE"}
              </button>
            </div>
            <div className="ee-hint">
              We&apos;ll email a one-time code to confirm the address is yours. This check is for your own accounts — it is
              not a people-search or lookup tool for other individuals.
            </div>
          </>
        )}

        {step === "code" && (
          <>
            {notice && <div className={`ee-msg ${delivered ? "ee-info" : "ee-warn"}`} style={{ marginBottom: 14 }}>{notice}</div>}
            <label className="ee-label">VERIFICATION CODE FOR <span className="ee-mono">{email.trim().toLowerCase()}</span></label>
            <input
              className="ee-input ee-code" value={code} onChange={(e) => setCode(e.target.value.toUpperCase())}
              onKeyDown={(e) => e.key === "Enter" && !busy && verifyAndScan()}
              autoCapitalize="characters" autoCorrect="off" spellCheck={false} maxLength={12}
              placeholder="XXXXXXXX" disabled={busy}
            />
            <div style={{ display: "flex", gap: 10, marginTop: 14, flexWrap: "wrap" }}>
              <button className="ee-btn primary" style={{ flex: 2, minWidth: 180 }} onClick={verifyAndScan} disabled={busy}>
                {busy ? "VERIFYING & SCANNING…" : "VERIFY & RUN CHECK"}
              </button>
              <button className="ee-btn ghost" style={{ flex: 1, minWidth: 120 }} onClick={reset} disabled={busy}>
                Change email
              </button>
            </div>
            <div className="ee-hint">The code expires in 10 minutes. Didn&apos;t get it? Check spam, or change the email to resend.</div>
          </>
        )}

        {step === "results" && result && (
          <>
            <div style={{ fontSize: 13, color: "#7d8590", marginBottom: 4 }}>
              Verified results for <span className="ee-mono" style={{ color: "#d7dce3" }}>{result.email}</span>
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
