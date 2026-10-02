"use client";
// Shared read-only renderer for a completed scan result. Used by the main app
// (after a job completes) and by the public /report/<token> share page, so both
// show identical findings, coverage/confidence and AI analysis.

const SEV_COLOR = { critical: "#ff2b4e", high: "#ff7a1a", medium: "#eab308", low: "#38bdf8", info: "#8b8b8b" };

function CoveragePanel({ coverage }) {
  if (!coverage) return null;
  const c = coverage;
  const confColor = String(c.confidence || "").startsWith("High") ? "#16a34a" : String(c.confidence || "").startsWith("Low") ? "#ff7a1a" : "#eab308";
  return (
    <div className="bb-panel" style={{ marginTop: 14, borderColor: "#24303f" }}>
      <div style={{ display: "flex", gap: 18, flexWrap: "wrap", alignItems: "center" }}>
        <div>
          <div style={{ fontSize: 28, fontWeight: 800, color: "#58a6ff", lineHeight: 1 }}>{c.coveragePct}%</div>
          <div style={{ fontSize: 10, color: "#7d8590", marginTop: 2 }}>TESTING COVERAGE</div>
        </div>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, color: confColor }}>{c.confidence}</div>
          <div style={{ fontSize: 10, color: "#7d8590" }}>EVIDENCE CONFIDENCE</div>
        </div>
        {c.posture && <div style={{ fontSize: 12, color: "#9aa4af", flex: 1, minWidth: 180 }}>{c.posture}</div>}
      </div>
      {Array.isArray(c.areasNotTested) && c.areasNotTested.length > 0 && (
        <details style={{ marginTop: 10 }}>
          <summary style={{ fontSize: 11, color: "#eab308", cursor: "pointer" }}>AREAS NOT TESTED ({c.areasNotTested.length})</summary>
          <ul style={{ margin: "8px 0 0", paddingLeft: 20 }}>
            {c.areasNotTested.map((a, i) => <li key={i} style={{ fontSize: 12, color: "#9aa4af", lineHeight: 1.5 }}>{a}</li>)}
          </ul>
        </details>
      )}
      <p style={{ fontSize: 10.5, color: "#6b7580", margin: "10px 0 0", lineHeight: 1.5 }}>
        {c.disclaimer || "Testing coverage reflects breadth of checks performed, not a guarantee of security. Automated testing cannot prove the absence of vulnerabilities."}
      </p>
    </div>
  );
}

export default function ScanResult({ result }) {
  if (!result) return null;
  const coverage = result.coverage || null;
  return (
    <section style={{ marginTop: 18 }}>
      <div className="bb-panel">
        <div className="bb-frow" style={{ display: "flex", flexWrap: "wrap", gap: 14, alignItems: "baseline", fontSize: 13 }}>
          <b style={{ color: "#16a34a", wordBreak: "break-all" }}>{result.finalTarget || result.target}</b>
          <span style={{ color: "#7d8590" }}>HTTP {result.httpStatus} · {((result.durationMs || 0) / 1000) | 0}s · mode {result.mode}</span>
        </div>
        {result.summary && (
          <div className="bb-sevrow" style={{ display: "flex", gap: 14, marginTop: 10, flexWrap: "wrap" }}>
            {["critical", "high", "medium", "low", "info"].map((s) => (
              <span key={s} style={{ color: SEV_COLOR[s] }}>{s}: {result.summary[s] || 0}</span>
            ))}
          </div>
        )}
      </div>

      <CoveragePanel coverage={coverage} />

      <div style={{ marginTop: 14, display: "flex", flexDirection: "column", gap: 10 }}>
        {(!result.findings || result.findings.length === 0) && <div style={{ color: "#7d8590", fontSize: 13 }}>No findings for the checks run in {result.mode} mode. This is not proof the target is secure — see coverage above.</div>}
        {(result.findings || []).map((f) => (
          <div key={f.id} className="bb-finding" style={{ border: `1px solid ${SEV_COLOR[f.severity] || "#2a3441"}55`, borderLeft: `3px solid ${SEV_COLOR[f.severity] || "#2a3441"}` }}>
            <div className="bb-frow" style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
              <span style={{ fontSize: 10, fontWeight: 800, letterSpacing: 1, color: SEV_COLOR[f.severity], border: `1px solid ${SEV_COLOR[f.severity]}`, padding: "1px 7px", borderRadius: 5, flexShrink: 0 }}>{String(f.severity).toUpperCase()}</span>
              <b style={{ fontSize: 14, wordBreak: "break-word" }}>{f.title}</b>
              <span style={{ fontSize: 11, color: "#7d8590", flexShrink: 0 }}>[{f.tool}]</span>
            </div>
            {f.desc && <p style={{ fontSize: 12, color: "#9aa4af", margin: "6px 0 0", lineHeight: 1.5 }}>{f.desc}</p>}
            {f.evidence != null && (
              <details style={{ marginTop: 8 }}>
                <summary style={{ fontSize: 11, color: "#38bdf8", cursor: "pointer" }}>EVIDENCE / PROOF</summary>
                <pre className="bb-pre" style={{ marginTop: 8, color: "#c9d1d9" }}>{typeof f.evidence === "string" ? f.evidence : JSON.stringify(f.evidence, null, 2)}</pre>
              </details>
            )}
            {f.poc && f.poc.curl && (
              <details style={{ marginTop: 6 }}>
                <summary style={{ fontSize: 11, color: "#ff7a1a", cursor: "pointer" }}>REPRODUCE (curl)</summary>
                <pre className="bb-pre" style={{ marginTop: 8, border: "1px solid #4a1a12", color: "#ffb46e" }}>{f.poc.curl}</pre>
              </details>
            )}
            {f.fix && <div style={{ marginTop: 8, fontSize: 12, color: "#9aa4af", lineHeight: 1.5 }}><b style={{ color: "#16a34a" }}>FIX:</b> {f.fix}</div>}
          </div>
        ))}
      </div>

      {result.ai && result.ai.executiveSummary && (
        <div className="bb-panel" style={{ marginTop: 16, borderColor: "#2d4a22" }}>
          <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap", marginBottom: 10 }}>
            <b style={{ fontSize: 13, letterSpacing: 1, color: "#a3e635" }}>AI ANALYST — {result.ai.riskVerdict || "VERDICT"}</b>
            <span style={{ fontSize: 10, color: "#7d8590" }}>[{result.ai.aiProvider} · AI-generated, verify before acting]</span>
          </div>
          <p style={{ fontSize: 13, color: "#d7dce3", lineHeight: 1.6, margin: "0 0 10px" }}>{result.ai.executiveSummary}</p>
          {result.ai.attackNarrative && (
            <details style={{ marginBottom: 10 }}>
              <summary style={{ fontSize: 11, color: "#ff7a1a", cursor: "pointer" }}>HOW AN ATTACKER WOULD USE THIS</summary>
              <p style={{ fontSize: 12, color: "#d7dce3", lineHeight: 1.6, margin: "8px 0 0", whiteSpace: "pre-wrap" }}>{result.ai.attackNarrative}</p>
            </details>
          )}
          {Array.isArray(result.ai.remediation) && result.ai.remediation.length > 0 && (
            <details style={{ marginBottom: 10 }} open>
              <summary style={{ fontSize: 11, color: "#16a34a", cursor: "pointer" }}>PRIORITIZED REMEDIATION</summary>
              <ol style={{ margin: "8px 0 0", paddingLeft: 20, display: "flex", flexDirection: "column", gap: 6 }}>
                {result.ai.remediation.map((r, i) => (<li key={i} style={{ fontSize: 12, color: "#d7dce3", lineHeight: 1.5 }}><b>{r.title}</b>{r.howto ? <> — {r.howto}</> : null}</li>))}
              </ol>
            </details>
          )}
        </div>
      )}
    </section>
  );
}
