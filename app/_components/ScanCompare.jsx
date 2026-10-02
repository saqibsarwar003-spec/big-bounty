"use client";
// Renders a previous-vs-current scan diff for the pre-release regression workflow.

const SEV_COLOR = { critical: "#ff2b4e", high: "#ff7a1a", medium: "#eab308", low: "#38bdf8", info: "#8b8b8b" };

function Row({ f, tag, tagColor }) {
  return (
    <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap", padding: "4px 0", borderBottom: "1px solid #141a22" }}>
      <span style={{ fontSize: 10, fontWeight: 800, color: tagColor, width: 64, flexShrink: 0 }}>{tag}</span>
      <span style={{ fontSize: 10, fontWeight: 800, color: SEV_COLOR[f.severity] || "#8b8b8b", textTransform: "uppercase", width: 58, flexShrink: 0 }}>{f.severity}</span>
      <span style={{ fontSize: 12, color: "#d7dce3", wordBreak: "break-word" }}>{f.title}</span>
      {f.location && <span style={{ fontSize: 11, color: "#6b7580" }}>{f.location}</span>}
    </div>
  );
}

export default function ScanCompare({ data }) {
  if (!data || !data.diff) return null;
  const { diff } = data;
  const s = diff.summary || {};
  const cov = s.coverageChange;
  return (
    <div className="bb-panel" style={{ marginTop: 16, borderColor: "#24303f" }}>
      <div style={{ fontSize: 13, letterSpacing: 1, color: "#58a6ff", marginBottom: 10 }}>PREVIOUS → CURRENT COMPARISON</div>
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", fontSize: 13, marginBottom: 12 }}>
        <span style={{ color: "#ff7a1a" }}>＋ New: <b>{s.new ?? 0}</b></span>
        <span style={{ color: "#16a34a" }}>✓ Resolved: <b>{s.resolved ?? 0}</b></span>
        <span style={{ color: "#7d8590" }}>• Unchanged: <b>{s.unchanged ?? 0}</b></span>
        <span style={{ color: "#eab308" }}>↕ Severity changed: <b>{s.severityChanged ?? 0}</b></span>
        {typeof cov === "number" && (
          <span style={{ color: cov >= 0 ? "#16a34a" : "#ff7a1a" }}>Coverage Δ: <b>{cov >= 0 ? "+" : ""}{cov}%</b></span>
        )}
      </div>
      {s.improved && <div style={{ fontSize: 12, color: "#16a34a", marginBottom: 10 }}>↳ Net improvement since the previous scan.</div>}
      <div style={{ fontSize: 12 }}>
        {(diff.newFindings || []).map((f, i) => <Row key={"n" + i} f={f} tag="NEW" tagColor="#ff7a1a" />)}
        {(diff.severityChanges || []).map((f, i) => (
          <Row key={"s" + i} f={f} tag={f.direction === "worse" ? "WORSE" : "BETTER"} tagColor={f.direction === "worse" ? "#ff2b4e" : "#16a34a"} />
        ))}
        {(diff.resolved || []).map((f, i) => <Row key={"r" + i} f={f} tag="FIXED" tagColor="#16a34a" />)}
      </div>
      {(diff.newFindings?.length || 0) + (diff.resolved?.length || 0) + (diff.severityChanges?.length || 0) === 0 && (
        <div style={{ fontSize: 12, color: "#7d8590" }}>No changes between the two scans.</div>
      )}
    </div>
  );
}
