import { verifyShareToken } from "../../../lib/share-token";
import { getJob, getJobResult } from "../../../lib/control-plane";
import ScanResult from "../../_components/ScanResult";

export const dynamic = "force-dynamic";

const STYLE = `
* { box-sizing: border-box; }
.bb-root { min-height: 100vh; background: #0a0e14; color: #d7dce3; font-family: ui-monospace, Menlo, monospace; padding: 16px; }
.bb-wrap { max-width: 860px; margin: 0 auto; }
.bb-panel { border: 1px solid #1f2733; border-radius: 10px; padding: 16px; background: #0d1219; }
.bb-finding { border-radius: 8px; padding: 12px; background: #0d1219; }
.bb-pre { background: #0a0e14; border: 1px solid #1f2733; border-radius: 6px; padding: 10px; font-size: 11px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
.bb-foot { text-align: center; color: #7d8590; font-size: 12px; padding: 26px 0 10px; }
@media (min-width:640px){ .bb-root{padding:24px;} }
@media (max-width:480px){ .bb-frow{flex-direction:column !important; align-items:flex-start !important; gap:6px !important;} }
`;

function Shell({ children }) {
  return (
    <div className="bb-root"><style>{STYLE}</style>
      <div className="bb-wrap">
        <header style={{ marginBottom: 20 }}>
          <h1 style={{ fontSize: 24, margin: 0, color: "#ff2b4e", letterSpacing: 2 }}>⚔ BIG BOUNTY — Shared Report</h1>
          <p style={{ color: "#7d8590", fontSize: 12, margin: "6px 0 0" }}>Read-only security assessment report. Findings are observations from automated testing — verify before acting.</p>
        </header>
        {children}
        <footer className="bb-foot">Big Bounty · big-bounty.vercel.app</footer>
      </div>
    </div>
  );
}

function Notice({ title, body }) {
  return <div className="bb-panel" style={{ borderColor: "#4a1a12" }}><b style={{ color: "#ff7a1a" }}>{title}</b><p style={{ fontSize: 13, color: "#9aa4af", margin: "8px 0 0" }}>{body}</p></div>;
}

export default async function ReportPage({ params }) {
  const token = params?.token;
  const key = process.env.BIGBOUNTY_HMAC_SECRET;
  if (!key) return <Shell><Notice title="Unavailable" body="This deployment is not configured to serve shared reports yet." /></Shell>;

  const v = verifyShareToken(token, key);
  if (!v.valid) {
    const msg = v.reason === "expired" ? "This report link has expired. Ask the owner for a fresh link."
      : v.reason === "revoked" ? "This report link has been revoked."
      : "This report link is invalid.";
    return <Shell><Notice title="Link not valid" body={msg} /></Shell>;
  }

  const jobId = v.reportId;
  let job = null, result = null;
  try { const jr = await getJob(jobId); if (jr.ok) job = jr.data; } catch {}
  if (!job) return <Shell><Notice title="Report not found" body="The scan this link points to could not be found." /></Shell>;

  if (job.status === "completed") {
    try { const rr = await getJobResult(jobId); if (rr.ok) result = rr.data; } catch {}
  }

  return (
    <Shell>
      <div className="bb-panel" style={{ marginBottom: 8 }}>
        <div className="bb-frow" style={{ display: "flex", gap: 14, flexWrap: "wrap", alignItems: "baseline", fontSize: 13 }}>
          <b style={{ color: "#16a34a", wordBreak: "break-all" }}>{job.target}</b>
          <span style={{ color: "#7d8590" }}>status: {job.status}{job.progress ? ` · ${job.progress}%` : ""} · mode {job.mode}</span>
        </div>
      </div>
      {result ? <ScanResult result={result} /> : (
        <Notice title={job.status === "failed" ? "Scan failed" : "Scan in progress"}
          body={job.status === "failed" ? (job.error || "The scan did not complete.") : "This scan is still running. Refresh this page in a little while to see the results."} />
      )}
    </Shell>
  );
}
