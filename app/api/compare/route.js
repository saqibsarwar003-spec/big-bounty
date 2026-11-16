import { getJobResult } from "../../../lib/control-plane";
import { readBrowserAccessToken } from "../../../lib/job-access";
import { diffScans } from "../../../lib/compare";

export const dynamic = "force-dynamic";

// POST /api/compare { a, b }
// Fetches both stored results and returns the previous-vs-current diff:
// new / resolved / unchanged findings, severity changes, coverage delta.
export async function POST(request) {
  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: "Invalid JSON body" }, { status: 400 }); }
  const a = String(body.a || ""); // previous
  const b = String(body.b || ""); // current
  const accessToken = readBrowserAccessToken(request.headers.get("cookie"));
  if (!a || !b) return Response.json({ error: "need a (previous) and b (current) job ids" }, { status: 400 });
  if (!accessToken) {
    return Response.json({ error: "Both scans must be opened in this browser before comparing them." }, { status: 404, headers: { "Cache-Control": "no-store" } });
  }
  try {
    const [ra, rb] = await Promise.all([getJobResult(a, accessToken), getJobResult(b, accessToken)]);
    if (ra.status === 404 || rb.status === 404) {
      return Response.json({ error: "One or both scans are private to another browser." }, { status: 404, headers: { "Cache-Control": "no-store" } });
    }
    if (!ra.ok || !rb.ok) {
      return Response.json({ error: "One or both scans have no stored result yet." }, { status: 409 });
    }
    const diff = diffScans(ra.data, rb.data);
    return Response.json(
      { diff, prev: { jobId: a, target: ra.data?.target, when: ra.data?.completedAt }, curr: { jobId: b, target: rb.data?.target, when: rb.data?.completedAt } },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch (e) {
    if (e.code === "CONTROL_PLANE_UNCONFIGURED") return Response.json({ error: "Backend not configured." }, { status: 503 });
    return Response.json({ error: "Comparison failed." }, { status: 502 });
  }
}
