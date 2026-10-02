import { getJobResult } from "../../../lib/control-plane";
import { diffScans } from "../../../lib/compare";

export const dynamic = "force-dynamic";

// GET /api/compare?a=<previousJobId>&b=<currentJobId>
// Fetches both stored results and returns the previous-vs-current diff:
// new / resolved / unchanged findings, severity changes, coverage delta.
export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const a = searchParams.get("a"); // previous
  const b = searchParams.get("b"); // current
  if (!a || !b) return Response.json({ error: "need a (previous) and b (current) job ids" }, { status: 400 });
  try {
    const [ra, rb] = await Promise.all([getJobResult(a), getJobResult(b)]);
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
