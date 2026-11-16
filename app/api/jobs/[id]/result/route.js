import { getJobResult } from '../../../../../lib/control-plane';
import { readBrowserAccessToken } from '../../../../../lib/job-access';

export const dynamic = 'force-dynamic';

// GET /api/jobs/:id/result — full stored findings/evidence/AI for a completed job.
export async function GET(request, { params }) {
  const id = params?.id;
  if (!id) return Response.json({ error: 'job id required' }, { status: 400 });
  const accessToken = readBrowserAccessToken(request.headers.get('cookie'));
  if (!accessToken) {
    return Response.json({ error: 'This scan is private to the browser that created it.' }, { status: 404, headers: { 'Cache-Control': 'no-store' } });
  }
  try {
    const r = await getJobResult(id, accessToken);
    // getJobResult returns raw JSON body on 200; call() already parsed it into data.
    return Response.json(r.data ?? { error: 'result unavailable' }, { status: r.status, headers: { 'Cache-Control': 'no-store' } });
  } catch (e) {
    if (e.code === 'CONTROL_PLANE_UNCONFIGURED') {
      return Response.json({ error: 'The scanning backend is not configured yet.' }, { status: 503 });
    }
    return Response.json({ error: 'Could not reach the scanning backend.' }, { status: 502 });
  }
}
