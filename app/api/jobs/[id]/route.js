import { getJob } from '../../../../lib/control-plane';
import { readBrowserAccessToken } from '../../../../lib/job-access';

export const dynamic = 'force-dynamic';

// GET /api/jobs/:id  — current status, progress, summary and result pointer.
// This is what the UI polls so a scan reloads correctly after refresh/return.
export async function GET(request, { params }) {
  const id = params?.id;
  if (!id) return Response.json({ error: 'job id required' }, { status: 400 });
  const accessToken = readBrowserAccessToken(request.headers.get('cookie'));
  if (!accessToken) {
    return Response.json({ error: 'This scan is private to the browser that created it.' }, { status: 404, headers: { 'Cache-Control': 'no-store' } });
  }
  try {
    const r = await getJob(id, accessToken);
    return Response.json(r.data || { error: 'not found' }, { status: r.status, headers: { 'Cache-Control': 'no-store' } });
  } catch (e) {
    if (e.code === 'CONTROL_PLANE_UNCONFIGURED') {
      return Response.json({ error: 'The scanning backend is not configured yet.' }, { status: 503 });
    }
    return Response.json({ error: 'Could not reach the scanning backend.' }, { status: 502 });
  }
}
