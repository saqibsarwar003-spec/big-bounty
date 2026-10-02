import { getJob } from '../../../../lib/control-plane';

export const dynamic = 'force-dynamic';

// GET /api/jobs/:id  — current status, progress, summary and result pointer.
// This is what the UI polls so a scan reloads correctly after refresh/return.
export async function GET(_request, { params }) {
  const id = params?.id;
  if (!id) return Response.json({ error: 'job id required' }, { status: 400 });
  try {
    const r = await getJob(id);
    return Response.json(r.data || { error: 'not found' }, { status: r.status, headers: { 'Cache-Control': 'no-store' } });
  } catch (e) {
    if (e.code === 'CONTROL_PLANE_UNCONFIGURED') {
      return Response.json({ error: 'The scanning backend is not configured yet.' }, { status: 503 });
    }
    return Response.json({ error: 'Could not reach the scanning backend.' }, { status: 502 });
  }
}
