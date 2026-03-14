import { s3Get, s3Put }                                    from './s3.mjs';
import { getTopology, getAttackPaths, addAttackPath, removeAttackPath } from './graph.mjs';
import { afterDataSave, afterSnapshotSave, afterImportSave, syncEngagementFull } from './sync.mjs';

// ── Response helper ───────────────────────────────────────

function respond(statusCode, body) {
  return {
    statusCode,
    headers: {
      'Content-Type':                'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Authorization,Content-Type',
    },
    body: JSON.stringify(body),
  };
}

// ── Graph sync wrapper — never fails the main request ─────

async function graphSync(label, fn) {
  try {
    await fn();
  } catch (e) {
    console.error(`[graph:${label}]`, e.message);
  }
}

// ── Handler ───────────────────────────────────────────────

export const handler = async (event) => {
  const method = event.httpMethod;
  const path   = event.path;

  try {

    // ── Engagements ──────────────────────────────────────

    if (method === 'GET' && path === '/engagements') {
      const data = await s3Get('engagements.json');
      return respond(200, data || []);
    }

    if (method === 'POST' && path === '/engagements') {
      const body = JSON.parse(event.body);
      await s3Put('engagements.json', body);
      return respond(200, { ok: true });
    }

    // ── Engagement data (hosts + notes) ──────────────────

    const dataMatch = path.match(/^\/engagement\/([^/]+)\/data$/);

    if (method === 'GET' && dataMatch) {
      const data = await s3Get(`engagements/${dataMatch[1]}/data.json`);
      return respond(data ? 200 : 404, data || {});
    }

    if (method === 'POST' && dataMatch) {
      const engId = dataMatch[1];
      const body  = JSON.parse(event.body);
      await s3Put(`engagements/${engId}/data.json`, body);
      await graphSync('data', () => afterDataSave(engId, body));
      return respond(200, { ok: true });
    }

    // ── Snapshots ─────────────────────────────────────────

    const snapMatch = path.match(/^\/engagement\/([^/]+)\/snapshots$/);

    if (method === 'GET' && snapMatch) {
      const data = await s3Get(`engagements/${snapMatch[1]}/snapshots.json`);
      return respond(200, data || []);
    }

    if (method === 'POST' && snapMatch) {
      const engId     = snapMatch[1];
      const snapshots = JSON.parse(event.body);
      await s3Put(`engagements/${engId}/snapshots.json`, snapshots);
      await graphSync('snapshots', async () => {
        const data = await s3Get(`engagements/${engId}/data.json`);
        await afterSnapshotSave(engId, snapshots, data?.hosts || []);
      });
      return respond(200, { ok: true });
    }

    // ── Imports ───────────────────────────────────────────

    const importsMatch = path.match(/^\/engagement\/([^/]+)\/imports$/);

    if (method === 'GET' && importsMatch) {
      const data = await s3Get(`engagements/${importsMatch[1]}/imports.json`);
      return respond(200, data || []);
    }

    if (method === 'POST' && importsMatch) {
      const engId   = importsMatch[1];
      const imports = JSON.parse(event.body);
      await s3Put(`engagements/${engId}/imports.json`, imports);
      await graphSync('imports', async () => {
        const data = await s3Get(`engagements/${engId}/data.json`);
        await afterImportSave(engId, imports, data?.hosts || []);
      });
      return respond(200, { ok: true });
    }

    // ── Graph: topology ───────────────────────────────────

    const graphMatch = path.match(/^\/engagement\/([^/]+)\/graph$/);

    if (method === 'GET' && graphMatch) {
      const topology = await getTopology(graphMatch[1]);
      return respond(200, topology);
    }

    // ── Graph: attack paths ───────────────────────────────

    const pathsMatch = path.match(/^\/engagement\/([^/]+)\/graph\/paths$/);

    if (method === 'GET' && pathsMatch) {
      const paths = await getAttackPaths(pathsMatch[1]);
      return respond(200, paths);
    }

    if (method === 'POST' && pathsMatch) {
      const engId = pathsMatch[1];
      const body  = JSON.parse(event.body);
      await addAttackPath(engId, body);
      return respond(200, { ok: true });
    }

    // ── Graph: delete attack path edge ────────────────────

    const pathDeleteMatch = path.match(/^\/engagement\/([^/]+)\/graph\/paths\/delete$/);

    if (method === 'POST' && pathDeleteMatch) {
      const { edgeId } = JSON.parse(event.body);
      if (!edgeId) return respond(400, { error: 'edgeId required' });
      await removeAttackPath(edgeId);
      return respond(200, { ok: true });
    }

    // ── Graph: full re-sync ───────────────────────────────

    const syncMatch = path.match(/^\/engagement\/([^/]+)\/graph\/sync$/);

    if (method === 'POST' && syncMatch) {
      await syncEngagementFull(syncMatch[1]);
      return respond(200, { ok: true });
    }

    return respond(404, { error: 'Not found' });

  } catch (e) {
    console.error(e);
    return respond(500, { error: e.message });
  }
};
