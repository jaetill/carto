import { apiGet, apiPost } from './index.js';
import { isMockMode } from './index.js';

// ── Topology ──────────────────────────────────────────────

export async function loadTopology(engagementId) {
  if (isMockMode()) return { nodes: [], edges: [], subnets: [] };
  return await apiGet(`/engagement/${engagementId}/graph`) || { nodes: [], edges: [], subnets: [] };
}

// ── Attack Paths ──────────────────────────────────────────

export async function loadAttackPaths(engagementId) {
  if (isMockMode()) return [];
  return await apiGet(`/engagement/${engagementId}/graph/paths`) || [];
}

export async function saveAttackPath(engagementId, edge) {
  if (isMockMode()) return;
  await apiPost(`/engagement/${engagementId}/graph/paths`, edge);
}

export async function deleteAttackPath(engagementId, edgeId) {
  if (isMockMode()) return;
  await apiPost(`/engagement/${engagementId}/graph/paths/delete`, { edgeId });
}

// ── Full re-sync ──────────────────────────────────────────

export async function triggerGraphSync(engagementId) {
  if (isMockMode()) return;
  await apiPost(`/engagement/${engagementId}/graph/sync`, {});
}
