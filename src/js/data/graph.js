import { apiGet, apiPost, isMockMode } from './index.js';
import { mockEngagementData, mockSnapshots, mockAttackPaths, MOCK_ENG_ID } from './mockScenario.js';
import { parseNetstat } from './parsers.js';

// ── Mock topology (derived from mock data client-side) ────

// Session-local mock attack paths — operator can add/remove during the session
let _mockPaths = null;
function getMockPaths() {
  if (!_mockPaths) _mockPaths = mockAttackPaths.map(p => ({ ...p }));
  return _mockPaths;
}

function buildMockTopology() {
  const data  = mockEngagementData[MOCK_ENG_ID] || { hosts: [] };
  const hosts = data.hosts || [];

  // ip → hostId map
  const ipToHostId = {};
  for (const h of hosts) { if (h.ip) ipToHostId[h.ip] = h.id; }

  // Subnets from host primary IPs
  const subnetSet      = new Set();
  const subnetsByHost  = {};
  for (const h of hosts) {
    if (!h.ip) continue;
    const parts = h.ip.split('.');
    if (parts.length !== 4) continue;
    const cidr = `${parts.slice(0, 3).join('.')}.0/24`;
    subnetSet.add(cidr);
    if (!subnetsByHost[h.id]) subnetsByHost[h.id] = [];
    subnetsByHost[h.id].push(cidr);
  }

  // Nodes
  const nodes = hosts.map(h => ({
    id:            h.id,
    ip:            h.ip,
    hostname:      h.hostname,
    os:            h.os,
    osFamily:      h.osFamily,
    status:        h.status,
    subnets:       subnetsByHost[h.id] || [],
    openPortCount: 0,
  }));

  // Edges from netstat snapshots — parse raw output on the fly
  const snaps    = mockSnapshots[MOCK_ENG_ID] || [];
  const edgeKeys = new Set();
  const edges    = [];

  for (const snap of snaps) {
    if (snap.commandType !== 'netstat') continue;
    const parsed = snap.parsed || parseNetstat(snap.rawOutput, snap.osFamily);
    for (const conn of parsed.connections || []) {
      if (!conn.remoteAddr || conn.remoteAddr.startsWith('0.0.0.0') || conn.remoteAddr === '*') continue;
      const remoteIp  = conn.remoteAddr.replace(/:\d+$/, '');
      const dstHostId = ipToHostId[remoteIp];
      if (!dstHostId || dstHostId === snap.hostId) continue;
      const key = `${snap.hostId}→${dstHostId}:${conn.remotePort}/${conn.proto}`;
      if (edgeKeys.has(key)) continue;
      edgeKeys.add(key);
      edges.push({
        source:   snap.hostId,
        target:   dstHostId,
        port:     conn.remotePort || null,
        protocol: conn.proto || 'TCP',
        state:    conn.state || '',
      });
    }
  }

  return { nodes, edges, subnets: [...subnetSet] };
}

function buildMockAttackPaths() {
  const data     = mockEngagementData[MOCK_ENG_ID] || { hosts: [] };
  const hostMap  = Object.fromEntries((data.hosts || []).map(h => [h.id, h]));
  return getMockPaths().map(p => ({
    ...p,
    source:   p.fromHostId,
    target:   p.toHostId,
    srcLabel: hostMap[p.fromHostId]?.hostname || hostMap[p.fromHostId]?.ip || p.fromHostId,
    dstLabel: hostMap[p.toHostId]?.hostname   || hostMap[p.toHostId]?.ip   || p.toHostId,
  }));
}

// ── Topology ──────────────────────────────────────────────

export async function loadTopology(engagementId) {
  if (isMockMode()) return buildMockTopology();
  return await apiGet(`/engagement/${engagementId}/graph`) || { nodes: [], edges: [], subnets: [] };
}

// ── Attack Paths ──────────────────────────────────────────

export async function loadAttackPaths(engagementId) {
  if (isMockMode()) return buildMockAttackPaths();
  return await apiGet(`/engagement/${engagementId}/graph/paths`) || [];
}

export async function saveAttackPath(engagementId, edge) {
  if (isMockMode()) {
    getMockPaths().push(edge);
    return;
  }
  await apiPost(`/engagement/${engagementId}/graph/paths`, edge);
}

export async function deleteAttackPath(engagementId, edgeId) {
  if (isMockMode()) {
    _mockPaths = getMockPaths().filter(p => p.edgeId !== edgeId);
    return;
  }
  await apiPost(`/engagement/${engagementId}/graph/paths/delete`, { edgeId });
}

// ── Full re-sync ──────────────────────────────────────────

export async function triggerGraphSync(engagementId) {
  if (isMockMode()) return;
  await apiPost(`/engagement/${engagementId}/graph/sync`, {});
}
