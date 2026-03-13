import { Auth } from 'aws-amplify';

const API_URL = 'https://9o7c3668a4.execute-api.us-east-2.amazonaws.com/prod';

// ── API helpers ───────────────────────────────────────────

async function apiGet(path) {
  const session = await Auth.currentSession();
  const token   = session.getIdToken().getJwtToken();
  const res = await fetch(`${API_URL}${path}`, {
    headers: { Authorization: token },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Fetch failed: ${res.status}`);
  return res.json();
}

async function apiPost(path, body) {
  const session = await Auth.currentSession();
  const token   = session.getIdToken().getJwtToken();
  const res = await fetch(`${API_URL}${path}`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', Authorization: token },
    body:    JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Request failed: ${res.status}`);
  }
  return res.json();
}

// ── Engagements ───────────────────────────────────────────

export let engagements = [];

export async function loadEngagements() {
  const data = await apiGet('/engagements');
  engagements = data || [];
  return engagements;
}

export async function saveEngagements(updated) {
  await apiPost('/engagements', updated);
  engagements = updated;
}

// ── Engagement data (hosts + notes) ──────────────────────

export async function loadEngagementData(engagementId) {
  return await apiGet(`/engagement/${engagementId}/data`) || { hosts: [], notes: [] };
}

export async function saveEngagementData(engagementId, data) {
  await apiPost(`/engagement/${engagementId}/data`, data);
}

// ── Snapshots ─────────────────────────────────────────────

export async function loadSnapshots(engagementId) {
  return await apiGet(`/engagement/${engagementId}/snapshots`) || [];
}

export async function saveSnapshots(engagementId, snapshots) {
  await apiPost(`/engagement/${engagementId}/snapshots`, snapshots);
}

// ── Factory functions ─────────────────────────────────────

export function newEngagement(overrides = {}) {
  return {
    id:        crypto.randomUUID(),
    name:      '',
    client:    '',
    status:    'active',
    startDate: new Date().toISOString().slice(0, 10),
    notes:     '',
    createdAt: Date.now(),
    ...overrides,
  };
}

export function newHost(overrides = {}) {
  return {
    id:       crypto.randomUUID(),
    ip:       '',
    hostname: '',
    os:       '',
    osFamily: 'unknown', // 'windows' | 'linux' | 'unknown'
    status:   'observed', // 'observed' | 'compromised' | 'unknown'
    notes:    '',
    createdAt: Date.now(),
    ...overrides,
  };
}

export function newSnapshot(overrides = {}) {
  return {
    id:          crypto.randomUUID(),
    hostId:      '',
    commandType: '', // 'netstat' | 'pslist' | 'ipconfig' | 'uname' | 'arp'
    osFamily:    'unknown',
    rawOutput:   '',
    parsed:      null,
    timestamp:   Date.now(),
    ...overrides,
  };
}

export function newNote(overrides = {}) {
  return {
    id:        crypto.randomUUID(),
    hostId:    null, // null = engagement-level
    text:      '',
    timestamp: Date.now(),
    ...overrides,
  };
}
