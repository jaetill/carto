import { Auth } from 'aws-amplify';
import { DEBUG_MODE } from '../config.js';
import { mockEngagements, mockEngagementData, mockSnapshots, mockImports, MOCK_ENG_ID } from './mockScenario.js';
import { parseNetstat, parsePslist, parseIpconfig, parseUname, parseArp,
         parseNetUser, parseLocalAdmins, parseQwinsta, parsePasswd, parseShadow,
         parseLast, parseWhoamiAll, parseSudoL, parseNetAccounts, parseNetShare,
         parseADDomain, parseADDomainControllers, parseADTrusts, parseADOUs, parseADCS } from './parsers.js';


const API_URL = 'https://9o7c3668a4.execute-api.us-east-2.amazonaws.com/prod';

// ── API helpers ───────────────────────────────────────────

export async function apiGet(path) {
  const session = await Auth.currentSession();
  const token   = session.getIdToken().getJwtToken();
  const res = await fetch(`${API_URL}${path}`, {
    headers: { Authorization: token },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Fetch failed: ${res.status}`);
  return res.json();
}

export async function apiPost(path, body) {
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
let mockMode = false;

export function isMockMode() { return mockMode; }

export async function loadMockScenario() {
  mockMode = true;
  engagements = mockEngagements;
  return engagements;
}

export async function loadEngagements() {
  if (DEBUG_MODE) return loadMockScenario();
  const data = await apiGet('/engagements');
  engagements = data || [];
  return engagements;
}

export async function saveEngagements(updated) {
  if (mockMode) { engagements = updated; return; }
  await apiPost('/engagements', updated);
  engagements = updated;
}

// ── Engagement data (hosts + notes) ──────────────────────

export async function loadEngagementData(engagementId) {
  if (mockMode) return mockEngagementData[MOCK_ENG_ID] || { hosts: [], notes: [] };
  return await apiGet(`/engagement/${engagementId}/data`) || { hosts: [], notes: [] };
}

export async function saveEngagementData(engagementId, data) {
  if (mockMode) { if (mockEngagementData[MOCK_ENG_ID]) mockEngagementData[MOCK_ENG_ID] = data; return; }
  await apiPost(`/engagement/${engagementId}/data`, data);
}

// ── Snapshots ─────────────────────────────────────────────

function applyParsers(snap) {
  if (snap.parsed !== null && snap.parsed !== undefined) return snap;
  let parsed = null;
  try {
    if (snap.commandType === 'netstat')     parsed = parseNetstat(snap.rawOutput, snap.osFamily);
    if (snap.commandType === 'pslist')      parsed = parsePslist(snap.rawOutput, snap.osFamily);
    if (snap.commandType === 'ipconfig')    parsed = parseIpconfig(snap.rawOutput, snap.osFamily);
    if (snap.commandType === 'uname')       parsed = parseUname(snap.rawOutput);
    if (snap.commandType === 'arp')         parsed = parseArp(snap.rawOutput);
    if (snap.commandType === 'netuser')     parsed = parseNetUser(snap.rawOutput);
    if (snap.commandType === 'localadmins') parsed = parseLocalAdmins(snap.rawOutput);
    if (snap.commandType === 'sessions')    parsed = parseQwinsta(snap.rawOutput);
    if (snap.commandType === 'passwd')      parsed = parsePasswd(snap.rawOutput);
    if (snap.commandType === 'shadow')      parsed = parseShadow(snap.rawOutput);
    if (snap.commandType === 'lastlog')     parsed = parseLast(snap.rawOutput);
    if (snap.commandType === 'whoami')      parsed = parseWhoamiAll(snap.rawOutput);
    if (snap.commandType === 'sudol')       parsed = parseSudoL(snap.rawOutput);
    if (snap.commandType === 'netaccounts')        parsed = parseNetAccounts(snap.rawOutput);
    if (snap.commandType === 'netshare')           parsed = parseNetShare(snap.rawOutput);
    if (snap.commandType === 'addomain')           parsed = parseADDomain(snap.rawOutput);
    if (snap.commandType === 'addomaincontrollers') parsed = parseADDomainControllers(snap.rawOutput);
    if (snap.commandType === 'adtrusts')           parsed = parseADTrusts(snap.rawOutput);
    if (snap.commandType === 'adous')              parsed = parseADOUs(snap.rawOutput);
    if (snap.commandType === 'adcs')               parsed = parseADCS(snap.rawOutput);
  } catch (e) { console.warn('[carto] Parse error:', e); }
  return { ...snap, parsed };
}

export async function loadSnapshots(engagementId) {
  if (mockMode) {
    const snaps = (mockSnapshots[MOCK_ENG_ID] || []).map(applyParsers);
    mockSnapshots[MOCK_ENG_ID] = snaps;
    return snaps;
  }
  const raw = await apiGet(`/engagement/${engagementId}/snapshots`) || [];
  const needsBackfill = raw.some(s => s.parsed === null || s.parsed === undefined);
  if (!needsBackfill) return raw;
  const enriched = raw.map(applyParsers);
  // Save back in the background — don't block the UI
  apiPost(`/engagement/${engagementId}/snapshots`, enriched).catch(e => console.warn('[carto] Backfill save failed:', e));
  return enriched;
}

export async function saveSnapshots(engagementId, snapshots) {
  if (mockMode) { if (mockSnapshots[MOCK_ENG_ID]) mockSnapshots[MOCK_ENG_ID] = snapshots; return; }
  await apiPost(`/engagement/${engagementId}/snapshots`, snapshots);
}

// ── Imports ───────────────────────────────────────────────
// Engagement-level file imports (Nmap, Metasploit, SharpHound, etc.)
// Stored at engagements/{id}/imports.json via Lambda route /engagement/{id}/imports

export async function loadImports(engagementId) {
  if (mockMode) return mockImports[engagementId] || [];
  return await apiGet(`/engagement/${engagementId}/imports`) || [];
}

export async function saveImports(engagementId, imports) {
  if (mockMode) return;
  await apiPost(`/engagement/${engagementId}/imports`, imports);
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

export function newImport(overrides = {}) {
  return {
    id:         crypto.randomUUID(),
    importType: '', // 'nmap' | 'metasploit' | 'sharphound' | 'nuclei' | 'nessus' | 'ghostwriter'
    fileName:   '',
    importedAt: Date.now(),
    parsed:     null,
    summary:    {}, // type-specific quick stats for display
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
