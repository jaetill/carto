import { DEBUG_MODE } from '../config.js';
import { apiGet, apiPost } from '@carto/api';
import { mockEngagements, mockEngagementData, mockSnapshots, mockImports, MOCK_ENG_ID } from './mockScenario.js';
import { parseNetstat, parsePslist, parseIpconfig, parseUname, parseArp,
         parseNetUser, parseLocalAdmins, parseQwinsta, parsePasswd, parseShadow,
         parseLast, parseWhoamiAll, parseSudoL, parseNetAccounts, parseNetShare,
         parseADDomain, parseADDomainControllers, parseADTrusts, parseADOUs, parseADCS,
         parseEnv, parseSchtasks, parseCrontab, parseServices, parseRoutes,
         parseHostsFile, parseFirewall, parseBannerGrab, parseSuid, parseHistory, parseSoftware } from './parsers.js';

export { apiGet, apiPost };

// LOCAL_MODE: set to true by vite.config.js when building the local bundle.
// In local mode we always use the real storage adapter even if DEBUG_MODE is on.
const LOCAL_MODE = import.meta.env.VITE_LOCAL_MODE;

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
  if (DEBUG_MODE && !LOCAL_MODE) return loadMockScenario();
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
    if (snap.commandType === 'env')                parsed = parseEnv(snap.rawOutput);
    if (snap.commandType === 'schtasks')           parsed = parseSchtasks(snap.rawOutput);
    if (snap.commandType === 'crontab')            parsed = parseCrontab(snap.rawOutput);
    if (snap.commandType === 'services')           parsed = parseServices(snap.rawOutput);
    if (snap.commandType === 'routes')             parsed = parseRoutes(snap.rawOutput);
    if (snap.commandType === 'hostsfile')          parsed = parseHostsFile(snap.rawOutput);
    if (snap.commandType === 'firewall')           parsed = parseFirewall(snap.rawOutput);
    if (snap.commandType === 'bannergrab')         parsed = parseBannerGrab(snap.rawOutput);
    if (snap.commandType === 'suid')               parsed = parseSuid(snap.rawOutput);
    if (snap.commandType === 'history')            parsed = parseHistory(snap.rawOutput);
    if (snap.commandType === 'software')           parsed = parseSoftware(snap.rawOutput);
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
