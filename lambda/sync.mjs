import { s3Get } from './s3.mjs';
import {
  syncEngagement as graphSyncEngagement,
  syncHosts,
  syncSubnets,
  syncConnections,
  syncProcesses,
  syncPorts,
  syncVulnerabilities,
  syncCredentials,
} from './graph.mjs';

// ── Helpers ───────────────────────────────────────────────

function computeSubnetPairs(hosts, snapshots) {
  const pairs = [];
  for (const host of hosts) {
    const allIps = new Set();
    if (host.ip) allIps.add(host.ip);

    const ipcfgSnaps = (snapshots || []).filter(
      s => s.hostId === host.id && s.commandType === 'ipconfig' && s.parsed,
    );
    for (const snap of ipcfgSnaps) {
      for (const iface of snap.parsed.interfaces || []) {
        for (const addr of iface.addresses || []) {
          if (
            addr.ip &&
            addr.family !== 'IPv6' &&
            !addr.ip.startsWith('127.') &&
            !addr.ip.startsWith('169.254.')
          ) {
            allIps.add(addr.ip);
          }
        }
      }
    }

    for (const ip of allIps) {
      const parts = ip.split('.');
      if (parts.length === 4) {
        pairs.push({ cidr: `${parts.slice(0, 3).join('.')}.0/24`, hostId: host.id });
      }
    }
  }
  return pairs;
}

function buildIpToHostId(hosts) {
  const map = {};
  for (const h of hosts) { if (h.ip) map[h.ip] = h.id; }
  return map;
}

function buildHostsByIp(hosts) {
  const map = {};
  for (const h of hosts) { if (h.ip) map[h.ip] = h; }
  return map;
}

function extractConnections(snapshots, ipToHostId) {
  const conns = [];
  for (const snap of snapshots) {
    if (snap.commandType !== 'netstat' || !snap.parsed) continue;
    for (const conn of snap.parsed.connections || []) {
      if (!conn.remoteAddr || conn.remoteAddr === '*' || conn.remoteAddr.startsWith('0.0.0.0')) continue;
      // remoteAddr may be "1.2.3.4:PORT" or just "1.2.3.4"
      const remoteIp = conn.remoteAddr.replace(/:\d+$/, '');
      const dstHostId = ipToHostId[remoteIp];
      if (!dstHostId || dstHostId === snap.hostId) continue;
      conns.push({
        srcHostId: snap.hostId,
        dstHostId,
        port:      conn.remotePort || 0,
        protocol:  conn.proto      || 'TCP',
        state:     conn.state      || '',
        timestamp: snap.timestamp,
      });
    }
  }
  return conns;
}

function extractProcesses(snapshots) {
  const procs = [];
  for (const snap of snapshots) {
    if (snap.commandType !== 'pslist' || !snap.parsed) continue;
    for (const proc of snap.parsed.processes || []) {
      procs.push({
        hostId:     snap.hostId,
        snapshotId: snap.id,
        pid:        proc.pid   || 0,
        name:       proc.name  || '',
        user:       proc.user  || '',
        cmd:        proc.cmd   || '',
        timestamp:  snap.timestamp,
      });
    }
  }
  return procs;
}

function extractPorts(imports, hostsByIp) {
  const ports = [];
  for (const imp of imports) {
    if (imp.importType !== 'nmap' || !imp.parsed) continue;
    for (const scanHost of imp.parsed.hosts || []) {
      const host = hostsByIp[scanHost.ip];
      if (!host) continue;
      for (const port of scanHost.ports || []) {
        ports.push({
          hostId:   host.id,
          number:   port.port     || 0,
          protocol: port.protocol || 'tcp',
          state:    port.state    || '',
          service:  port.service  || '',
          version:  port.version  || '',
        });
      }
    }
  }
  return ports;
}

function extractVulns(imports, hostsByIp) {
  const vulns = [];
  for (const imp of imports) {
    if (imp.importType !== 'metasploit' || !imp.parsed) continue;
    for (const vuln of imp.parsed.vulns || []) {
      const host = hostsByIp[vuln.host];
      if (!host) continue;
      vulns.push({
        hostId:      host.id,
        name:        vuln.name     || '',
        cve:         (vuln.refs || []).find(r => r.startsWith('CVE-')) || '',
        cvss:        vuln.cvss     || 0,
        severity:    vuln.severity || '',
        description: vuln.info     || '',
      });
    }
  }
  return vulns;
}

function extractCredentials(imports) {
  const creds = [];
  for (const imp of imports) {
    if (imp.importType !== 'metasploit' || !imp.parsed) continue;
    for (const cred of imp.parsed.credentials || []) {
      creds.push({
        id:          cred.id          || crypto.randomUUID(),
        username:    cred.username    || '',
        secret:      cred.secret      || '',
        credType:    cred.type        || 'unknown',
        cracked:     cred.cracked     || false,
        servicePort: cred.servicePort || 0,
      });
    }
  }
  return creds;
}

// ── Incremental sync triggers ─────────────────────────────
// Called inline after each save — only syncs what changed.

export async function afterDataSave(engagementId, data) {
  const hosts = data.hosts || [];
  await syncHosts(engagementId, hosts);
  // Compute subnets from primary IPs only (no S3 read needed)
  const pairs = computeSubnetPairs(hosts, []);
  if (pairs.length) await syncSubnets(engagementId, pairs);
}

export async function afterSnapshotSave(engagementId, snapshots, hosts) {
  const ipToHostId = buildIpToHostId(hosts);
  const pairs      = computeSubnetPairs(hosts, snapshots);
  if (pairs.length) await syncSubnets(engagementId, pairs);

  const conns = extractConnections(snapshots, ipToHostId);
  if (conns.length) await syncConnections(conns);

  const procs = extractProcesses(snapshots);
  if (procs.length) await syncProcesses(procs);
}

export async function afterImportSave(engagementId, imports, hosts) {
  const hostsByIp = buildHostsByIp(hosts);

  const ports = extractPorts(imports, hostsByIp);
  if (ports.length) await syncPorts(ports);

  const vulns = extractVulns(imports, hostsByIp);
  if (vulns.length) await syncVulnerabilities(vulns);

  const creds = extractCredentials(imports);
  if (creds.length) await syncCredentials(engagementId, creds);
}

// ── Full re-sync from S3 ──────────────────────────────────

export async function syncEngagementFull(engagementId) {
  const [engagementsData, data, snapshots, imports] = await Promise.all([
    s3Get('engagements.json'),
    s3Get(`engagements/${engagementId}/data.json`),
    s3Get(`engagements/${engagementId}/snapshots.json`),
    s3Get(`engagements/${engagementId}/imports.json`),
  ]);

  const eng = (engagementsData || []).find(e => e.id === engagementId);
  if (eng) await graphSyncEngagement(eng);

  const hosts = data?.hosts || [];
  const snaps = snapshots   || [];
  const imps  = imports     || [];

  await syncHosts(engagementId, hosts);

  const pairs = computeSubnetPairs(hosts, snaps);
  if (pairs.length) await syncSubnets(engagementId, pairs);

  const ipToHostId = buildIpToHostId(hosts);
  const conns      = extractConnections(snaps, ipToHostId);
  if (conns.length) await syncConnections(conns);

  const procs = extractProcesses(snaps);
  if (procs.length) await syncProcesses(procs);

  const hostsByIp = buildHostsByIp(hosts);

  const ports = extractPorts(imps, hostsByIp);
  if (ports.length) await syncPorts(ports);

  const vulns = extractVulns(imps, hostsByIp);
  if (vulns.length) await syncVulnerabilities(vulns);

  const creds = extractCredentials(imps);
  if (creds.length) await syncCredentials(engagementId, creds);
}
