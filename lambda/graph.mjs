// graph.mjs — Neo4j Cypher operations for carto engagement topology
// Manages: hosts, subnets, connections, processes, ports, vulnerabilities,
//          credentials, users, sessions, shares, attack paths
// Env vars: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD, NEO4J_DATABASE
// Called by: sync.mjs (after data saves) and index.mjs (graph/paths routes)

import neo4j from 'neo4j-driver';

// ── Driver ────────────────────────────────────────────────

let _driver = null;

function getDriver() {
  if (!_driver) {
    _driver = neo4j.driver(
      process.env.NEO4J_URI,
      neo4j.auth.basic(process.env.NEO4J_USERNAME, process.env.NEO4J_PASSWORD),
    );
  }
  return _driver;
}

async function run(cypher, params = {}) {
  const session = getDriver().session({ database: process.env.NEO4J_DATABASE });
  try {
    const result = await session.run(cypher, params);
    return result.records;
  } finally {
    await session.close();
  }
}

// neo4j-driver returns Integer objects for numeric properties — normalize to plain JS
function toInt(val) {
  if (val === null || val === undefined) return null;
  if (typeof val === 'object' && typeof val.toNumber === 'function') return val.toNumber();
  return val;
}

function nodeProps(rec, key) {
  const node = rec.get(key);
  if (!node) return null;
  const p = { ...node.properties };
  // Normalize all integer values
  for (const k of Object.keys(p)) p[k] = toInt(p[k]) ?? p[k];
  return p;
}

// ── Engagement ────────────────────────────────────────────

export async function syncEngagement(eng) {
  await run(
    `MERGE (e:Engagement {id: $id})
     SET e.name = $name, e.client = $client, e.status = $status, e.startDate = $startDate`,
    { id: eng.id, name: eng.name || '', client: eng.client || '', status: eng.status || 'active', startDate: eng.startDate || '' },
  );
}

// ── Hosts ─────────────────────────────────────────────────

export async function syncHosts(engagementId, hosts) {
  if (!hosts.length) return;

  // Upsert Engagement node (in case it doesn't exist yet)
  await run(`MERGE (e:Engagement {id: $engagementId})`, { engagementId });

  // Batch upsert Host nodes
  await run(
    `UNWIND $hosts AS h
     MERGE (host:Host {id: h.id})
     SET host.engagementId = $engagementId,
         host.ip           = h.ip,
         host.hostname     = h.hostname,
         host.os           = h.os,
         host.osFamily     = h.osFamily,
         host.status       = h.status`,
    {
      engagementId,
      hosts: hosts.map(h => ({
        id:       h.id,
        ip:       h.ip       || '',
        hostname: h.hostname || '',
        os:       h.os       || '',
        osFamily: h.osFamily || 'unknown',
        status:   h.status   || 'observed',
      })),
    },
  );

  // Wire HAS_HOST relationships
  await run(
    `MATCH (e:Engagement {id: $engagementId}), (h:Host {engagementId: $engagementId})
     MERGE (e)-[:HAS_HOST]->(h)`,
    { engagementId },
  );
}

// ── Subnets ───────────────────────────────────────────────
// pairs: [{ cidr, hostId }]

export async function syncSubnets(engagementId, pairs) {
  if (!pairs.length) return;

  await run(
    `UNWIND $pairs AS p
     MERGE (s:Subnet {engagementId: $engagementId, cidr: p.cidr})
     WITH s, p
     MATCH (e:Engagement {id: $engagementId})
     MERGE (e)-[:HAS_SUBNET]->(s)
     WITH s, p
     MATCH (h:Host {id: p.hostId})
     MERGE (h)-[:IN_SUBNET]->(s)`,
    { engagementId, pairs },
  );
}

// ── Connections (netstat → CONNECTS_TO) ───────────────────
// conns: [{ srcHostId, dstHostId, port, protocol, state, timestamp }]

export async function syncConnections(conns) {
  if (!conns.length) return;

  await run(
    `UNWIND $conns AS c
     MATCH (src:Host {id: c.srcHostId}), (dst:Host {id: c.dstHostId})
     MERGE (src)-[r:CONNECTS_TO {port: c.port, protocol: c.protocol}]->(dst)
     SET r.state    = c.state,
         r.lastSeen = c.timestamp`,
    { conns },
  );
}

// ── Processes (pslist → RUNS) ─────────────────────────────
// procs: [{ hostId, snapshotId, pid, name, user, cmd, timestamp }]

export async function syncProcesses(procs) {
  if (!procs.length) return;

  await run(
    `UNWIND $procs AS p
     MATCH (h:Host {id: p.hostId})
     MERGE (proc:Process {hostId: p.hostId, snapshotId: p.snapshotId, pid: p.pid})
     SET proc.name      = p.name,
         proc.user      = p.user,
         proc.cmd       = p.cmd,
         proc.timestamp = p.timestamp
     MERGE (h)-[:RUNS]->(proc)`,
    { procs },
  );
}

// ── Ports (nmap → EXPOSES) ────────────────────────────────
// ports: [{ hostId, number, protocol, state, service, version }]

export async function syncPorts(ports) {
  if (!ports.length) return;

  await run(
    `UNWIND $ports AS p
     MATCH (h:Host {id: p.hostId})
     MERGE (port:Port {hostId: p.hostId, number: p.number, protocol: p.protocol})
     SET port.state   = p.state,
         port.service = p.service,
         port.version = p.version
     MERGE (h)-[:EXPOSES]->(port)`,
    { ports },
  );
}

// ── Vulnerabilities (metasploit → HAS_VULNERABILITY) ──────
// vulns: [{ hostId, name, cve, cvss, severity, description }]

export async function syncVulnerabilities(vulns) {
  if (!vulns.length) return;

  await run(
    `UNWIND $vulns AS v
     MATCH (h:Host {id: v.hostId})
     MERGE (vuln:Vulnerability {hostId: v.hostId, name: v.name})
     SET vuln.cve         = v.cve,
         vuln.cvss        = v.cvss,
         vuln.severity    = v.severity,
         vuln.description = v.description
     MERGE (h)-[:HAS_VULNERABILITY]->(vuln)`,
    { vulns },
  );
}

// ── Credentials (metasploit → HAS_CREDENTIAL) ─────────────
// creds: [{ id, engagementId, username, secret, credType, cracked, servicePort }]

export async function syncCredentials(engagementId, creds) {
  if (!creds.length) return;

  await run(
    `UNWIND $creds AS c
     MERGE (cred:Credential {id: c.id})
     SET cred.engagementId = $engagementId,
         cred.username     = c.username,
         cred.secret       = c.secret,
         cred.credType     = c.credType,
         cred.cracked      = c.cracked,
         cred.servicePort  = c.servicePort
     WITH cred
     MATCH (e:Engagement {id: $engagementId})
     MERGE (e)-[:HAS_CREDENTIAL]->(cred)`,
    { engagementId, creds },
  );
}

// ── Users ─────────────────────────────────────────────────
// users: [{ id, engagementId, username, domain, isAdmin }]

export async function syncUsers(engagementId, users) {
  if (!users.length) return;
  await run(
    `UNWIND $users AS u
     MERGE (user:User {id: u.id})
     SET user.engagementId = $engagementId,
         user.username     = u.username,
         user.domain       = u.domain,
         user.isAdmin      = u.isAdmin
     WITH user
     MATCH (e:Engagement {id: $engagementId})
     MERGE (e)-[:HAS_USER]->(user)`,
    { engagementId, users },
  );
}

// ── Local admin links (User → IS_LOCAL_ADMIN → Host) ──────
// links: [{ userId, hostId }]

export async function syncLocalAdmins(links) {
  if (!links.length) return;
  await run(
    `UNWIND $links AS l
     MATCH (u:User {id: l.userId}), (h:Host {id: l.hostId})
     MERGE (u)-[:IS_LOCAL_ADMIN]->(h)`,
    { links },
  );
}

// ── Session links (User → HAS_SESSION → Host) ─────────────
// links: [{ userId, hostId, fromIp, timestamp }]

export async function syncSessions(links) {
  if (!links.length) return;
  await run(
    `UNWIND $links AS l
     MATCH (u:User {id: l.userId}), (h:Host {id: l.hostId})
     MERGE (u)-[r:HAS_SESSION {userId: l.userId, hostId: l.hostId}]->(h)
     SET r.fromIp    = l.fromIp,
         r.timestamp = l.timestamp`,
    { links },
  );
}

// ── Shares (Host → EXPOSES_SHARE → Share) ─────────────────
// shares: [{ hostId, name, path, remark, isAdmin }]

export async function syncShares(shares) {
  if (!shares.length) return;
  await run(
    `UNWIND $shares AS s
     MATCH (h:Host {id: s.hostId})
     MERGE (share:Share {hostId: s.hostId, name: s.name})
     SET share.path    = s.path,
         share.remark  = s.remark,
         share.isAdmin = s.isAdmin
     MERGE (h)-[:EXPOSES_SHARE]->(share)`,
    { shares },
  );
}

// ── Attack Paths ──────────────────────────────────────────

export async function addAttackPath(engagementId, { edgeId, fromHostId, toHostId, technique, notes, timestamp }) {
  await run(
    `MATCH (src:Host {id: $fromHostId}), (dst:Host {id: $toHostId})
     MERGE (src)-[r:ATTACK_PATH {edgeId: $edgeId}]->(dst)
     SET r.engagementId = $engagementId,
         r.technique    = $technique,
         r.notes        = $notes,
         r.timestamp    = $timestamp`,
    {
      edgeId,
      fromHostId,
      toHostId,
      engagementId,
      technique: technique || '',
      notes:     notes     || '',
      timestamp: timestamp || Date.now(),
    },
  );
}

export async function removeAttackPath(edgeId) {
  await run(
    `MATCH ()-[r:ATTACK_PATH {edgeId: $edgeId}]->() DELETE r`,
    { edgeId },
  );
}

// ── Query: Topology ───────────────────────────────────────

export async function getTopology(engagementId) {
  const [hostRecs, connRecs, subnetRecs, userRecs, userEdgeRecs] = await Promise.all([
    run(
      `MATCH (e:Engagement {id: $engagementId})-[:HAS_HOST]->(h:Host)
       OPTIONAL MATCH (h)-[:IN_SUBNET]->(s:Subnet)
       OPTIONAL MATCH (h)-[:EXPOSES]->(port:Port {state: 'open'})
       RETURN h.id AS id, h.ip AS ip, h.hostname AS hostname,
              h.os AS os, h.osFamily AS osFamily, h.status AS status,
              collect(DISTINCT s.cidr) AS subnets,
              count(DISTINCT port) AS openPortCount`,
      { engagementId },
    ),
    run(
      `MATCH (e:Engagement {id: $engagementId})-[:HAS_HOST]->(src:Host)
             -[r:CONNECTS_TO]->(dst:Host)<-[:HAS_HOST]-(e)
       RETURN src.id AS source, dst.id AS target,
              r.port AS port, r.protocol AS protocol, r.state AS state`,
      { engagementId },
    ),
    run(
      `MATCH (e:Engagement {id: $engagementId})-[:HAS_SUBNET]->(s:Subnet)
       RETURN s.cidr AS cidr`,
      { engagementId },
    ),
    run(
      `MATCH (e:Engagement {id: $engagementId})-[:HAS_USER]->(u:User)
       RETURN u.id AS id, u.username AS username,
              u.domain AS domain, u.isAdmin AS isAdmin`,
      { engagementId },
    ),
    run(
      `MATCH (e:Engagement {id: $engagementId})-[:HAS_HOST]->(h:Host)
       MATCH (u:User {engagementId: $engagementId})-[r:IS_LOCAL_ADMIN|HAS_SESSION]->(h)
       RETURN u.id AS userId, h.id AS hostId, type(r) AS relType,
              r.fromIp AS fromIp`,
      { engagementId },
    ),
  ]);

  return {
    nodes: hostRecs.map(r => ({
      id:            r.get('id'),
      ip:            r.get('ip'),
      hostname:      r.get('hostname'),
      os:            r.get('os'),
      osFamily:      r.get('osFamily'),
      status:        r.get('status'),
      subnets:       r.get('subnets'),
      openPortCount: toInt(r.get('openPortCount')),
    })),
    edges: connRecs.map(r => ({
      source:   r.get('source'),
      target:   r.get('target'),
      port:     toInt(r.get('port')),
      protocol: r.get('protocol'),
      state:    r.get('state'),
    })),
    subnets: subnetRecs.map(r => r.get('cidr')),
    users: userRecs.map(r => ({
      id:       r.get('id'),
      username: r.get('username'),
      domain:   r.get('domain'),
      isAdmin:  r.get('isAdmin'),
    })),
    userEdges: userEdgeRecs.map(r => ({
      userId:  r.get('userId'),
      hostId:  r.get('hostId'),
      type:    r.get('relType'),   // 'IS_LOCAL_ADMIN' | 'HAS_SESSION'
      fromIp:  r.get('fromIp'),
    })),
  };
}

// ── Query: Attack Paths ───────────────────────────────────

export async function getAttackPaths(engagementId) {
  const records = await run(
    `MATCH (e:Engagement {id: $engagementId})-[:HAS_HOST]->(src:Host)
           -[r:ATTACK_PATH {engagementId: $engagementId}]->(dst:Host)
     RETURN r.edgeId        AS edgeId,
            src.id          AS source,
            dst.id          AS target,
            src.hostname    AS srcHostname,
            src.ip          AS srcIp,
            dst.hostname    AS dstHostname,
            dst.ip          AS dstIp,
            r.technique     AS technique,
            r.notes         AS notes,
            r.timestamp     AS timestamp
     ORDER BY r.timestamp`,
    { engagementId },
  );

  return records.map(r => ({
    edgeId:    r.get('edgeId'),
    source:    r.get('source'),
    target:    r.get('target'),
    srcLabel:  r.get('srcHostname') || r.get('srcIp'),
    dstLabel:  r.get('dstHostname') || r.get('dstIp'),
    technique: r.get('technique'),
    notes:     r.get('notes'),
    timestamp: toInt(r.get('timestamp')),
  }));
}
