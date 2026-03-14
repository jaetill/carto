// Mock scenario: "CORP Internal Pentest" — 30-day engagement, 15 hosts
// Used when DEBUG_MODE is enabled or "Load Mock Scenario" is triggered

const ENG_ID     = 'mock-eng-0001';
const START_TS   = Date.now() - (30 * 24 * 60 * 60 * 1000);
const START_DATE = new Date(START_TS).toISOString().slice(0, 10);

// ── Nmap port helpers ─────────────────────────────────────

function port(portid, protocol, state, name, product = null, version = null) {
  return { port: portid, protocol, state, service: { name, product, version, extrainfo: null, ostype: null } };
}

function winOS(name = 'Windows Server 2019') {
  return { name, accuracy: 94, family: 'Windows', generation: null, type: 'general purpose' };
}

function linOS(name = 'Linux 5.X') {
  return { name, accuracy: 89, family: 'Linux', generation: '5.X', type: 'general purpose' };
}

const H = {
  DC01:    'mock-host-dc01',
  DC02:    'mock-host-dc02',
  FS01:    'mock-host-fs01',
  APP01:   'mock-host-app01',
  SQL01:   'mock-host-sql01',
  WEB01:   'mock-host-web01',
  WEB02:   'mock-host-web02',
  DB01:    'mock-host-db01',
  JENKINS: 'mock-host-jenkins',
  VPN:     'mock-host-vpn',
  JSMITH:  'mock-host-jsmith',
  MTHOMAS: 'mock-host-mthomas',
  CBROWN:  'mock-host-cbrown',
  RLEE:    'mock-host-rlee',
  KIOSK01: 'mock-host-kiosk01',
};

function daysAgo(d, h = 0) { return Date.now() - (d * 86400000) + (h * 3600000); }

function netstatWin(ip) {
  return `Active Connections\n\n  Proto  Local Address          Foreign Address        State\n  TCP    ${ip}:445        10.10.1.5:49720        ESTABLISHED\n  TCP    ${ip}:3389       10.10.3.55:52841       ESTABLISHED\n  TCP    ${ip}:49668      13.107.42.14:443       ESTABLISHED\n  TCP    0.0.0.0:135      0.0.0.0:0              LISTENING\n  TCP    0.0.0.0:445      0.0.0.0:0              LISTENING`;
}
function netstatLin(ip) {
  return `Proto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 ${ip}:22               10.10.3.55:54210        ESTABLISHED\ntcp        0      0 ${ip}:443              10.10.1.20:49330        ESTABLISHED\ntcp        0      0 ${ip}:8080             10.10.2.30:39421        ESTABLISHED`;
}
function pslistWin() {
  return `Name                          PID   PPID\nlsass.exe                    776    648\nsvchost.exe                  896    648\nMsMpEng.exe                 2340    648\npowershell.exe              4812   4780\ncmd.exe                     5220   4812`;
}
function ipconfigWin(ip, shortname) {
  return `Host Name: ${shortname}\nPrimary Dns Suffix: CORP.LOCAL\nIPv4 Address: ${ip}\nSubnet Mask: 255.255.255.0\nDefault Gateway: 10.10.1.1`;
}
function uname(shortname, kernel) {
  return `Linux ${shortname} ${kernel} #1 SMP x86_64 GNU/Linux`;
}

function netUserList(hostname, users) {
  const lines = [];
  for (let i = 0; i < users.length; i += 3)
    lines.push(users.slice(i, i + 3).map(u => u.padEnd(24)).join(''));
  return `User accounts for \\\\${hostname}\n\n-------------------------------------------------------------------------------\n${lines.join('\n')}\nThe command completed successfully.`;
}

function localAdmins(members) {
  return `Alias name     administrators\nComment        Administrators have complete and unrestricted access to the computer/domain\n\nMembers\n\n-------------------------------------------------------------------------------\n${members.join('\n')}\nThe command completed successfully.`;
}

function qwinsta(sessions) {
  const header = ' SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE';
  const rows = sessions.map(s =>
    ` ${(s[0] || '').padEnd(18)}${(s[1] || '').padEnd(25)}${String(s[2]).padEnd(4)}${s[3]}`
  );
  return [header, ...rows].join('\n');
}

function etcPasswd(users) {
  return users.map(u => `${u[0]}:x:${u[1]}:${u[1]}:${u[2]}:/home/${u[0]}:${u[3]}`).join('\n');
}

function etcShadow(users) {
  return users.map(u => `${u[0]}:${u[1]}:19400:0:99999:7:::`).join('\n');
}

function lastLog(entries) {
  return entries.map(e => `${e[0].padEnd(9)}${e[1].padEnd(13)}${(e[2] || '').padEnd(17)}Mon Mar 10 ${e[3]}  (${e[4]})`).join('\n') +
    '\nreboot   system boot  5.4.0-182-generic Mon Mar 10 08:00\nwtmp begins Mon Feb 10 00:00:00 2025';
}

function sudoL(username, hostname, entries) {
  const entryLines = entries.map(e => `    (${e[0]}) ${e[1] ? 'NOPASSWD: ' : ''}${e[2]}`).join('\n');
  return `Matching Defaults entries for ${username} on ${hostname}:\n    env_reset, mail_badpass, secure_path=/usr/local/sbin\n\nUser ${username} may run the following commands on ${hostname}:\n${entryLines}`;
}

function netAccounts(role, minLen, maxAge, lockout) {
  return `Force user logoff how long after time expires?:       Never\nMinimum password age (days):                          1\nMaximum password age (days):                          ${maxAge}\nMinimum password length:                              ${minLen}\nLength of password history maintained:                24\nLockout threshold:                                    ${lockout}\nLockout duration (minutes):                           30\nLockout observation window (minutes):                 30\nComputer role:                                        ${role}\nThe command completed successfully.`;
}

function netShare(shares) {
  const header = 'Share name   Resource                        Remark\n\n-------------------------------------------------------------------------------';
  const rows = shares.map(s => `${s[0].padEnd(13)}${(s[1] || '').padEnd(32)}${s[2] || ''}`);
  return `${header}\n${rows.join('\n')}\nThe command completed successfully.`;
}

function whoamiAll(domain, username, sid, groups, privs) {
  const groupRows = groups.map(g =>
    `${g[0].padEnd(41)}${g[1].padEnd(17)}${g[2].padEnd(13)}Mandatory group, Enabled by default, Enabled group`
  ).join('\n');
  const privRows = privs.map(p =>
    `${p[0].padEnd(30)}${p[1].padEnd(37)}${p[2]}`
  ).join('\n');
  return `USER INFORMATION\n----------------\n\nUser Name           SID\n=================== ==============================================\n${domain}\\${username}         ${sid}\n\n\nGROUP INFORMATION\n-----------------\n\nGroup Name                               Type             SID          Attributes\n======================================== ================ ============ ==================================================\n${groupRows}\n\n\nPRIVILEGES INFORMATION\n----------------------\n\nPrivilege Name                Description                          State\n============================= ==================================== ========\n${privRows}`;
}

function snap(id, hostId, commandType, osFamily, rawOutput, daysAgoVal, hoursOffset = 0) {
  return { id, hostId, commandType, osFamily, rawOutput, parsed: null, timestamp: daysAgo(daysAgoVal, hoursOffset) };
}

export const MOCK_ENG_ID = ENG_ID;

// ── Mock attack path edges ─────────────────────────────────
// Mirrors the attack chain told in engagement notes 1–6.

export const mockAttackPaths = [
  {
    edgeId:    'mock-path-01',
    fromHostId: H.JSMITH,
    toHostId:   H.FS01,
    technique:  'NTLM relay',
    notes:      'Stolen NTLM hash from phishing victim. Relayed to FS01 — confirmed write access to Finance share.',
    timestamp:  daysAgo(27),
  },
  {
    edgeId:    'mock-path-02',
    fromHostId: H.FS01,
    toHostId:   H.DC01,
    technique:  'Kerberoast → DCSync',
    notes:      'SVC_BACKUP hash cracked offline (weak password). Used to escalate to Domain Admin. DCSync dumped all hashes.',
    timestamp:  daysAgo(21),
  },
  {
    edgeId:    'mock-path-03',
    fromHostId: H.DC01,
    toHostId:   H.JENKINS,
    technique:  'Pass-the-hash (DA)',
    notes:      'Pivoted to Jenkins using DA credentials. Found plaintext AWS keys in build pipeline env vars.',
    timestamp:  daysAgo(18),
  },
  {
    edgeId:    'mock-path-04',
    fromHostId: H.JENKINS,
    toHostId:   H.WEB01,
    technique:  'Pipeline abuse (CVE-2024-23897)',
    notes:      'Deployed reverse shell via Jenkins deployment job. WEB01 compromised.',
    timestamp:  daysAgo(14),
  },
  {
    edgeId:    'mock-path-05',
    fromHostId: H.DC01,
    toHostId:   H.FS01,
    technique:  'Golden ticket',
    notes:      'Persistence via golden ticket after krbtgt hash dump. Re-access FS01 without credentials.',
    timestamp:  daysAgo(5),
  },
];

export const mockEngagements = [
  { id: ENG_ID, name: 'CORP Internal Pentest', client: 'Acme Corporation', status: 'active', startDate: START_DATE, notes: '', createdAt: START_TS },
];

export const mockEngagementData = {
  [ENG_ID]: {
    hosts: [
      { id: H.DC01,    ip: '10.10.1.5',  hostname: 'DC01.CORP.LOCAL',     os: 'Windows Server 2019', osFamily: 'windows', status: 'compromised', notes: '', createdAt: START_TS },
      { id: H.DC02,    ip: '10.10.1.6',  hostname: 'DC02.CORP.LOCAL',     os: 'Windows Server 2019', osFamily: 'windows', status: 'observed',    notes: '', createdAt: START_TS + 3600000 },
      { id: H.FS01,    ip: '10.10.1.20', hostname: 'FS01.CORP.LOCAL',     os: 'Windows Server 2016', osFamily: 'windows', status: 'compromised', notes: '', createdAt: START_TS + 7200000 },
      { id: H.APP01,   ip: '10.10.1.30', hostname: 'APPSVR01.CORP.LOCAL', os: 'Windows Server 2022', osFamily: 'windows', status: 'observed',    notes: '', createdAt: START_TS + 10800000 },
      { id: H.SQL01,   ip: '10.10.1.40', hostname: 'SQLDB01.CORP.LOCAL',  os: 'Windows Server 2019', osFamily: 'windows', status: 'observed',    notes: '', createdAt: START_TS + 14400000 },
      { id: H.WEB01,   ip: '10.10.2.10', hostname: 'web01.corp.local',    os: 'Ubuntu 22.04 LTS',    osFamily: 'linux',   status: 'compromised', notes: '', createdAt: START_TS + 18000000 },
      { id: H.WEB02,   ip: '10.10.2.11', hostname: 'web02.corp.local',    os: 'Ubuntu 22.04 LTS',    osFamily: 'linux',   status: 'observed',    notes: '', createdAt: START_TS + 21600000 },
      { id: H.DB01,    ip: '10.10.2.20', hostname: 'db01.corp.local',     os: 'CentOS 7.9',          osFamily: 'linux',   status: 'observed',    notes: '', createdAt: START_TS + 25200000 },
      { id: H.JENKINS, ip: '10.10.2.30', hostname: 'jenkins.corp.local',  os: 'Ubuntu 20.04 LTS',    osFamily: 'linux',   status: 'compromised', notes: '', createdAt: START_TS + 28800000 },
      { id: H.VPN,     ip: '10.10.2.40', hostname: 'vpn.corp.local',      os: 'Debian 11',           osFamily: 'linux',   status: 'observed',    notes: '', createdAt: START_TS + 32400000 },
      { id: H.JSMITH,  ip: '10.10.3.55', hostname: 'WS-JSMITH',           os: 'Windows 11 Pro 22H2', osFamily: 'windows', status: 'compromised', notes: '', createdAt: START_TS + 36000000 },
      { id: H.MTHOMAS, ip: '10.10.3.62', hostname: 'WS-MTHOMAS',          os: 'Windows 10 Pro 21H2', osFamily: 'windows', status: 'observed',    notes: '', createdAt: START_TS + 39600000 },
      { id: H.CBROWN,  ip: '10.10.3.71', hostname: 'WS-CBROWN',           os: 'Windows 11 Pro 22H2', osFamily: 'windows', status: 'observed',    notes: '', createdAt: START_TS + 43200000 },
      { id: H.RLEE,    ip: '10.10.3.80', hostname: 'WS-RLEE',             os: 'Windows 10 Pro 22H2', osFamily: 'windows', status: 'unknown',     notes: '', createdAt: START_TS + 46800000 },
      { id: H.KIOSK01, ip: '10.10.4.5',  hostname: 'KIOSK01.CORP.LOCAL',  os: 'Windows 10 LTSC',     osFamily: 'windows', status: 'unknown',     notes: '', createdAt: START_TS + 50400000 },
    ],
    notes: [
      { id: 'mock-note-01', hostId: null, text: 'Initial access via phishing email targeting J. Smith (jsmith@corp.local). Payload delivered through macro-enabled Excel attachment.', timestamp: daysAgo(29) },
      { id: 'mock-note-02', hostId: null, text: 'Lateral movement from WS-JSMITH to FS01 using stolen NTLM hash. Confirmed write access to \\\\FS01\\Finance share.', timestamp: daysAgo(27) },
      { id: 'mock-note-03', hostId: null, text: 'Kerberoasting attempt against DC01 — recovered 3 service account hashes. SVC_BACKUP cracked offline (weak password).', timestamp: daysAgo(24) },
      { id: 'mock-note-04', hostId: null, text: 'Escalated to Domain Admin via SVC_BACKUP credentials. DC01 fully compromised. DCSync performed — all hashes dumped.', timestamp: daysAgo(21) },
      { id: 'mock-note-05', hostId: null, text: 'Pivoted to Jenkins CI/CD server (10.10.2.30). Found plaintext AWS credentials in build pipeline env vars.', timestamp: daysAgo(18) },
      { id: 'mock-note-06', hostId: null, text: 'Web01 compromised via Jenkins pipeline abuse — deployed reverse shell via deployment job.', timestamp: daysAgo(14) },
      { id: 'mock-note-07', hostId: null, text: 'Blue team appears to have noticed anomalous DC traffic around day 20. No containment action observed yet. Proceeding.', timestamp: daysAgo(10) },
      { id: 'mock-note-08', hostId: null, text: 'Persistence established on DC01 via scheduled task and golden ticket. Recommend client rotate all krbtgt hashes as remediation.', timestamp: daysAgo(5) },
      { id: 'mock-note-09', hostId: null, text: 'Scope clarification from client — KIOSK01 and WS-RLEE are out of scope. Do not interact further.', timestamp: daysAgo(2) },
      { id: 'mock-note-10', hostId: null, text: 'Engagement day 30. Beginning report drafting. Need to verify all C2 implants removed before close-out call.', timestamp: daysAgo(0) },
    ],
  },
};

// ── Mock imports ──────────────────────────────────────────

const NMAP_PARSED = {
  scanArgs:   '-sV -O -T4 10.10.1.0/24 10.10.2.0/24 10.10.3.0/24 10.10.4.0/24',
  scanStart:  daysAgo(28),
  scanEnd:    daysAgo(28) + 840000,
  hostsTotal: 254 * 4,
  hostsUp:    15,
  hosts: [
    {
      ip: '10.10.1.5', mac: '00:50:56:A1:11:01', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'DC01.CORP.LOCAL', type: 'PTR' }],
      os: winOS('Windows Server 2019 Standard 17763'),
      ports: [
        port(53,   'tcp', 'open', 'domain',      'Microsoft DNS',    '10.0.17763'),
        port(88,   'tcp', 'open', 'kerberos-sec','Microsoft Kerberos'),
        port(135,  'tcp', 'open', 'msrpc',       'Microsoft RPC'),
        port(139,  'tcp', 'open', 'netbios-ssn', 'Microsoft netbios-ssn'),
        port(389,  'tcp', 'open', 'ldap',        'Microsoft AD LDAP'),
        port(445,  'tcp', 'open', 'microsoft-ds','Windows Server 2019 SMB'),
        port(636,  'tcp', 'open', 'tcpwrapped'),
        port(3268, 'tcp', 'open', 'ldap',        'Microsoft AD GC'),
        port(3389, 'tcp', 'open', 'ms-wbt-server','Microsoft RDP'),
      ],
      scripts: [{ id: 'smb-os-discovery', output: 'OS: Windows Server 2019; Computer name: DC01; Domain: CORP.LOCAL' }],
    },
    {
      ip: '10.10.1.6', mac: '00:50:56:A1:11:02', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'DC02.CORP.LOCAL', type: 'PTR' }],
      os: winOS('Windows Server 2019 Standard 17763'),
      ports: [
        port(53,   'tcp', 'open', 'domain',       'Microsoft DNS'),
        port(88,   'tcp', 'open', 'kerberos-sec', 'Microsoft Kerberos'),
        port(389,  'tcp', 'open', 'ldap',         'Microsoft AD LDAP'),
        port(445,  'tcp', 'open', 'microsoft-ds', 'Windows Server 2019 SMB'),
        port(3268, 'tcp', 'open', 'ldap',         'Microsoft AD GC'),
        port(3389, 'tcp', 'open', 'ms-wbt-server','Microsoft RDP'),
      ],
      scripts: [],
    },
    {
      ip: '10.10.1.20', mac: '00:50:56:A1:11:03', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'FS01.CORP.LOCAL', type: 'PTR' }],
      os: winOS('Windows Server 2016 Standard 14393'),
      ports: [
        port(135,  'tcp', 'open', 'msrpc',        'Microsoft RPC'),
        port(139,  'tcp', 'open', 'netbios-ssn'),
        port(445,  'tcp', 'open', 'microsoft-ds', 'Windows Server 2016 SMB'),
        port(3389, 'tcp', 'open', 'ms-wbt-server','Microsoft RDP'),
      ],
      scripts: [{ id: 'smb-security-mode', output: 'message_signing: disabled (DANGEROUS, but default)' }],
    },
    {
      ip: '10.10.1.30', mac: '00:50:56:A1:11:04', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'APPSVR01.CORP.LOCAL', type: 'PTR' }],
      os: winOS('Windows Server 2022 Standard 20348'),
      ports: [
        port(80,   'tcp', 'open', 'http',         'Microsoft IIS httpd', '10.0'),
        port(443,  'tcp', 'open', 'ssl/http',     'Microsoft IIS httpd', '10.0'),
        port(3389, 'tcp', 'open', 'ms-wbt-server','Microsoft RDP'),
        port(8080, 'tcp', 'open', 'http',         'Apache Tomcat',       '9.0.75'),
      ],
      scripts: [],
    },
    {
      ip: '10.10.1.40', mac: '00:50:56:A1:11:05', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'SQLDB01.CORP.LOCAL', type: 'PTR' }],
      os: winOS('Windows Server 2019 Standard 17763'),
      ports: [
        port(1433, 'tcp', 'open', 'ms-sql-s',     'Microsoft SQL Server', '2019'),
        port(3389, 'tcp', 'open', 'ms-wbt-server','Microsoft RDP'),
      ],
      scripts: [{ id: 'ms-sql-info', output: 'SQL Server 2019 (RTM-CU19) 15.0.4298.1 (X64)' }],
    },
    {
      ip: '10.10.2.10', mac: '00:50:56:A1:22:01', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'web01.corp.local', type: 'PTR' }],
      os: linOS('Linux 5.15.X'),
      ports: [
        port(22,  'tcp', 'open', 'ssh',   'OpenSSH', '8.9p1'),
        port(80,  'tcp', 'open', 'http',  'nginx',   '1.23.4'),
        port(443, 'tcp', 'open', 'https', 'nginx',   '1.23.4'),
      ],
      scripts: [],
    },
    {
      ip: '10.10.2.11', mac: '00:50:56:A1:22:02', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'web02.corp.local', type: 'PTR' }],
      os: linOS('Linux 5.15.X'),
      ports: [
        port(22,  'tcp', 'open', 'ssh',   'OpenSSH', '8.9p1'),
        port(80,  'tcp', 'open', 'http',  'nginx',   '1.23.4'),
        port(443, 'tcp', 'open', 'https', 'nginx',   '1.23.4'),
      ],
      scripts: [],
    },
    {
      ip: '10.10.2.20', mac: '00:50:56:A1:22:03', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'db01.corp.local', type: 'PTR' }],
      os: linOS('Linux 3.10.X'),
      ports: [
        port(22,   'tcp', 'open', 'ssh',   'OpenSSH', '7.4'),
        port(3306, 'tcp', 'open', 'mysql', 'MySQL',   '5.7.44'),
      ],
      scripts: [],
    },
    {
      ip: '10.10.2.30', mac: '00:50:56:A1:22:04', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'jenkins.corp.local', type: 'PTR' }],
      os: linOS('Linux 5.4.X'),
      ports: [
        port(22,   'tcp', 'open', 'ssh',  'OpenSSH',       '8.2p1'),
        port(8080, 'tcp', 'open', 'http', 'Jetty httpd',   '9.4'),
        port(8443, 'tcp', 'open', 'ssl/https', 'Jetty httpd', '9.4'),
      ],
      scripts: [{ id: 'http-title', output: 'Dashboard [Jenkins]' }],
    },
    {
      ip: '10.10.2.40', mac: '00:50:56:A1:22:05', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'vpn.corp.local', type: 'PTR' }],
      os: linOS('Linux 5.10.X'),
      ports: [
        port(22,   'tcp', 'open',     'ssh',         'OpenSSH',  '9.2p1'),
        port(443,  'tcp', 'open',     'ssl/https'),
        port(1194, 'udp', 'open',     'openvpn',     'OpenVPN'),
      ],
      scripts: [],
    },
    {
      ip: '10.10.3.55', mac: '00:50:56:A1:33:01', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'WS-JSMITH', type: 'PTR' }],
      os: winOS('Windows 11 Pro 22621'),
      ports: [
        port(135,  'tcp', 'open', 'msrpc',        'Microsoft RPC'),
        port(139,  'tcp', 'open', 'netbios-ssn'),
        port(445,  'tcp', 'open', 'microsoft-ds', 'Windows 11 SMB'),
        port(3389, 'tcp', 'open', 'ms-wbt-server','Microsoft RDP'),
      ],
      scripts: [],
    },
    {
      ip: '10.10.3.62', mac: '00:50:56:A1:33:02', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'WS-MTHOMAS', type: 'PTR' }],
      os: winOS('Windows 10 Pro 19044'),
      ports: [
        port(135,  'tcp', 'open', 'msrpc',        'Microsoft RPC'),
        port(445,  'tcp', 'open', 'microsoft-ds', 'Windows 10 SMB'),
        port(3389, 'tcp', 'open', 'ms-wbt-server','Microsoft RDP'),
      ],
      scripts: [],
    },
    {
      ip: '10.10.3.71', mac: '00:50:56:A1:33:03', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'WS-CBROWN', type: 'PTR' }],
      os: winOS('Windows 11 Pro 22621'),
      ports: [
        port(135,  'tcp', 'open', 'msrpc',        'Microsoft RPC'),
        port(445,  'tcp', 'open', 'microsoft-ds', 'Windows 11 SMB'),
      ],
      scripts: [],
    },
    {
      ip: '10.10.3.80', mac: '00:50:56:A1:33:04', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'WS-RLEE', type: 'PTR' }],
      os: winOS('Windows 10 Pro 19045'),
      ports: [
        port(135,  'tcp', 'open', 'msrpc',        'Microsoft RPC'),
        port(445,  'tcp', 'open', 'microsoft-ds', 'Windows 10 SMB'),
        port(3389, 'tcp', 'open', 'ms-wbt-server','Microsoft RDP'),
      ],
      scripts: [],
    },
    {
      ip: '10.10.4.5', mac: '00:50:56:A1:44:01', vendor: 'VMware', status: 'up',
      hostnames: [{ name: 'KIOSK01.CORP.LOCAL', type: 'PTR' }],
      os: winOS('Windows 10 Enterprise LTSC 2019'),
      ports: [
        port(135,  'tcp', 'open', 'msrpc',        'Microsoft RPC'),
        port(3389, 'tcp', 'open', 'ms-wbt-server','Microsoft RDP'),
      ],
      scripts: [],
    },
  ],
};

const METASPLOIT_PARSED = {
  hosts: [
    { ip: '10.10.1.5',  mac: '00:50:56:A1:11:01', hostname: 'DC01',    state: 'alive', purpose: 'server',     arch: 'x64', os: { name: 'Windows Server 2019 Standard', flavor: 'Standard', sp: 'SP0' } },
    { ip: '10.10.1.20', mac: '00:50:56:A1:11:03', hostname: 'FS01',    state: 'alive', purpose: 'server',     arch: 'x64', os: { name: 'Windows Server 2016 Standard', flavor: 'Standard', sp: 'SP0' } },
    { ip: '10.10.2.30', mac: '00:50:56:A1:22:04', hostname: 'jenkins', state: 'alive', purpose: 'server',     arch: 'x64', os: { name: 'Ubuntu 20.04.6 LTS',           flavor: null,       sp: null  } },
    { ip: '10.10.2.10', mac: '00:50:56:A1:22:01', hostname: 'web01',   state: 'alive', purpose: 'server',     arch: 'x64', os: { name: 'Ubuntu 22.04.3 LTS',           flavor: null,       sp: null  } },
    { ip: '10.10.3.55', mac: '00:50:56:A1:33:01', hostname: 'JSMITH',  state: 'alive', purpose: 'workstation', arch: 'x64', os: { name: 'Windows 11 Pro',              flavor: 'Pro',      sp: 'SP0' } },
  ],
  services: [
    { hostIp: '10.10.1.5',  port: 445,  protocol: 'tcp', state: 'open', name: 'microsoft-ds', banner: 'Windows Server 2019' },
    { hostIp: '10.10.1.5',  port: 3389, protocol: 'tcp', state: 'open', name: 'ms-wbt-server', banner: null },
    { hostIp: '10.10.1.5',  port: 88,   protocol: 'tcp', state: 'open', name: 'kerberos-sec',  banner: null },
    { hostIp: '10.10.1.5',  port: 389,  protocol: 'tcp', state: 'open', name: 'ldap',          banner: 'CORP.LOCAL' },
    { hostIp: '10.10.1.20', port: 445,  protocol: 'tcp', state: 'open', name: 'microsoft-ds',  banner: 'Windows Server 2016' },
    { hostIp: '10.10.1.20', port: 3389, protocol: 'tcp', state: 'open', name: 'ms-wbt-server', banner: null },
    { hostIp: '10.10.2.30', port: 8080, protocol: 'tcp', state: 'open', name: 'http',          banner: 'Jenkins 2.401.3' },
    { hostIp: '10.10.2.30', port: 22,   protocol: 'tcp', state: 'open', name: 'ssh',           banner: 'OpenSSH 8.2p1' },
    { hostIp: '10.10.2.10', port: 80,   protocol: 'tcp', state: 'open', name: 'http',          banner: 'nginx 1.23.4' },
    { hostIp: '10.10.2.10', port: 22,   protocol: 'tcp', state: 'open', name: 'ssh',           banner: 'OpenSSH 8.9p1' },
    { hostIp: '10.10.3.55', port: 445,  protocol: 'tcp', state: 'open', name: 'microsoft-ds',  banner: 'Windows 11' },
    { hostIp: '10.10.3.55', port: 3389, protocol: 'tcp', state: 'open', name: 'ms-wbt-server', banner: null },
  ],
  vulns: [
    { hostIp: '10.10.1.5',  name: 'MS17-010 EternalBlue SMB Remote Code Execution', refs: ['CVE-2017-0144', 'CVE-2017-0145', 'MSB-MS17-010'] },
    { hostIp: '10.10.1.20', name: 'MS17-010 EternalBlue SMB Remote Code Execution', refs: ['CVE-2017-0144', 'MSB-MS17-010'] },
    { hostIp: '10.10.1.20', name: 'SMB Signing Disabled',                            refs: ['CWE-326'] },
    { hostIp: '10.10.2.30', name: 'Jenkins Unauthenticated Script Console RCE',      refs: ['CVE-2024-23897'] },
    { hostIp: '10.10.2.10', name: 'Nginx Misconfiguration — Directory Listing',      refs: [] },
  ],
  credentials: [
    { username: 'Administrator', secret: 'aad3b435b51404eeaad3b435b51404ee:97f2592347d8fbe42be381726ff9ea83', secretType: 'ntlm_hash',  hostIp: '10.10.1.5',  port: 445, protocol: 'tcp' },
    { username: 'SVC_BACKUP',    secret: 'aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef', secretType: 'ntlm_hash',  hostIp: '10.10.1.5',  port: 445, protocol: 'tcp' },
    { username: 'jsmith',        secret: 'Welcome1!',                                                          secretType: 'password',    hostIp: '10.10.3.55', port: 445, protocol: 'tcp' },
    { username: 'jenkins',       secret: 'jenkins',                                                            secretType: 'password',    hostIp: '10.10.2.30', port: 8080, protocol: 'tcp' },
  ],
  sessions: [
    { hostIp: '10.10.1.5',  sessionType: 'meterpreter', platform: 'windows/x64', exploit: 'exploit/windows/smb/ms17_010_eternalblue', openedAt: new Date(daysAgo(21)).toISOString(), closedAt: null },
    { hostIp: '10.10.2.30', sessionType: 'meterpreter', platform: 'linux/x64',   exploit: 'exploit/multi/http/jenkins_script_console',  openedAt: new Date(daysAgo(18)).toISOString(), closedAt: new Date(daysAgo(17)).toISOString() },
  ],
};

// ── Mock Nessus scan results ──────────────────────────────

const NESSUS_PARSED = {
  policyName: 'Internal Network Scan',
  hosts: [
    {
      ip: '10.10.1.5', hostname: 'DC01.corp.local', os: 'Windows Server 2019 Standard', mac: '00:50:56:A1:11:01',
      scanStart: daysAgo(10), scanEnd: daysAgo(10) + 3600,
      findings: [
        { port: 445, protocol: 'tcp', severity: 3, pluginId: '57608', pluginName: 'SMB Signing Not Required', synopsis: 'Signing is not required on the remote SMB server.', description: 'The remote SMB server does not enforce message signing. An unauthenticated attacker can exploit this to conduct man-in-the-middle attacks.', solution: 'Enforce message signing in the host configuration.', cvssScore: 5.0, cvss3Score: 7.5, cveIds: [], exploitAvailable: false, pluginOutput: null },
        { port: 3389, protocol: 'tcp', severity: 2, pluginId: '30218', pluginName: 'Terminal Services Encryption Level Is Medium or Low', synopsis: 'The remote Terminal Services is not configured to use high-level encryption.', description: null, solution: 'Change RDP encryption level to High.', cvssScore: 4.3, cvss3Score: null, cveIds: [], exploitAvailable: false, pluginOutput: null },
        { port: 0, protocol: 'tcp', severity: 1, pluginId: '11936', pluginName: 'OS Identification', synopsis: null, description: null, solution: null, cvssScore: null, cvss3Score: null, cveIds: [], exploitAvailable: false, pluginOutput: 'The remote host is running Microsoft Windows Server 2019 Standard' },
      ],
    },
    {
      ip: '10.10.2.10', hostname: 'WEB01.corp.local', os: 'Linux Kernel 5.15', mac: '00:50:56:A1:22:01',
      scanStart: daysAgo(10), scanEnd: daysAgo(10) + 3600,
      findings: [
        { port: 80, protocol: 'tcp', severity: 4, pluginId: '90317', pluginName: 'Apache Struts CVE-2017-5638 RCE', synopsis: 'The remote host is running a vulnerable version of Apache Struts.', description: 'A remote code execution vulnerability exists in Apache Struts due to improper handling of the Content-Type header.', solution: 'Upgrade to Apache Struts 2.3.32 or 2.5.10.1 or later.', cvssScore: 10.0, cvss3Score: 10.0, cveIds: ['CVE-2017-5638'], exploitAvailable: true, pluginOutput: 'Struts version: 2.3.5' },
        { port: 443, protocol: 'tcp', severity: 3, pluginId: '51192', pluginName: 'SSL Certificate Cannot Be Trusted', synopsis: 'The SSL certificate for this service cannot be trusted.', description: null, solution: 'Purchase or generate a proper SSL certificate for the service.', cvssScore: 6.4, cvss3Score: 7.5, cveIds: [], exploitAvailable: false, pluginOutput: null },
        { port: 80, protocol: 'tcp', severity: 1, pluginId: '10107', pluginName: 'HTTP Server Type and Version', synopsis: null, description: null, solution: null, cvssScore: null, cvss3Score: null, cveIds: [], exploitAvailable: false, pluginOutput: 'Apache/2.4.41 (Ubuntu)' },
      ],
    },
    {
      ip: '10.10.2.30', hostname: 'JENKINS.corp.local', os: 'Linux Kernel 5.4', mac: null,
      scanStart: daysAgo(10), scanEnd: daysAgo(10) + 3600,
      findings: [
        { port: 8080, protocol: 'tcp', severity: 4, pluginId: '97999', pluginName: 'Jenkins Unauthenticated RCE (CVE-2017-1000353)', synopsis: 'Unauthenticated remote code execution in Jenkins.', description: 'Jenkins before 2.89 and LTS before 2.73.3 allow unauthenticated remote code execution via a deserialization attack.', solution: 'Upgrade Jenkins to 2.89 or 2.73.3 (LTS) or later.', cvssScore: 9.8, cvss3Score: 9.8, cveIds: ['CVE-2017-1000353'], exploitAvailable: true, pluginOutput: 'Detected Jenkins 2.60.3' },
        { port: 8080, protocol: 'tcp', severity: 2, pluginId: '42873', pluginName: 'SSL/TLS Protocol Initialization Vector Implementation Information Disclosure Vulnerability (BEAST)', synopsis: null, description: null, solution: 'Configure SSL/TLS to use TLS 1.1 or later.', cvssScore: 4.3, cvss3Score: null, cveIds: ['CVE-2011-3389'], exploitAvailable: false, pluginOutput: null },
      ],
    },
  ],
};

// ── Mock Nuclei scan results ──────────────────────────────

const NUCLEI_PARSED = {
  findings: [
    { templateId: 'CVE-2021-44228', name: 'Apache Log4j RCE (Log4Shell)', severity: 'critical', tags: ['cve', 'rce', 'log4j'], cveIds: ['CVE-2021-44228'], cvssScore: 10.0, host: 'https://10.10.2.10', ip: '10.10.2.10', matchedAt: 'https://10.10.2.10:443/api/v1/auth', timestamp: daysAgo(8), extractedResults: [], curlCommand: null },
    { templateId: 'CVE-2021-44228', name: 'Apache Log4j RCE (Log4Shell)', severity: 'critical', tags: ['cve', 'rce', 'log4j'], cveIds: ['CVE-2021-44228'], cvssScore: 10.0, host: 'http://10.10.2.30:8080', ip: '10.10.2.30', matchedAt: 'http://10.10.2.30:8080/j_acegi_security_check', timestamp: daysAgo(8), extractedResults: [], curlCommand: null },
    { templateId: 'CVE-2022-22965', name: 'Spring4Shell Remote Code Execution', severity: 'critical', tags: ['cve', 'rce', 'spring'], cveIds: ['CVE-2022-22965'], cvssScore: 9.8, host: 'https://10.10.2.10', ip: '10.10.2.10', matchedAt: 'https://10.10.2.10/app/login', timestamp: daysAgo(8), extractedResults: [], curlCommand: null },
    { templateId: 'CVE-2021-42013', name: 'Apache HTTP Server Path Traversal', severity: 'high', tags: ['cve', 'lfi', 'apache'], cveIds: ['CVE-2021-42013'], cvssScore: 9.8, host: 'http://10.10.2.11', ip: '10.10.2.11', matchedAt: 'http://10.10.2.11/cgi-bin/.%2e/.%2e/etc/passwd', timestamp: daysAgo(8), extractedResults: ['root:x:0:0:root:/root:/bin/bash'], curlCommand: null },
    { templateId: 'default-login-jenkins', name: 'Jenkins Default Admin Credentials', severity: 'high', tags: ['default-login', 'jenkins'], cveIds: [], cvssScore: null, host: 'http://10.10.2.30:8080', ip: '10.10.2.30', matchedAt: 'http://10.10.2.30:8080/login', timestamp: daysAgo(8), extractedResults: ['admin:admin'], curlCommand: null },
    { templateId: 'exposed-panels-jenkins', name: 'Jenkins Dashboard Exposed', severity: 'medium', tags: ['exposure', 'jenkins'], cveIds: [], cvssScore: null, host: 'http://10.10.2.30:8080', ip: '10.10.2.30', matchedAt: 'http://10.10.2.30:8080/', timestamp: daysAgo(8), extractedResults: [], curlCommand: null },
    { templateId: 'http-missing-security-headers', name: 'Missing Security Headers', severity: 'info', tags: ['headers', 'generic'], cveIds: [], cvssScore: null, host: 'https://10.10.2.10', ip: '10.10.2.10', matchedAt: 'https://10.10.2.10/', timestamp: daysAgo(8), extractedResults: [], curlCommand: null },
  ],
};

// ── Mock SharpHound collection results ───────────────────

const SHARPHOUND_PARSED = {
  collectedAt: daysAgo(15),
  domain:      'CORP.LOCAL',
  version:     5,
  users: [
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1103', name: 'JSMITH@CORP.LOCAL',        domain: 'CORP.LOCAL', enabled: true,  lastLogon: daysAgo(1),  pwdLastSet: daysAgo(45),  hasSPN: false, adminCount: false, dontReqPreauth: false, pwdNeverExpires: false, unconstrainedDelegation: false, trustedToAuth: false, sensitive: false, allowedToDelegate: [], memberOf: ['S-1-5-21-3623811015-3361044348-30300820-1104'] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1105', name: 'MTHOMAS@CORP.LOCAL',       domain: 'CORP.LOCAL', enabled: true,  lastLogon: daysAgo(3),  pwdLastSet: daysAgo(90),  hasSPN: false, adminCount: false, dontReqPreauth: false, pwdNeverExpires: false, unconstrainedDelegation: false, trustedToAuth: false, sensitive: false, allowedToDelegate: [], memberOf: [] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1106', name: 'CBROWN@CORP.LOCAL',        domain: 'CORP.LOCAL', enabled: true,  lastLogon: daysAgo(7),  pwdLastSet: daysAgo(30),  hasSPN: false, adminCount: false, dontReqPreauth: true,  pwdNeverExpires: false, unconstrainedDelegation: false, trustedToAuth: false, sensitive: false, allowedToDelegate: [], memberOf: [] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-500',  name: 'ADMINISTRATOR@CORP.LOCAL', domain: 'CORP.LOCAL', enabled: true,  lastLogon: daysAgo(2),  pwdLastSet: daysAgo(180), hasSPN: false, adminCount: true,  dontReqPreauth: false, pwdNeverExpires: true,  unconstrainedDelegation: false, trustedToAuth: false, sensitive: true,  allowedToDelegate: [], memberOf: ['S-1-5-21-3623811015-3361044348-30300820-512'] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1108', name: 'SVC_JENKINS@CORP.LOCAL',   domain: 'CORP.LOCAL', enabled: true,  lastLogon: daysAgo(1),  pwdLastSet: daysAgo(365), hasSPN: true,  adminCount: false, dontReqPreauth: false, pwdNeverExpires: true,  unconstrainedDelegation: false, trustedToAuth: false, sensitive: false, allowedToDelegate: [], memberOf: [] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1109', name: 'SVC_SQL@CORP.LOCAL',       domain: 'CORP.LOCAL', enabled: true,  lastLogon: daysAgo(1),  pwdLastSet: daysAgo(365), hasSPN: true,  adminCount: false, dontReqPreauth: false, pwdNeverExpires: true,  unconstrainedDelegation: false, trustedToAuth: true,  sensitive: false, allowedToDelegate: ['S-1-5-21-3623811015-3361044348-30300820-1001$'], memberOf: [] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1110', name: 'SVC_BACKUP@CORP.LOCAL',    domain: 'CORP.LOCAL', enabled: true,  lastLogon: daysAgo(14), pwdLastSet: daysAgo(730), hasSPN: true,  adminCount: false, dontReqPreauth: false, pwdNeverExpires: true,  unconstrainedDelegation: false, trustedToAuth: false, sensitive: false, allowedToDelegate: [], memberOf: ['S-1-5-21-3623811015-3361044348-30300820-512'] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1107', name: 'RLEE@CORP.LOCAL',          domain: 'CORP.LOCAL', enabled: false, lastLogon: daysAgo(60), pwdLastSet: daysAgo(200), hasSPN: false, adminCount: false, dontReqPreauth: true,  pwdNeverExpires: false, unconstrainedDelegation: false, trustedToAuth: false, sensitive: false, allowedToDelegate: [], memberOf: [] },
  ],
  computers: [
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1001$', name: 'DC01.CORP.LOCAL',      domain: 'CORP.LOCAL', enabled: true,  os: 'Windows Server 2019 Standard', isDC: true,  hasLAPS: false, unconstrainedDelegation: true,  trustedToAuth: false, localAdmins: ['S-1-5-21-3623811015-3361044348-30300820-512'], sessions: [] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1002$', name: 'DC02.CORP.LOCAL',      domain: 'CORP.LOCAL', enabled: true,  os: 'Windows Server 2019 Standard', isDC: true,  hasLAPS: false, unconstrainedDelegation: true,  trustedToAuth: false, localAdmins: ['S-1-5-21-3623811015-3361044348-30300820-512'], sessions: [] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1010$', name: 'FS01.CORP.LOCAL',      domain: 'CORP.LOCAL', enabled: true,  os: 'Windows Server 2016 Standard', isDC: false, hasLAPS: true,  unconstrainedDelegation: false, trustedToAuth: false, localAdmins: ['S-1-5-21-3623811015-3361044348-30300820-1103'], sessions: [{ userId: 'S-1-5-21-3623811015-3361044348-30300820-1103', isAdmin: false, source: 'session' }] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1020$', name: 'WS-JSMITH.CORP.LOCAL', domain: 'CORP.LOCAL', enabled: true,  os: 'Windows 10 Enterprise',        isDC: false, hasLAPS: true,  unconstrainedDelegation: false, trustedToAuth: false, localAdmins: ['S-1-5-21-3623811015-3361044348-30300820-1103'], sessions: [{ userId: 'S-1-5-21-3623811015-3361044348-30300820-1103', isAdmin: true, source: 'privileged' }] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1030$', name: 'APP01.CORP.LOCAL',     domain: 'CORP.LOCAL', enabled: true,  os: 'Windows Server 2016 Standard', isDC: false, hasLAPS: false, unconstrainedDelegation: false, trustedToAuth: true,  localAdmins: [], sessions: [] },
  ],
  groups: [
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-512',  name: 'DOMAIN ADMINS@CORP.LOCAL',      domain: 'CORP.LOCAL', members: [{ objectId: 'S-1-5-21-3623811015-3361044348-30300820-500', objectType: 'User' }, { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1110', objectType: 'User' }] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-513',  name: 'DOMAIN USERS@CORP.LOCAL',       domain: 'CORP.LOCAL', members: [{ objectId: 'S-1-5-21-3623811015-3361044348-30300820-1103', objectType: 'User' }, { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1105', objectType: 'User' }, { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1106', objectType: 'User' }] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-1104', name: 'IT ADMINS@CORP.LOCAL',          domain: 'CORP.LOCAL', members: [{ objectId: 'S-1-5-21-3623811015-3361044348-30300820-1103', objectType: 'User' }] },
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820-519',  name: 'ENTERPRISE ADMINS@CORP.LOCAL',  domain: 'CORP.LOCAL', members: [{ objectId: 'S-1-5-21-3623811015-3361044348-30300820-500', objectType: 'User' }] },
  ],
  domains: [
    { objectId: 'S-1-5-21-3623811015-3361044348-30300820', name: 'CORP.LOCAL', trusts: [{ targetDomain: 'CHILD.CORP.LOCAL', trustType: 'ParentChild', trustDirection: 'Bidirectional', isTransitive: true }] },
  ],
  gpos: [
    { objectId: '{31B2F340-016D-11D2-945F-00C04FB984F9}', name: 'DEFAULT DOMAIN POLICY',             guid: '31B2F340-016D-11D2-945F-00C04FB984F9', domain: 'CORP.LOCAL' },
    { objectId: '{6AC1786C-016F-11D2-945F-00C04FB984F9}', name: 'DEFAULT DOMAIN CONTROLLERS POLICY', guid: '6AC1786C-016F-11D2-945F-00C04FB984F9', domain: 'CORP.LOCAL' },
    { objectId: '{AA4BE5D5-1234-5678-ABCD-1234567890AB}', name: 'SERVER HARDENING POLICY',           guid: 'AA4BE5D5-1234-5678-ABCD-1234567890AB', domain: 'CORP.LOCAL' },
  ],
  aces: [
    { principalSid: 'S-1-5-21-3623811015-3361044348-30300820-1110', principalType: 'User',  rightName: 'DCSync',     objectSid: 'S-1-5-21-3623811015-3361044348-30300820', objectType: 'Domain',   isInherited: false },
    { principalSid: 'S-1-5-21-3623811015-3361044348-30300820-1103', principalType: 'User',  rightName: 'GenericAll', objectSid: 'S-1-5-21-3623811015-3361044348-30300820-1010$', objectType: 'Computer', isInherited: false },
  ],
  cas: [
    { objectId: 'corp-DC01-CA', name: 'corp-DC01-CA', domain: 'CORP.LOCAL', dnsName: 'DC01.corp.local', certTemplates: ['User', 'Machine', 'WebServer', 'DomainController', 'SubCA'] },
  ],
  certTemplates: [
    { objectId: 'CORP-CT-001', name: 'CORPWEBSERVER@CORP.LOCAL',   displayName: 'Corp Web Server',    domain: 'CORP.LOCAL', validityPeriod: '1 year',  renewalPeriod: '6 weeks', schemaVersion: 2, requiresManagerApproval: false, enrolleesSuppliesSubject: true,  authenticationEnabled: true,  subjectAltRequireUpn: false, subjectAltRequireDns: true,  noSecurityExtension: false, ekus: ['1.3.6.1.5.5.7.3.1'], esc1: true  },
    { objectId: 'CORP-CT-002', name: 'USER@CORP.LOCAL',            displayName: 'User',               domain: 'CORP.LOCAL', validityPeriod: '1 year',  renewalPeriod: '6 weeks', schemaVersion: 1, requiresManagerApproval: false, enrolleesSuppliesSubject: false, authenticationEnabled: true,  subjectAltRequireUpn: true,  subjectAltRequireDns: false, noSecurityExtension: false, ekus: ['1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2'], esc1: false },
    { objectId: 'CORP-CT-003', name: 'MACHINE@CORP.LOCAL',         displayName: 'Machine',            domain: 'CORP.LOCAL', validityPeriod: '1 year',  renewalPeriod: '6 weeks', schemaVersion: 1, requiresManagerApproval: false, enrolleesSuppliesSubject: false, authenticationEnabled: true,  subjectAltRequireUpn: false, subjectAltRequireDns: true,  noSecurityExtension: false, ekus: ['1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2'], esc1: false },
    { objectId: 'CORP-CT-004', name: 'WEBSERVER@CORP.LOCAL',       displayName: 'Web Server',         domain: 'CORP.LOCAL', validityPeriod: '2 years', renewalPeriod: '6 weeks', schemaVersion: 1, requiresManagerApproval: true,  enrolleesSuppliesSubject: true,  authenticationEnabled: false, subjectAltRequireUpn: false, subjectAltRequireDns: true,  noSecurityExtension: false, ekus: ['1.3.6.1.5.5.7.3.1'], esc1: false },
    { objectId: 'CORP-CT-005', name: 'DOMAINCONTROLLER@CORP.LOCAL',displayName: 'Domain Controller',  domain: 'CORP.LOCAL', validityPeriod: '1 year',  renewalPeriod: '6 weeks', schemaVersion: 1, requiresManagerApproval: false, enrolleesSuppliesSubject: false, authenticationEnabled: true,  subjectAltRequireUpn: false, subjectAltRequireDns: true,  noSecurityExtension: false, ekus: ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'], esc1: false },
    { objectId: 'CORP-CT-006', name: 'SMARTCARDLOGON@CORP.LOCAL',  displayName: 'Smartcard Logon',    domain: 'CORP.LOCAL', validityPeriod: '1 year',  renewalPeriod: '6 weeks', schemaVersion: 1, requiresManagerApproval: true,  enrolleesSuppliesSubject: false, authenticationEnabled: true,  subjectAltRequireUpn: true,  subjectAltRequireDns: false, noSecurityExtension: false, ekus: ['1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2'], esc1: false },
  ],
  ous: [
    { objectId: 'OU=Domain Controllers,DC=corp,DC=local', name: 'Domain Controllers', domain: 'CORP.LOCAL', guid: '2B9A51B1-1111-1111-1111-000000000001', properties: {} },
    { objectId: 'OU=Servers,DC=corp,DC=local',            name: 'Servers',            domain: 'CORP.LOCAL', guid: '2B9A51B1-1111-1111-1111-000000000002', properties: {} },
    { objectId: 'OU=Workstations,DC=corp,DC=local',       name: 'Workstations',       domain: 'CORP.LOCAL', guid: '2B9A51B1-1111-1111-1111-000000000003', properties: {} },
    { objectId: 'OU=Users,DC=corp,DC=local',              name: 'Users',              domain: 'CORP.LOCAL', guid: '2B9A51B1-1111-1111-1111-000000000004', properties: {} },
    { objectId: 'OU=Service Accounts,DC=corp,DC=local',   name: 'Service Accounts',   domain: 'CORP.LOCAL', guid: '2B9A51B1-1111-1111-1111-000000000005', properties: {} },
    { objectId: 'OU=IT,OU=Users,DC=corp,DC=local',        name: 'IT',                 domain: 'CORP.LOCAL', guid: '2B9A51B1-1111-1111-1111-000000000006', properties: {} },
  ],
};

export const mockImports = {
  [ENG_ID]: [
    {
      id:         'mock-import-nmap-01',
      importType: 'nmap',
      fileName:   'corp_full_sweep_day1.xml',
      importedAt: daysAgo(28),
      parsed:     NMAP_PARSED,
      summary: {
        hostsUp:    15,
        hostsTotal: 1016,
        openPorts:  NMAP_PARSED.hosts.reduce((n, h) => n + h.ports.filter(p => p.state === 'open').length, 0),
      },
    },
    {
      id:         'mock-import-msf-01',
      importType: 'metasploit',
      fileName:   'corp_pentest_workspace.xml',
      importedAt: daysAgo(5),
      parsed:     METASPLOIT_PARSED,
      summary: {
        hostCount:    METASPLOIT_PARSED.hosts.length,
        serviceCount: METASPLOIT_PARSED.services.length,
        vulnCount:    METASPLOIT_PARSED.vulns.length,
        credCount:    METASPLOIT_PARSED.credentials.length,
        sessionCount: METASPLOIT_PARSED.sessions.length,
      },
    },
    {
      id:         'mock-import-nessus-01',
      importType: 'nessus',
      fileName:   'corp_vuln_scan_day10.nessus',
      importedAt: daysAgo(10),
      parsed:     NESSUS_PARSED,
      summary: {
        hostCount:     NESSUS_PARSED.hosts.length,
        findingCount:  NESSUS_PARSED.hosts.reduce((n, h) => n + h.findings.length, 0),
        criticalCount: NESSUS_PARSED.hosts.reduce((n, h) => n + h.findings.filter(f => f.severity === 4).length, 0),
        highCount:     NESSUS_PARSED.hosts.reduce((n, h) => n + h.findings.filter(f => f.severity === 3).length, 0),
      },
    },
    {
      id:         'mock-import-nuclei-01',
      importType: 'nuclei',
      fileName:   'corp_web_nuclei_day8.jsonl',
      importedAt: daysAgo(8),
      parsed:     NUCLEI_PARSED,
      summary: {
        findingCount:  NUCLEI_PARSED.findings.length,
        criticalCount: NUCLEI_PARSED.findings.filter(f => f.severity === 'critical').length,
        highCount:     NUCLEI_PARSED.findings.filter(f => f.severity === 'high').length,
      },
    },
    {
      id:         'mock-import-sharphound-01',
      importType: 'sharphound',
      fileName:   'CORP_BloodHound_20240315.zip',
      importedAt: daysAgo(15),
      parsed:     SHARPHOUND_PARSED,
      summary: {
        computerCount:      SHARPHOUND_PARSED.computers.length,
        userCount:          SHARPHOUND_PARSED.users.length,
        groupCount:         SHARPHOUND_PARSED.groups.length,
        domainCount:        SHARPHOUND_PARSED.domains.length,
        certTemplateCount:  SHARPHOUND_PARSED.certTemplates.length,
      },
    },
  ],
};

export const mockSnapshots = {
  [ENG_ID]: [
    snap('mock-s-dc01-1',  H.DC01,    'netstat',  'windows', netstatWin('10.10.1.5'),              28),
    snap('mock-s-dc01-2',  H.DC01,    'pslist',   'windows', pslistWin(),                           28, 1),
    snap('mock-s-dc01-3',  H.DC01,    'ipconfig', 'windows', ipconfigWin('10.10.1.5', 'DC01'),      21, 2),
    snap('mock-s-dc01-4',  H.DC01,    'netstat',  'windows', netstatWin('10.10.1.5'),              14),
    snap('mock-s-dc01-5',  H.DC01,    'pslist',   'windows', pslistWin(),                           7),
    snap('mock-s-dc01-6',  H.DC01,    'netstat',  'windows', netstatWin('10.10.1.5'),              1),
    snap('mock-s-fs01-1',  H.FS01,    'netstat',  'windows', netstatWin('10.10.1.20'),             26),
    snap('mock-s-fs01-2',  H.FS01,    'ipconfig', 'windows', ipconfigWin('10.10.1.20', 'FS01'),    26, 1),
    snap('mock-s-fs01-3',  H.FS01,    'pslist',   'windows', pslistWin(),                          20),
    snap('mock-s-jen-1',   H.JENKINS, 'uname',    'linux',   uname('jenkins', '5.4.0-169-generic'), 18),
    snap('mock-s-jen-2',   H.JENKINS, 'netstat',  'linux',   netstatLin('10.10.2.30'),             18, 1),
    snap('mock-s-jen-3',   H.JENKINS, 'pslist',   'linux',   'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.0  22516  1524 ?        Ss   08:00   0:00 /sbin/init\njenkins   1842  2.1  8.4 3234568 345000 ?      Sl   08:01  45:12 java -jar /usr/share/jenkins/jenkins.war\nroot      4201  0.0  0.0  72296  6428 ?        Ss   08:00   0:00 /usr/sbin/sshd -D\njsmith    5512  0.0  0.0  22232  5124 pts/0    Ss   09:15   0:00 -bash\nroot      6001  0.1  0.0  14648  5212 ?        S    10:00   0:01 python3 /tmp/.x', 17),
    snap('mock-s-jen-4',   H.JENKINS, 'netstat',  'linux',   netstatLin('10.10.2.30'),             10),
    snap('mock-s-web01-1', H.WEB01,   'uname',    'linux',   uname('web01', '5.15.0-91-generic'),  14),
    snap('mock-s-web01-2', H.WEB01,   'netstat',  'linux',   netstatLin('10.10.2.10'),             14, 1),
    snap('mock-s-web01-3', H.WEB01,   'netstat',  'linux',   netstatLin('10.10.2.10'),              7),
    snap('mock-s-jsm-1',   H.JSMITH,  'ipconfig', 'windows', ipconfigWin('10.10.3.55', 'WS-JSMITH'), 29),
    snap('mock-s-jsm-2',   H.JSMITH,  'netstat',  'windows', netstatWin('10.10.3.55'),             29, 1),
    snap('mock-s-jsm-3',   H.JSMITH,  'pslist',   'windows', pslistWin(),                          29, 2),
    snap('mock-s-jsm-4',   H.JSMITH,  'netstat',  'windows', netstatWin('10.10.3.55'),             20),
    snap('mock-s-dc02-1',  H.DC02,    'ipconfig', 'windows', ipconfigWin('10.10.1.6', 'DC02'),     22),
    snap('mock-s-dc02-2',  H.DC02,    'netstat',  'windows', netstatWin('10.10.1.6'),               8),
    snap('mock-s-web02-1', H.WEB02,   'uname',    'linux',   uname('web02', '5.15.0-91-generic'),  15),
    snap('mock-s-web02-2', H.WEB02,   'netstat',  'linux',   netstatLin('10.10.2.11'),              4),
    snap('mock-s-db01-1',  H.DB01,    'uname',    'linux',   uname('db01', '3.10.0-1160.el7.x86_64'), 12),
    snap('mock-s-db01-2',  H.DB01,    'netstat',  'linux',   netstatLin('10.10.2.20'),              3),

    // ── net user (DC01 — domain user listing) ────────────
    snap('mock-snap-netuser-dc01', H.DC01, 'netuser', 'windows',
      netUserList('DC01', ['Administrator','Guest','krbtgt','jsmith','mthomas','cbrown','rlee','svc_backup','svc_web']),
      20),

    // ── net localgroup administrators (FS01 — svc_backup is local admin) ──
    snap('mock-snap-localadmins-fs01', H.FS01, 'localadmins', 'windows',
      localAdmins(['Administrator', 'CORP\\Domain Admins', 'CORP\\svc_backup']),
      22),

    // ── net localgroup administrators (DC01) ─────────────
    snap('mock-snap-localadmins-dc01', H.DC01, 'localadmins', 'windows',
      localAdmins(['Administrator', 'CORP\\Domain Admins']),
      21),

    // ── qwinsta (JSMITH — active session) ────────────────
    snap('mock-snap-sessions-jsmith', H.JSMITH, 'sessions', 'windows',
      qwinsta([['console', 'jsmith', 1, 'Active'], ['services', '', 0, 'Disc']]),
      28),

    // ── qwinsta (DC01 — attacker session via pass-the-hash) ──
    snap('mock-snap-sessions-dc01', H.DC01, 'sessions', 'windows',
      qwinsta([['rdp-tcp#0', 'Administrator', 2, 'Active'], ['console', 'SYSTEM', 1, 'Active'], ['services', '', 0, 'Disc']]),
      21),

    // ── whoami /all (JSMITH — post-compromise privs) ──────
    snap('mock-snap-whoami-jsmith', H.JSMITH, 'whoami', 'windows',
      whoamiAll('CORP', 'jsmith', 'S-1-5-21-1234567890-1234567890-1234567890-1103',
        [
          ['Everyone',             'Well-known group', 'S-1-1-0'],
          ['BUILTIN\\Administrators', 'Alias',          'S-1-5-32-544'],
          ['CORP\\Domain Users',   'Group',             'S-1-5-21-...-513'],
        ],
        [
          ['SeImpersonatePrivilege', 'Impersonate a client after authentication', 'Enabled'],
          ['SeDebugPrivilege',       'Debug programs',                            'Enabled'],
          ['SeChangeNotifyPrivilege','Bypass traverse checking',                  'Enabled'],
        ]),
      28),

    // ── net accounts (DC01 — domain password policy) ──────
    snap('mock-snap-netaccounts-dc01', H.DC01, 'netaccounts', 'windows',
      netAccounts('PRIMARY', 7, 90, 5),
      20),

    // ── net share (FS01 — Finance and HR shares) ──────────
    snap('mock-snap-netshare-fs01', H.FS01, 'netshare', 'windows',
      netShare([
        ['C$',       'C:\\',                        'Default share'],
        ['IPC$',     '',                            'Remote IPC'],
        ['ADMIN$',   'C:\\Windows',                 'Remote Admin'],
        ['Finance',  'C:\\Shares\\Finance',         'Financial reports — restricted'],
        ['HR',       'C:\\Shares\\HR',              'HR documents'],
        ['NETLOGON', 'C:\\Windows\\SYSVOL\\sysvol\\corp.local\\SCRIPTS', 'Logon server share'],
        ['SYSVOL',   'C:\\Windows\\SYSVOL\\sysvol', 'Logon server share'],
      ]),
      22),

    // ── /etc/passwd (JENKINS) ─────────────────────────────
    snap('mock-snap-passwd-jenkins', H.JENKINS, 'passwd', 'linux',
      'root:x:0:0:root:/root:/bin/bash\n' +
      'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n' +
      'syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n' +
      'jenkins:x:112:118:Jenkins,,,:/var/lib/jenkins:/bin/bash\n' +
      'jsmith:x:1001:1001:John Smith,,,:/home/jsmith:/bin/bash\n' +
      'svc_deploy:x:1002:1002:Deploy Service,,,:/home/svc_deploy:/bin/bash',
      18),

    // ── /etc/shadow (JENKINS) ────────────────────────────
    snap('mock-snap-shadow-jenkins', H.JENKINS, 'shadow', 'linux',
      'root:$6$rounds=5000$randsalt1$roothashabcdef0123456789abcdef0123456789abcdef0123456789abcdef012345:19400:0:99999:7:::\n' +
      'daemon:*:18397:0:99999:7:::\n' +
      'jenkins:$6$rounds=5000$jenksalt1$jenkinshashabcdef0123456789abcdef0123456789abcdef0123456789abcdef01:19380:0:99999:7:::\n' +
      'jsmith:$6$rounds=5000$jsmsalt01$jsmithhashabcdef0123456789abcdef0123456789abcdef0123456789abcdef012:19400:0:99999:7:::\n' +
      'svc_deploy:$6$rounds=5000$deplsalt1$deployhashabcdef0123456789abcdef0123456789abcdef0123456789abcdef01:19400:0:99999:7:::',
      18),

    // ── last (JENKINS — logins from DC01 and JSMITH IPs) ──
    snap('mock-snap-last-jenkins', H.JENKINS, 'lastlog', 'linux',
      lastLog([
        ['jsmith',     'pts/0', '10.10.3.55', '09:15', '08:15'],
        ['root',       'pts/1', '10.10.1.5',  '22:12', '00:33'],
        ['jsmith',     'pts/0', '10.10.3.55', '08:30', '09:15'],
        ['svc_deploy', 'pts/2', '10.10.1.30', '03:00', '00:15'],
      ]),
      18),

    // ── sudo -l (JENKINS — docker NOPASSWD = easy privesc) ─
    snap('mock-snap-sudol-jenkins', H.JENKINS, 'sudol', 'linux',
      sudoL('jsmith', 'jenkins', [
        ['root', true,  '/usr/bin/docker'],
        ['root', true,  '/bin/systemctl restart jenkins'],
        ['root', true,  '/bin/systemctl restart nginx'],
      ]),
      18),

    // ── /etc/passwd (WEB01) ───────────────────────────────
    snap('mock-snap-passwd-web01', H.WEB01, 'passwd', 'linux',
      'root:x:0:0:root:/root:/bin/bash\n' +
      'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n' +
      'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n' +
      'jsmith:x:1001:1001:John Smith,,,:/home/jsmith:/bin/bash\n' +
      'svc_web:x:1002:1002:Web Service,,,:/home/svc_web:/bin/bash',
      14),

    // ── /etc/shadow (WEB01) ───────────────────────────────
    snap('mock-snap-shadow-web01', H.WEB01, 'shadow', 'linux',
      'root:$6$rounds=5000$web01salt$web01roothashabcdef0123456789abcdef0123456789abcdef0123456789abcdef0:19400:0:99999:7:::\n' +
      'daemon:*:18397:0:99999:7:::\n' +
      'www-data:!:19380:0:99999:7:::\n' +
      'jsmith:$6$rounds=5000$web01jsm$web01jsmithhashabcdef0123456789abcdef0123456789abcdef0123456789abcd:19400:0:99999:7:::\n' +
      'svc_web:$6$rounds=5000$svcwbslt$svcwebhashabcdef0123456789abcdef0123456789abcdef0123456789abcdef01:19400:0:99999:7:::',
      14),

    // ── last (WEB01) ──────────────────────────────────────
    // ── AD Domain survey (DC01) ───────────────────────────
    snap('mock-snap-addomain-dc01', H.DC01, 'addomain', 'windows',
      'Forest                  : corp.local\n' +
      'DomainSID               : S-1-5-21-3623811015-3361044348-30300820\n' +
      'NetBIOSName             : CORP\n' +
      'DomainMode              : Windows2016Domain\n' +
      'PDCEmulator             : DC01.corp.local\n' +
      'RIDMaster               : DC01.corp.local\n' +
      'InfrastructureMaster    : DC01.corp.local\n' +
      'ParentDomain            :\n' +
      'ChildDomains            : {child.corp.local}\n' +
      'Forest                  : corp.local\n' +
      'ForestMode              : Windows2016Forest\n' +
      'GlobalCatalogs          : {DC01.corp.local, DC02.corp.local}\n' +
      'Sites                   : {Default-First-Site-Name}\n' +
      'UPNSuffixes             : {corp.local, corp-ext.com}',
      15),

    snap('mock-snap-addc-dc01', H.DC01, 'addomaincontrollers', 'windows',
      'DefaultPartition    : DC=corp,DC=local\n' +
      'Domain              : corp.local\n' +
      'Enabled             : True\n' +
      'Forest              : corp.local\n' +
      'HostName            : DC01.corp.local\n' +
      'IPAddress           : 10.10.1.5\n' +
      'IsGlobalCatalog     : True\n' +
      'IsReadOnly          : False\n' +
      'Name                : DC01\n' +
      'OperatingSystem     : Windows Server 2019 Standard\n' +
      'OperationMasterRoles: {SchemaMaster, DomainNamingMaster, PDCEmulator, RIDMaster, InfrastructureMaster}\n' +
      'Site                : Default-First-Site-Name\n' +
      '\n' +
      'DefaultPartition    : DC=corp,DC=local\n' +
      'Domain              : corp.local\n' +
      'Enabled             : True\n' +
      'Forest              : corp.local\n' +
      'HostName            : DC02.corp.local\n' +
      'IPAddress           : 10.10.1.6\n' +
      'IsGlobalCatalog     : True\n' +
      'IsReadOnly          : False\n' +
      'Name                : DC02\n' +
      'OperatingSystem     : Windows Server 2019 Standard\n' +
      'OperationMasterRoles: {}\n' +
      'Site                : Default-First-Site-Name',
      15),

    snap('mock-snap-adtrusts-dc01', H.DC01, 'adtrusts', 'windows',
      'List of domain trusts:\n' +
      '    0: CORP corp.local (NT 5) (Forest: 2) (Forest Tree Root) (Direct Inbound) (Direct Outbound)\n' +
      '    1: CHILD child.corp.local (NT 5) (Forest: 0) (Direct Inbound) (Direct Outbound)\n' +
      'The command completed successfully',
      15),

    snap('mock-snap-adous-dc01', H.DC01, 'adous', 'windows',
      'DistinguishedName    : OU=Domain Controllers,DC=corp,DC=local\n' +
      'Name                 : Domain Controllers\n' +
      'ObjectClass          : organizationalUnit\n' +
      '\n' +
      'DistinguishedName    : OU=Servers,DC=corp,DC=local\n' +
      'Name                 : Servers\n' +
      'ObjectClass          : organizationalUnit\n' +
      '\n' +
      'DistinguishedName    : OU=Workstations,DC=corp,DC=local\n' +
      'Name                 : Workstations\n' +
      'ObjectClass          : organizationalUnit\n' +
      '\n' +
      'DistinguishedName    : OU=Users,DC=corp,DC=local\n' +
      'Name                 : Users\n' +
      'ObjectClass          : organizationalUnit\n' +
      '\n' +
      'DistinguishedName    : OU=Service Accounts,DC=corp,DC=local\n' +
      'Name                 : Service Accounts\n' +
      'ObjectClass          : organizationalUnit\n' +
      '\n' +
      'DistinguishedName    : OU=IT,OU=Users,DC=corp,DC=local\n' +
      'Name                 : IT\n' +
      'ObjectClass          : organizationalUnit\n' +
      '\n' +
      'DistinguishedName    : OU=Finance,OU=Users,DC=corp,DC=local\n' +
      'Name                 : Finance\n' +
      'ObjectClass          : organizationalUnit',
      15),

    snap('mock-snap-adcs-dc01', H.DC01, 'adcs', 'windows',
      'Entry 0: (Local)\n' +
      '  Name: "corp-DC01-CA"\n' +
      '  Organization: "CORP"\n' +
      '  Config: "DC01.corp.local\\corp-DC01-CA"\n' +
      '  Server: "DC01.corp.local"\n' +
      '  Authority: "corp-DC01-CA"\n' +
      '  Sanitized Name: "corp-DC01-CA"\n' +
      '  Short Name: "corp-DC01-CA"\n' +
      '  Flags: "1"\n' +
      '  Web Enrollment Servers: "https://DC01.corp.local/certsrv"\n' +
      'CertUtil: -CA command completed successfully.',
      15),

    snap('mock-snap-last-web01', H.WEB01, 'lastlog', 'linux',
      lastLog([
        ['jsmith',   'pts/0', '10.10.2.30', '14:22', '03:10'],
        ['root',     'pts/1', '10.10.2.30', '14:05', '00:17'],
        ['svc_web',  'pts/2', '10.10.1.30', '02:00', '00:05'],
      ]),
      14),
  ],
};
