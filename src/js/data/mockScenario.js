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
  return `Proto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 ${ip}:ssh              10.10.3.55:54210        ESTABLISHED\ntcp        0      0 ${ip}:https            10.10.1.20:49330        ESTABLISHED\ntcp        0      0 ${ip}:8080             10.10.2.30:39421        ESTABLISHED`;
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

function snap(id, hostId, commandType, osFamily, rawOutput, daysAgoVal, hoursOffset = 0) {
  return { id, hostId, commandType, osFamily, rawOutput, parsed: null, timestamp: daysAgo(daysAgoVal, hoursOffset) };
}

export const MOCK_ENG_ID = ENG_ID;

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
    snap('mock-s-jen-3',   H.JENKINS, 'pslist',   'linux',   'root 1 /sbin/init\njenkins 1842 java -jar jenkins.war\nroot 4201 sshd\njsmith 5512 bash\nroot 6001 python3 /tmp/.x', 17),
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
  ],
};
