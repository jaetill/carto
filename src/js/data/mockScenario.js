// Mock scenario: "CORP Internal Pentest" — 30-day engagement, 15 hosts
// Used when DEBUG_MODE is enabled or "Load Mock Scenario" is triggered

const ENG_ID   = 'mock-eng-0001';
const START_TS = Date.now() - (30 * 24 * 60 * 60 * 1000);
const START_DATE = new Date(START_TS).toISOString().slice(0, 10);

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
