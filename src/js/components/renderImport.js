import { btn } from '../ui/elements.js';

export function renderImport(engagementId, importObj, onBack) {
  const container = document.getElementById('app-content');
  container.innerHTML = '';

  if (importObj.importType === 'nmap') {
    renderNmap(container, importObj, onBack);
  } else if (importObj.importType === 'metasploit') {
    renderMetasploit(container, importObj, onBack);
  } else if (importObj.importType === 'nessus') {
    renderNessus(container, importObj, onBack);
  } else if (importObj.importType === 'nuclei') {
    renderNuciei(container, importObj, onBack);
  } else if (importObj.importType === 'sharphound') {
    renderSharpHound(container, importObj, onBack);
  } else if (importObj.importType === 'ghostwriter') {
    renderGhostwriter(container, importObj, onBack);
  } else {
    renderGeneric(container, importObj, onBack);
  }
}

// ── Nmap detail view ──────────────────────────────────────

function renderNmap(container, importObj, onBack) {
  const parsed = importObj.parsed || {};
  const hosts  = parsed.hosts || [];

  // Header
  const header = buildHeader(container, importObj, onBack);

  // Scan args row
  if (parsed.scanArgs) {
    const argsRow = document.createElement('p');
    argsRow.className = 'text-xs text-slate-500 font-mono mb-1';
    argsRow.textContent = `Args: ${parsed.scanArgs}`;
    header.appendChild(argsRow);
  }

  // Scan date row
  if (parsed.scanStart) {
    const dateRow = document.createElement('p');
    dateRow.className = 'text-xs text-slate-400 mb-4';
    dateRow.textContent = `Scan started: ${new Date(parsed.scanStart * 1000).toLocaleString()}`;
    header.appendChild(dateRow);
  }

  // Stats row
  const openPorts = hosts.reduce((n, h) => n + (h.ports || []).filter(p => p.state === 'open').length, 0);
  buildStatsRow(container, [
    { label: 'Hosts Up',    value: parsed.hostsUp    ?? '—' },
    { label: 'Total Hosts', value: parsed.hostsTotal ?? '—' },
    { label: 'Open Ports',  value: openPorts },
  ]);

  // Hosts table
  const tableWrap = document.createElement('div');
  tableWrap.className = 'bg-white rounded-xl border border-slate-200 overflow-hidden';

  const table = document.createElement('table');
  table.className = 'w-full text-sm';

  const thead = document.createElement('thead');
  thead.innerHTML = `<tr class="border-b border-slate-100 bg-slate-50">
    <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">IP</th>
    <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">Hostname</th>
    <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">OS</th>
    <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">Open Ports</th>
    <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">Status</th>
  </tr>`;
  table.appendChild(thead);

  const tbody = document.createElement('tbody');

  hosts.forEach(host => {
    const tr = document.createElement('tr');
    tr.className = 'border-b border-slate-50 hover:bg-slate-50 cursor-pointer transition-colors';

    const hostname = (host.hostnames || []).find(n => n.type === 'PTR')?.name
      || (host.hostnames || [])[0]?.name
      || '—';

    const os = host.os?.name || '—';

    const openPortsList = (host.ports || []).filter(p => p.state === 'open');

    // IP cell
    const tdIp = document.createElement('td');
    tdIp.className = 'px-4 py-2.5 font-mono text-xs font-semibold text-slate-700';
    tdIp.textContent = host.ip || '—';

    // Hostname cell
    const tdHost = document.createElement('td');
    tdHost.className = 'px-4 py-2.5 text-slate-600 text-xs truncate max-w-xs font-mono';
    tdHost.textContent = hostname;

    // OS cell
    const tdOs = document.createElement('td');
    tdOs.className = 'px-4 py-2.5 text-slate-500 text-xs';
    tdOs.textContent = os;

    // Ports cell — pill badges
    const tdPorts = document.createElement('td');
    tdPorts.className = 'px-4 py-2.5';
    if (openPortsList.length === 0) {
      tdPorts.innerHTML = '<span class="text-slate-300 text-xs">—</span>';
    } else {
      const pillWrap = document.createElement('div');
      pillWrap.className = 'flex flex-wrap gap-1';
      openPortsList.slice(0, 20).forEach(p => {
        const pill = document.createElement('span');
        pill.className = 'inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono bg-blue-50 text-blue-700 border border-blue-100';
        pill.textContent = p.service?.name ? `${p.port}/${p.service.name}` : String(p.port);
        pillWrap.appendChild(pill);
      });
      if (openPortsList.length > 20) {
        const more = document.createElement('span');
        more.className = 'text-xs text-slate-400';
        more.textContent = `+${openPortsList.length - 20} more`;
        pillWrap.appendChild(more);
      }
      tdPorts.appendChild(pillWrap);
    }

    // Status cell
    const tdStatus = document.createElement('td');
    tdStatus.className = 'px-4 py-2.5';
    const badge = document.createElement('span');
    badge.className = `inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
      host.status === 'up' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'
    }`;
    badge.textContent = host.status || '—';
    tdStatus.appendChild(badge);

    tr.appendChild(tdIp);
    tr.appendChild(tdHost);
    tr.appendChild(tdOs);
    tr.appendChild(tdPorts);
    tr.appendChild(tdStatus);
    tbody.appendChild(tr);
  });

  if (hosts.length === 0) {
    const emptyRow = document.createElement('tr');
    emptyRow.innerHTML = `<td colspan="5" class="px-4 py-8 text-center text-slate-400 text-sm italic">No hosts in this scan.</td>`;
    tbody.appendChild(emptyRow);
  }

  table.appendChild(tbody);
  tableWrap.appendChild(table);
  container.appendChild(tableWrap);
}

// ── Metasploit detail view ────────────────────────────────

function renderMetasploit(container, importObj, onBack) {
  const parsed = importObj.parsed || {};

  let activeInnerTab = 'hosts';

  // Header
  buildHeader(container, importObj, onBack);

  // Stats row
  buildStatsRow(container, [
    { label: 'Hosts',    value: (parsed.hosts        || []).length },
    { label: 'Services', value: (parsed.services      || []).length },
    { label: 'Vulns',    value: (parsed.vulns         || []).length },
    { label: 'Creds',    value: (parsed.credentials   || []).length },
    { label: 'Sessions', value: (parsed.sessions      || []).length },
  ]);

  // Inner tab bar + content wrapper
  const tabSection = document.createElement('div');
  container.appendChild(tabSection);

  function renderInnerTabs() {
    tabSection.innerHTML = '';

    const tabBar = document.createElement('div');
    tabBar.className = 'flex items-center gap-1 mb-4 border-b border-slate-200';

    const innerTabs = [
      { id: 'hosts',    label: 'Hosts' },
      { id: 'services', label: 'Services' },
      { id: 'vulns',    label: 'Vulns' },
      { id: 'creds',    label: 'Creds' },
    ];

    innerTabs.forEach(({ id, label }) => {
      const tab = document.createElement('button');
      tab.type = 'button';
      tab.className = `px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
        activeInnerTab === id
          ? 'border-indigo-600 text-indigo-700'
          : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
      }`;
      tab.textContent = label;
      tab.onclick = () => { activeInnerTab = id; renderInnerTabs(); };
      tabBar.appendChild(tab);
    });

    tabSection.appendChild(tabBar);

    const tableWrap = document.createElement('div');
    tableWrap.className = 'bg-white rounded-xl border border-slate-200 overflow-hidden';

    if (activeInnerTab === 'hosts') {
      const hosts = parsed.hosts || [];
      tableWrap.appendChild(buildTable(
        ['IP', 'Hostname', 'OS', 'Arch', 'Purpose'],
        hosts,
        host => [
          monoCell(host.ip || '—'),
          textCell(host.hostname || '—'),
          textCell(host.os ? [host.os.name, host.os.flavor].filter(Boolean).join(' ') || '—' : '—'),
          monoCell(host.arch || '—'),
          textCell(host.purpose || '—'),
        ],
        'No hosts recorded.'
      ));
    }

    if (activeInnerTab === 'services') {
      const services = parsed.services || [];
      tableWrap.appendChild(buildTable(
        ['Host IP', 'Port', 'Protocol', 'Name', 'Banner'],
        services,
        svc => [
          monoCell(svc.hostIp || '—'),
          monoCell(svc.port != null ? String(svc.port) : '—'),
          textCell(svc.protocol || '—'),
          textCell(svc.name || '—'),
          textCell(svc.banner || '—', true),
        ],
        'No services recorded.'
      ));
    }

    if (activeInnerTab === 'vulns') {
      const vulns = parsed.vulns || [];
      tableWrap.appendChild(buildTable(
        ['Host IP', 'Name', 'Refs'],
        vulns,
        vuln => [
          monoCell(vuln.hostIp || '—'),
          textCell(vuln.name || '—'),
          refsCell(vuln.refs || []),
        ],
        'No vulnerabilities recorded.'
      ));
    }

    if (activeInnerTab === 'creds') {
      const creds = parsed.credentials || [];
      tableWrap.appendChild(buildTable(
        ['Username', 'Secret Type', 'Host:Port'],
        creds,
        cred => [
          monoCell(cred.username || '—'),
          textCell(cred.secretType || '—'),
          monoCell(cred.hostIp ? `${cred.hostIp}${cred.port ? ':' + cred.port : ''}` : '—'),
        ],
        'No credentials recorded.'
      ));
    }

    tabSection.appendChild(tableWrap);
  }

  renderInnerTabs();
}

// ── Nessus detail view ────────────────────────────────────

function renderNessus(container, importObj, onBack) {
  const parsed = importObj.parsed || {};
  const hosts  = parsed.hosts || [];

  // Header
  const header = buildHeader(container, importObj, onBack);

  if (parsed.policyName) {
    const policyRow = document.createElement('p');
    policyRow.className = 'text-xs text-slate-500 font-mono mb-4';
    policyRow.textContent = `Policy: ${parsed.policyName}`;
    header.appendChild(policyRow);
  }

  // Flatten findings across all hosts
  const allFindings = hosts.flatMap(h =>
    (h.findings || []).map(f => ({ ...f, hostIp: h.ip, hostName: h.hostname }))
  );

  const critCount       = allFindings.filter(f => f.severity === 4).length;
  const highCount       = allFindings.filter(f => f.severity === 3).length;
  const exploitCount    = allFindings.filter(f => f.exploitAvailable).length;

  buildStatsRow(container, [
    { label: 'Hosts',       value: hosts.length },
    { label: 'Findings',    value: allFindings.length },
    { label: 'Critical',    value: critCount },
    { label: 'High',        value: highCount },
    { label: 'Exploitable', value: exploitCount },
  ]);

  // Sort findings by severity descending (critical first)
  const sortedFindings = [...allFindings].sort((a, b) => b.severity - a.severity);

  const tableWrap = document.createElement('div');
  tableWrap.className = 'bg-white rounded-xl border border-slate-200 overflow-hidden';

  tableWrap.appendChild(buildTable(
    ['Host', 'Severity', 'Plugin / Finding Name', 'Port', 'CVEs', 'CVSS'],
    sortedFindings,
    finding => [
      monoCell(finding.hostIp || finding.hostName || '—'),
      nessusSeverityCell(finding.severity),
      textCell(finding.pluginName || '—'),
      monoCell(finding.port != null ? String(finding.port) : '—'),
      refsCell(finding.cveIds || []),
      textCell(finding.cvss3Score != null ? String(finding.cvss3Score) : (finding.cvssScore != null ? String(finding.cvssScore) : '—')),
    ],
    'No findings recorded.'
  ));

  container.appendChild(tableWrap);
}

function nessusSeverityCell(severity) {
  const td = document.createElement('td');
  td.className = 'px-4 py-2.5';
  const labels = { 4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Info' };
  const colors = {
    4: 'bg-red-100 text-red-700 border border-red-200',
    3: 'bg-orange-100 text-orange-700 border border-orange-200',
    2: 'bg-yellow-100 text-yellow-700 border border-yellow-200',
    1: 'bg-blue-100 text-blue-700 border border-blue-200',
    0: 'bg-slate-100 text-slate-500',
  };
  const badge = document.createElement('span');
  badge.className = `inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${colors[severity] || colors[0]}`;
  badge.textContent = labels[severity] ?? String(severity);
  td.appendChild(badge);
  return td;
}

// ── Nuclei detail view ────────────────────────────────────

function renderNuciei(container, importObj, onBack) {
  const parsed   = importObj.parsed || {};
  const findings = parsed.findings || [];

  // Header
  buildHeader(container, importObj, onBack);

  const critCount   = findings.filter(f => f.severity === 'critical').length;
  const highCount   = findings.filter(f => f.severity === 'high').length;
  const medCount    = findings.filter(f => f.severity === 'medium').length;

  buildStatsRow(container, [
    { label: 'Findings', value: findings.length },
    { label: 'Critical', value: critCount },
    { label: 'High',     value: highCount },
    { label: 'Medium',   value: medCount },
  ]);

  // Sort by severity descending
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const sortedFindings = [...findings].sort(
    (a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0)
  );

  const tableWrap = document.createElement('div');
  tableWrap.className = 'bg-white rounded-xl border border-slate-200 overflow-hidden';

  tableWrap.appendChild(buildTable(
    ['Host / IP', 'Severity', 'Finding Name', 'Matched At', 'CVEs'],
    sortedFindings,
    finding => [
      monoCell(finding.host || finding.ip || '—'),
      nucleiSeverityCell(finding.severity),
      textCell(finding.name || finding.templateId || '—'),
      textCell(finding.matchedAt || '—', true),
      refsCell(finding.cveIds || []),
    ],
    'No findings recorded.'
  ));

  container.appendChild(tableWrap);
}

function nucleiSeverityCell(severity) {
  const td = document.createElement('td');
  td.className = 'px-4 py-2.5';
  const colors = {
    critical: 'bg-red-100 text-red-700 border border-red-200',
    high:     'bg-orange-100 text-orange-700 border border-orange-200',
    medium:   'bg-yellow-100 text-yellow-700 border border-yellow-200',
    low:      'bg-blue-100 text-blue-700 border border-blue-200',
    info:     'bg-slate-100 text-slate-500',
  };
  const badge = document.createElement('span');
  badge.className = `inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${colors[severity] || colors.info}`;
  badge.textContent = severity ? severity.charAt(0).toUpperCase() + severity.slice(1) : '—';
  td.appendChild(badge);
  return td;
}

// ── SharpHound detail view ────────────────────────────────

function renderSharpHound(container, importObj, onBack) {
  const parsed = importObj.parsed || {};

  let activeInnerTab = 'computers';

  // Header
  const header = buildHeader(container, importObj, onBack);

  if (parsed.domain) {
    const domainRow = document.createElement('p');
    domainRow.className = 'text-xs text-slate-500 font-mono mb-1';
    domainRow.textContent = `Domain: ${parsed.domain}`;
    header.appendChild(domainRow);
  }

  if (parsed.collectedAt) {
    const dateRow = document.createElement('p');
    dateRow.className = 'text-xs text-slate-400 mb-4';
    dateRow.textContent = `Collected: ${new Date(parsed.collectedAt * 1000).toLocaleString()}`;
    header.appendChild(dateRow);
  }

  // Build SID → name lookup for use across all tabs
  const sidToName = {};
  for (const u of parsed.users     || []) if (u.objectId && u.name) sidToName[u.objectId] = u.name;
  for (const g of parsed.groups    || []) if (g.objectId && g.name) sidToName[g.objectId] = g.name;
  for (const c of parsed.computers || []) if (c.objectId && c.name) sidToName[c.objectId] = c.name;
  for (const d of parsed.domains   || []) if (d.objectId && d.name) sidToName[d.objectId] = d.name;

  const notableRights = new Set(['DCSync','GenericAll','GenericWrite','WriteDACL','WriteOwner','AllExtendedRights','Owns','ForceChangePassword','AddMember','ReadLAPSPassword','ReadGMSAPassword','AddKeyCredentialLink','AllowedToAct']);
  const notableAces = (parsed.aces || []).filter(a => notableRights.has(a.rightName) && !a.isInherited);

  // Stats row
  buildStatsRow(container, [
    { label: 'Computers',      value: (parsed.computers     || []).length },
    { label: 'Users',          value: (parsed.users         || []).length },
    { label: 'Groups',         value: (parsed.groups        || []).length },
    { label: 'Domains',        value: (parsed.domains       || []).length },
    { label: 'CAs',            value: (parsed.cas           || []).length },
    { label: 'Cert Templates', value: (parsed.certTemplates || []).length },
    { label: 'Notable ACEs',   value: notableAces.length },
  ]);

  // Inner tab bar + content wrapper
  const tabSection = document.createElement('div');
  container.appendChild(tabSection);

  function renderInnerTabs() {
    tabSection.innerHTML = '';

    const tabBar = document.createElement('div');
    tabBar.className = 'flex items-center gap-1 mb-4 border-b border-slate-200';

    const innerTabs = [
      { id: 'computers',      label: 'Computers' },
      { id: 'users',          label: 'Users' },
      { id: 'groups',         label: 'Groups' },
      { id: 'domains',        label: 'Domains' },
      { id: 'ous',            label: 'OUs' },
      { id: 'cas',            label: 'CAs' },
      { id: 'cert-templates', label: 'Cert Templates' },
      { id: 'gpos',           label: 'GPOs' },
      { id: 'aces',           label: `ACEs (${notableAces.length})` },
    ];

    innerTabs.forEach(({ id, label }) => {
      const tab = document.createElement('button');
      tab.type = 'button';
      tab.className = `px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
        activeInnerTab === id
          ? 'border-indigo-600 text-indigo-700'
          : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
      }`;
      tab.textContent = label;
      tab.onclick = () => { activeInnerTab = id; renderInnerTabs(); };
      tabBar.appendChild(tab);
    });

    tabSection.appendChild(tabBar);

    const tableWrap = document.createElement('div');
    tableWrap.className = 'bg-white rounded-xl border border-slate-200 overflow-hidden';

    if (activeInnerTab === 'computers') {
      const computers = parsed.computers || [];
      tableWrap.appendChild(buildTable(
        ['Name', 'OS', 'DC', 'LAPS', 'Unconstrained', 'Constrained', 'Sessions', 'Local Admins'],
        computers,
        c => [
          monoCell(c.name || '—'),
          textCell(c.os || '—'),
          shBoolCell(c.isDC, 'DC', 'bg-blue-100 text-blue-700'),
          shBoolCell(c.hasLAPS, 'Yes', 'bg-green-100 text-green-700'),
          shBoolCell(c.unconstrainedDelegation, 'YES', 'bg-red-100 text-red-700'),
          shBoolCell(c.trustedToAuth, 'Yes', 'bg-orange-100 text-orange-700'),
          textCell(String((c.sessions || []).length)),
          textCell(String((c.localAdmins || []).length)),
        ],
        'No computers collected.'
      ));
    }

    if (activeInnerTab === 'users') {
      const users = parsed.users || [];
      tableWrap.appendChild(buildTable(
        ['Name', 'Enabled', 'Has SPN', 'AS-REP', 'Pwd Never Expires', 'Constrained Deleg.', 'Admin', 'Groups'],
        users,
        u => [
          monoCell(u.name || '—'),
          shBoolCell(u.enabled),
          shBoolCell(u.hasSPN, 'Yes', 'bg-orange-100 text-orange-700'),
          shBoolCell(u.dontReqPreauth, 'YES', 'bg-red-100 text-red-700'),
          shBoolCell(u.pwdNeverExpires, 'YES', 'bg-yellow-100 text-yellow-700'),
          shBoolCell(u.trustedToAuth, 'Yes', 'bg-orange-100 text-orange-700'),
          shBoolCell(u.adminCount, 'Yes', 'bg-red-100 text-red-700'),
          textCell(String((u.memberOf || []).length)),
        ],
        'No users collected.'
      ));
    }

    if (activeInnerTab === 'groups') {
      const groups = parsed.groups || [];
      tableWrap.appendChild(buildTable(
        ['Name', 'Domain', 'Member Count'],
        groups,
        g => [
          monoCell(g.name || '—'),
          textCell(g.domain || '—'),
          textCell(String((g.members || []).length)),
        ],
        'No groups collected.'
      ));
    }

    if (activeInnerTab === 'domains') {
      const domains = parsed.domains || [];
      tableWrap.appendChild(buildTable(
        ['Name', 'Trusts'],
        domains,
        d => [
          monoCell(d.name || '—'),
          textCell(String((d.trusts || []).length)),
        ],
        'No domains collected.'
      ));
    }

    if (activeInnerTab === 'ous') {
      const ous = parsed.ous || [];
      tableWrap.appendChild(buildTable(
        ['Name', 'Domain'],
        ous,
        ou => [
          monoCell(ou.name || '—'),
          textCell(ou.domain || '—'),
        ],
        'No OUs collected.'
      ));
    }

    if (activeInnerTab === 'cas') {
      const cas = parsed.cas || [];
      tableWrap.appendChild(buildTable(
        ['Name', 'DNS Name', 'Cert Templates'],
        cas,
        ca => [
          monoCell(ca.name || '—'),
          monoCell(ca.dnsName || '—'),
          textCell(String((ca.certTemplates || []).length)),
        ],
        'No CAs collected.'
      ));
    }

    if (activeInnerTab === 'cert-templates') {
      const templates = parsed.certTemplates || [];
      const sorted = [...templates].sort((a, b) => (b.esc1 ? 1 : 0) - (a.esc1 ? 1 : 0) || (a.name || '').localeCompare(b.name || ''));
      tableWrap.appendChild(buildTable(
        ['Template Name', 'Validity', 'Auth Enabled', 'Enrollee Supplies SAN', 'Mgr Approval', 'ESC1'],
        sorted,
        t => [
          (() => { const td = monoCell(t.displayName || t.name || '—'); if (t.esc1) td.className += ' font-semibold'; return td; })(),
          textCell(t.validityPeriod || '—'),
          shBoolCell(t.authenticationEnabled, 'Yes', 'bg-orange-100 text-orange-700'),
          shBoolCell(t.enrolleesSuppliesSubject, 'YES', 'bg-red-100 text-red-700'),
          shBoolCell(t.requiresManagerApproval, 'Required', 'bg-green-100 text-green-700'),
          shBoolCell(t.esc1, 'ESC1', 'bg-red-600 text-white'),
        ],
        'No certificate templates collected.'
      ));
    }

    if (activeInnerTab === 'gpos') {
      const gpos = parsed.gpos || [];
      tableWrap.appendChild(buildTable(
        ['Name', 'Domain', 'GUID'],
        gpos,
        g => [
          monoCell(g.name || '—'),
          textCell(g.domain || '—'),
          (() => { const td = document.createElement('td'); td.className = 'px-4 py-2.5 text-slate-400 text-xs font-mono'; td.textContent = g.guid || g.objectId || '—'; return td; })(),
        ],
        'No GPOs collected.'
      ));
    }

    if (activeInnerTab === 'aces') {
      // Sort: high-impact rights first
      const highImpact = new Set(['DCSync','GenericAll','AllExtendedRights','WriteDACL','WriteOwner']);
      const sorted = [...notableAces].sort((a, b) => {
        const aHigh = highImpact.has(a.rightName) ? 0 : 1;
        const bHigh = highImpact.has(b.rightName) ? 0 : 1;
        return aHigh - bHigh || (a.rightName || '').localeCompare(b.rightName || '');
      });
      tableWrap.appendChild(buildTable(
        ['Principal', 'Type', 'Right', 'Object', 'Object Type'],
        sorted,
        a => {
          const rightClass = highImpact.has(a.rightName) ? 'text-red-600 font-semibold' : 'text-orange-600';
          const td = document.createElement('td');
          td.className = `px-4 py-2.5 text-sm ${rightClass}`;
          td.textContent = a.rightName || '—';
          return [
            monoCell(sidToName[a.principalSid] || a.principalSid || '—'),
            textCell(a.principalType || '—'),
            td,
            monoCell(sidToName[a.objectSid] || a.objectSid || '—'),
            textCell(a.objectType || '—'),
          ];
        },
        'No notable ACEs found.'
      ));
    }

    tabSection.appendChild(tableWrap);
  }

  renderInnerTabs();
}

function shBoolCell(value, trueLabel = 'Yes', trueClass = 'bg-green-100 text-green-700') {
  const td = document.createElement('td');
  td.className = 'px-4 py-2.5';
  if (value == null) {
    td.innerHTML = '<span class="text-slate-300 text-xs">—</span>';
  } else if (value) {
    const badge = document.createElement('span');
    badge.className = `inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${trueClass}`;
    badge.textContent = trueLabel;
    td.appendChild(badge);
  } else {
    const badge = document.createElement('span');
    badge.className = 'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-400';
    badge.textContent = 'No';
    td.appendChild(badge);
  }
  return td;
}

// ── Ghostwriter oplog detail view ────────────────────────

function renderGhostwriter(container, importObj, onBack) {
  const parsed  = importObj.parsed || {};
  const entries = (parsed.entries || []).slice()
    .sort((a, b) => (a.startDate ?? 0) - (b.startDate ?? 0));

  buildHeader(container, importObj, onBack);

  const operators = new Set(entries.map(e => e.operatorName).filter(Boolean));
  const tools     = new Set(entries.map(e => e.tool).filter(Boolean));

  const dates = entries.map(e => e.startDate).filter(Boolean);
  const dateRange = dates.length >= 2
    ? `${new Date(Math.min(...dates)).toLocaleDateString()} – ${new Date(Math.max(...dates)).toLocaleDateString()}`
    : dates.length === 1 ? new Date(dates[0]).toLocaleDateString() : null;

  buildStatsRow(container, [
    { label: 'Log Entries', value: entries.length },
    { label: 'Operators',   value: operators.size },
    { label: 'Tools',       value: tools.size },
    ...(dateRange ? [{ label: 'Date Range', value: dateRange }] : []),
  ]);

  const tableWrap = document.createElement('div');
  tableWrap.className = 'bg-white rounded-xl border border-slate-200 overflow-hidden';

  tableWrap.appendChild(buildTable(
    ['Time', 'Operator', 'Source IP', 'Dest', 'Tool', 'User Context', 'Command'],
    entries,
    entry => [
      textCell(entry.startDate ? new Date(entry.startDate).toLocaleString() : '—'),
      textCell(entry.operatorName || '—'),
      monoCell(entry.sourceIp || '—'),
      monoCell(entry.destHost || entry.destIp || '—'),
      textCell(entry.tool || '—'),
      monoCell(entry.userContext || '—'),
      commandCell(entry.command),
    ],
    'No log entries recorded.'
  ));

  container.appendChild(tableWrap);
}

function commandCell(command) {
  const td = document.createElement('td');
  td.className = 'px-4 py-2.5 font-mono text-xs text-slate-700 max-w-xs';
  if (!command) { td.innerHTML = '<span class="text-slate-300">—</span>'; return td; }
  if (command.length <= 80) {
    td.textContent = command;
  } else {
    const short = document.createElement('span');
    short.textContent = command.slice(0, 80) + '…';
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'ml-1 text-indigo-500 hover:underline text-xs';
    toggle.textContent = 'more';
    let expanded = false;
    toggle.onclick = () => {
      expanded = !expanded;
      short.textContent = expanded ? command : command.slice(0, 80) + '…';
      toggle.textContent = expanded ? 'less' : 'more';
    };
    td.appendChild(short);
    td.appendChild(toggle);
  }
  return td;
}

// ── Generic fallback ──────────────────────────────────────

function renderGeneric(container, importObj, onBack) {
  buildHeader(container, importObj, onBack);

  const notice = document.createElement('div');
  notice.className = 'bg-white rounded-xl border border-slate-200 px-6 py-8 text-center';
  const msg = document.createElement('p');
  msg.className = 'text-slate-400 text-sm italic';
  msg.textContent = 'No detail view available for this import type.';
  notice.appendChild(msg);
  container.appendChild(notice);
}

// ── Shared helpers ────────────────────────────────────────

/**
 * Builds and appends the page header (breadcrumb + title + meta).
 * Returns the header element so callers can append extra rows.
 */
function buildHeader(container, importObj, onBack) {
  const header = document.createElement('div');
  header.className = 'mb-6';

  // Breadcrumb row
  const breadcrumb = document.createElement('div');
  breadcrumb.className = 'flex items-center gap-2 mb-3';

  const backBtn = btn('← Back', 'ghost');
  backBtn.className += ' text-xs';
  backBtn.onclick = onBack;
  breadcrumb.appendChild(backBtn);

  const sep = document.createElement('span');
  sep.className = 'text-slate-300 text-xs';
  sep.textContent = '/';
  breadcrumb.appendChild(sep);

  const crumb = document.createElement('span');
  crumb.className = 'text-xs text-slate-500 truncate';
  crumb.textContent = importObj.fileName;
  breadcrumb.appendChild(crumb);

  header.appendChild(breadcrumb);

  // Title row
  const titleRow = document.createElement('div');
  titleRow.className = 'flex items-center gap-3';

  const typeBadge = document.createElement('span');
  typeBadge.className = `inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold flex-shrink-0 ${importTypeStyle(importObj.importType)}`;
  typeBadge.textContent = importObj.importType;

  const title = document.createElement('h2');
  title.className = 'text-xl font-bold text-slate-800 truncate';
  title.textContent = importObj.fileName;

  titleRow.appendChild(typeBadge);
  titleRow.appendChild(title);
  header.appendChild(titleRow);

  // Import date
  const meta = document.createElement('p');
  meta.className = 'text-xs text-slate-400 mt-1';
  meta.textContent = `Imported: ${new Date(importObj.importedAt).toLocaleString()}`;
  header.appendChild(meta);

  container.appendChild(header);
  return header;
}

function buildStatsRow(container, stats) {
  const row = document.createElement('div');
  row.className = `grid grid-cols-${stats.length} gap-4 mb-6`;

  stats.forEach(({ label, value }) => {
    const card = document.createElement('div');
    card.className = 'bg-white rounded-xl border border-slate-200 p-4';

    const val = document.createElement('p');
    val.className = 'text-2xl font-bold text-slate-800';
    val.textContent = value;

    const lbl = document.createElement('p');
    lbl.className = 'text-xs text-slate-400 mt-0.5';
    lbl.textContent = label;

    card.appendChild(val);
    card.appendChild(lbl);
    row.appendChild(card);
  });

  container.appendChild(row);
}

function buildTable(headers, rows, cellBuilder, emptyMsg) {
  const table = document.createElement('table');
  table.className = 'w-full text-sm';

  const thead = document.createElement('thead');
  const headerRow = document.createElement('tr');
  headerRow.className = 'border-b border-slate-100 bg-slate-50';

  headers.forEach(h => {
    const th = document.createElement('th');
    th.className = 'text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide';
    th.textContent = h;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');

  if (rows.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = headers.length;
    td.className = 'px-4 py-8 text-center text-slate-400 text-sm italic';
    td.textContent = emptyMsg;
    tr.appendChild(td);
    tbody.appendChild(tr);
  } else {
    rows.forEach(row => {
      const tr = document.createElement('tr');
      tr.className = 'border-b border-slate-50';
      cellBuilder(row).forEach(td => tr.appendChild(td));
      tbody.appendChild(tr);
    });
  }

  table.appendChild(tbody);
  return table;
}

function monoCell(text) {
  const td = document.createElement('td');
  td.className = 'px-4 py-2.5 font-mono text-xs text-slate-700';
  td.textContent = text;
  return td;
}

function textCell(text, truncate = false) {
  const td = document.createElement('td');
  td.className = `px-4 py-2.5 text-xs text-slate-600${truncate ? ' truncate max-w-xs' : ''}`;
  td.textContent = text;
  return td;
}

function refsCell(refs) {
  const td = document.createElement('td');
  td.className = 'px-4 py-2.5';

  if (!refs || refs.length === 0) {
    td.innerHTML = '<span class="text-slate-300 text-xs">—</span>';
    return td;
  }

  const wrap = document.createElement('div');
  wrap.className = 'flex flex-wrap gap-1';

  refs.forEach(ref => {
    const isCve = typeof ref === 'string' && ref.toUpperCase().startsWith('CVE-');
    const pill = document.createElement('span');
    pill.className = `inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono ${
      isCve ? 'bg-red-50 text-red-700 border border-red-100' : 'bg-slate-100 text-slate-600'
    }`;
    pill.textContent = typeof ref === 'string' ? ref : (ref.id || JSON.stringify(ref));
    wrap.appendChild(pill);
  });

  td.appendChild(wrap);
  return td;
}

function importTypeStyle(type) {
  const styles = {
    nmap:        'bg-blue-100 text-blue-700',
    metasploit:  'bg-red-100 text-red-700',
    sharphound:  'bg-purple-100 text-purple-700',
    nuclei:      'bg-orange-100 text-orange-700',
    nessus:      'bg-green-100 text-green-700',
    ghostwriter: 'bg-slate-100 text-slate-600',
    openvas:     'bg-green-100 text-green-700',
  };
  return styles[type] || 'bg-slate-100 text-slate-600';
}
