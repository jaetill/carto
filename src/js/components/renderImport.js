import { btn } from '../ui/elements.js';

export function renderImport(engagementId, importObj, onBack) {
  const container = document.getElementById('app-content');
  container.innerHTML = '';

  if (importObj.importType === 'nmap') {
    renderNmap(container, importObj, onBack);
  } else if (importObj.importType === 'metasploit') {
    renderMetasploit(container, importObj, onBack);
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
