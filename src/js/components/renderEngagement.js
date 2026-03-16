import { engagements, loadEngagementData, saveEngagementData, loadSnapshots, saveSnapshots, loadImports, saveImports, newHost, newNote, newImport, saveEngagements } from '../data/index.js';
import { detectFileType, parseNmap, parseMetasploit, parseNessus, parseNuciei, parseSharpHound, parseGhostwriter, checkParseQuality } from '../data/parsers.js';
import { btn } from '../ui/elements.js';
import { toastSuccess, toastError } from '../ui/toast.js';
import { renderSidebar } from './renderEngagements.js';
import { triggerGraphSync } from '../data/graph.js';

export async function renderEngagement(engagementId) {
  const container = document.getElementById('app-content');
  container.innerHTML = '<p class="text-slate-400 text-sm text-center py-12">Loading…</p>';

  const eng = engagements.find(e => e.id === engagementId);
  if (!eng) { container.innerHTML = '<p class="text-slate-400 text-sm text-center py-12">Engagement not found.</p>'; return; }

  let data      = await loadEngagementData(engagementId);
  let snapshots = await loadSnapshots(engagementId);
  let imports   = await loadImports(engagementId);

  // Subnet collapse state — null means "not yet initialized"
  let collapsedSubnets = null;

  // Tab state
  let activeTab = 'overview'; // 'overview' | 'analytics' | 'topology' | 'pathing'

  render();

  function render() {
    container.innerHTML = '';

    // ── Edit button (top-right) ───────────────────────────
    const editRow = document.createElement('div');
    editRow.className = 'flex justify-end mb-4';
    const editBtn = btn('Edit', 'secondary');
    editBtn.className += ' text-xs';
    editBtn.onclick = () => showEngagementForm();
    editRow.appendChild(editBtn);
    container.appendChild(editRow);

    // ── Tab bar ───────────────────────────────────────────
    const tabBar = document.createElement('div');
    tabBar.className = 'flex items-center gap-1 mb-6 border-b border-slate-200';

    const ingestErrors = snapshots
      .map(snap => ({ snap, check: checkParseQuality(snap) }))
      .filter(({ check }) => !check.ok);

    const tabs = [
      { id: 'overview',      label: 'Overview' },
      { id: 'analytics',     label: 'Analytics' },
      { id: 'topology',      label: 'Topology' },
      { id: 'pathing',       label: 'Attack Path' },
      { id: 'ingest-errors', label: ingestErrors.length > 0 ? `Ingest Errors (${ingestErrors.length})` : 'Ingest Errors' },
    ];

    tabs.forEach(({ id, label }) => {
      const tab = document.createElement('button');
      tab.type = 'button';
      tab.className = `px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
        activeTab === id
          ? 'border-indigo-600 text-indigo-700'
          : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
      }`;
      tab.textContent = label;
      tab.onclick = () => {
        activeTab = id;
        render();
      };
      tabBar.appendChild(tab);
    });

    // Sync button — only on topology/pathing tabs
    if (activeTab !== 'overview') {
      const syncBtn = btn('↺ Sync Graph', 'ghost');
      syncBtn.className += ' text-xs ml-auto';
      syncBtn.onclick = async () => {
        syncBtn.disabled = true;
        syncBtn.textContent = 'Syncing…';
        try {
          await triggerGraphSync(engagementId);
          toastSuccess('Graph synced.');
          render();
        } catch (e) {
          toastError('Sync failed: ' + e.message);
          syncBtn.disabled = false;
          syncBtn.textContent = '↺ Sync Graph';
        }
      };
      tabBar.appendChild(syncBtn);
    }

    container.appendChild(tabBar);

    // ── Tab content ───────────────────────────────────────
    if (activeTab === 'analytics') {
      renderAnalyticsTab(container, data.hosts, snapshots, (hostId) =>
        import('./renderHost.js').then(r => r.renderHost(engagementId, hostId, data, snapshots, render, imports))
      );
      return;
    }

    if (activeTab === 'topology') {
      const topologyContainer = document.createElement('div');
      container.appendChild(topologyContainer);
      import('./renderTopology.js').then(m =>
        m.renderTopology(
          engagementId,
          topologyContainer,
          (hostId) => import('./renderHost.js').then(r => r.renderHost(engagementId, hostId, data, snapshots, render, imports)),
        )
      );
      return;
    }

    if (activeTab === 'pathing') {
      const pathingContainer = document.createElement('div');
      container.appendChild(pathingContainer);
      import('./renderPathing.js').then(m => m.renderPathing(engagementId, pathingContainer));
      return;
    }

    if (activeTab === 'ingest-errors') {
      renderIngestErrorsTab(container, ingestErrors, data.hosts, (hostId) =>
        import('./renderHost.js').then(r => r.renderHost(engagementId, hostId, data, snapshots, render, imports))
      );
      return;
    }

    // ── Two-column layout ─────────────────────────────────
    const cols = document.createElement('div');
    cols.className = 'grid grid-cols-3 gap-6';

    // Left: host table (2/3 width)
    const hostCol = document.createElement('div');
    hostCol.className = 'col-span-2';

    const hostsHeader = document.createElement('div');
    hostsHeader.className = 'flex items-center justify-between mb-3';
    const hostsTitle = document.createElement('h3');
    hostsTitle.className = 'text-sm font-semibold text-slate-700';
    hostsTitle.textContent = 'Hosts';
    const hostBtns = document.createElement('div');
    hostBtns.className = 'flex gap-2';
    const importBtn = btn('↑ Import Scan', 'secondary');
    importBtn.className += ' text-xs';
    importBtn.onclick = () => showImportForm();
    const addHostBtn = btn('+ Add Host', 'secondary');
    addHostBtn.className += ' text-xs';
    addHostBtn.onclick = () => showHostForm(null);
    hostBtns.appendChild(importBtn);
    hostBtns.appendChild(addHostBtn);
    hostsHeader.appendChild(hostsTitle);
    hostsHeader.appendChild(hostBtns);
    hostCol.appendChild(hostsHeader);

    if (data.hosts.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'text-slate-400 text-sm italic';
      empty.textContent = 'No hosts yet.';
      hostCol.appendChild(empty);
    } else {
      // Group by /24 subnet (dual-NIC hosts appear in each subnet they touch)
      const grouped = groupBySubnet(data.hosts, snapshots);
      const subnetKeys = [...grouped.keys()];

      // First render: auto-collapse all subnets if there are multiple
      if (collapsedSubnets === null) {
        collapsedSubnets = subnetKeys.length > 1 ? new Set(subnetKeys) : new Set();
      }

      const table = document.createElement('table');
      table.className = 'w-full text-sm bg-white rounded-xl border border-slate-100 overflow-hidden';

      const thead = document.createElement('thead');
      thead.innerHTML = `<tr class="border-b border-slate-100">
        <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide w-8"></th>
        <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">IP</th>
        <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">Hostname</th>
        <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">OS</th>
        <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">Status</th>
        <th class="text-right px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">Snaps</th>
      </tr>`;
      table.appendChild(thead);

      const tbody = document.createElement('tbody');

      subnetKeys.forEach(subnet => {
        const hosts = grouped.get(subnet);
        const isCollapsed = collapsedSubnets.has(subnet);
        const compromisedCount = hosts.filter(({ host }) => host.status === 'compromised').length;
        const snapTotal = hosts.reduce((n, { host }) => n + snapshots.filter(s => s.hostId === host.id).length, 0);

        // Subnet header row
        if (subnetKeys.length > 1) {
          const subnetRow = document.createElement('tr');
          subnetRow.className = 'bg-slate-50 border-b border-slate-200 cursor-pointer select-none hover:bg-slate-100 transition-colors';
          subnetRow.onclick = () => {
            if (isCollapsed) collapsedSubnets.delete(subnet);
            else collapsedSubnets.add(subnet);
            render();
          };

          const chevron = isCollapsed ? '▶' : '▼';
          subnetRow.innerHTML = `
            <td class="px-3 py-2 text-slate-400 text-xs">${chevron}</td>
            <td colspan="3" class="px-4 py-2 font-mono text-xs font-semibold text-slate-600">${subnet}.0/24</td>
            <td class="px-4 py-2 text-xs text-slate-400">${hosts.length} host${hosts.length !== 1 ? 's' : ''}${compromisedCount ? ` · <span class="text-red-500">${compromisedCount} compromised</span>` : ''}</td>
            <td class="px-4 py-2 text-right text-xs text-slate-400">${snapTotal || '—'}</td>
          `;
          tbody.appendChild(subnetRow);
        }

        // Host rows
        if (!isCollapsed) {
          hosts.forEach(({ host, displayIp }) => {
            const snapCount = snapshots.filter(s => s.hostId === host.id).length;
            const isAlt = displayIp !== host.ip;
            const ipCell = isAlt
              ? `<span class="font-mono text-xs font-semibold text-slate-700">${displayIp}</span><span class="ml-1 text-slate-400 text-xs font-mono">(${host.ip})</span>`
              : `<span class="font-mono text-xs font-semibold text-slate-700">${displayIp || '—'}</span>`;
            const tr = document.createElement('tr');
            tr.className = 'border-b border-slate-50 hover:bg-slate-50 cursor-pointer transition-colors';
            tr.innerHTML = `
              <td class="px-3 py-2.5"></td>
              <td class="px-4 py-2.5">${ipCell}</td>
              <td class="px-4 py-2.5 text-slate-600 truncate max-w-xs">${host.hostname || '—'}</td>
              <td class="px-4 py-2.5 text-slate-500 text-xs">${host.os || host.osFamily || '—'}</td>
              <td class="px-4 py-2.5"><span class="badge badge-${host.status}">${host.status}</span></td>
              <td class="px-4 py-2.5 text-right text-xs text-slate-400">${snapCount || '—'}</td>
            `;
            tr.onclick = () => import('./renderHost.js').then(m => m.renderHost(engagementId, host.id, data, snapshots, render, imports));
            tbody.appendChild(tr);
          });
        }
      });

      table.appendChild(tbody);
      hostCol.appendChild(table);
    }

    cols.appendChild(hostCol);

    // Right: notes (1/3 width)
    const noteCol = document.createElement('div');

    const notesHeader = document.createElement('div');
    notesHeader.className = 'flex items-center justify-between mb-3';
    const notesTitle = document.createElement('h3');
    notesTitle.className = 'text-sm font-semibold text-slate-700';
    notesTitle.textContent = 'Notes';
    const addNoteBtn = btn('+ Add', 'secondary');
    addNoteBtn.className += ' text-xs';
    addNoteBtn.onclick = () => showNoteForm();
    notesHeader.appendChild(notesTitle);
    notesHeader.appendChild(addNoteBtn);
    noteCol.appendChild(notesHeader);

    const engNotes = (data.notes || []).filter(n => !n.hostId).sort((a, b) => b.timestamp - a.timestamp);

    if (engNotes.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'text-slate-400 text-sm italic';
      empty.textContent = 'No notes yet.';
      noteCol.appendChild(empty);
    } else {
      engNotes.forEach(note => {
        const card = document.createElement('div');
        card.className = 'bg-white rounded-xl border border-slate-100 p-3 mb-2';

        const ts = document.createElement('p');
        ts.className = 'text-xs text-slate-400 mb-1';
        ts.textContent = new Date(note.timestamp).toLocaleString();

        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.textContent = '×';
        delBtn.className = 'float-right text-slate-300 hover:text-red-400 text-lg leading-none ml-2';
        delBtn.onclick = async () => {
          data.notes = data.notes.filter(n => n.id !== note.id);
          try { await saveEngagementData(engagementId, data); render(); }
          catch { toastError('Could not delete note.'); }
        };

        const text = document.createElement('p');
        text.className = 'text-sm text-slate-700 whitespace-pre-wrap';
        text.textContent = note.text;

        card.appendChild(delBtn);
        card.appendChild(ts);
        card.appendChild(text);
        noteCol.appendChild(card);
      });
    }

    cols.appendChild(noteCol);
    container.appendChild(cols);

    // ── Imports section ───────────────────────────────────
    if (imports.length > 0) {
      const importsSection = document.createElement('div');
      importsSection.className = 'mt-6';

      const importsHeader = document.createElement('h3');
      importsHeader.className = 'text-sm font-semibold text-slate-700 mb-3';
      importsHeader.textContent = `Scan Imports (${imports.length})`;
      importsSection.appendChild(importsHeader);

      const importGrid = document.createElement('div');
      importGrid.className = 'grid grid-cols-3 gap-3';

      imports.slice().sort((a, b) => b.importedAt - a.importedAt).forEach(imp => {
        const card = document.createElement('div');
        card.className = 'bg-white rounded-xl border border-slate-200 px-4 py-3 flex items-start gap-3 cursor-pointer hover:border-indigo-300 hover:shadow-sm transition-all';
        card.onclick = () => import('./renderImport.js').then(m => m.renderImport(engagementId, imp, render));

        const typeBadge = document.createElement('span');
        typeBadge.className = `inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold flex-shrink-0 mt-0.5 ${importTypeStyle(imp.importType)}`;
        typeBadge.textContent = imp.importType;

        const info = document.createElement('div');
        info.className = 'min-w-0';

        const fname = document.createElement('p');
        fname.className = 'text-sm text-slate-700 truncate font-medium';
        fname.textContent = imp.fileName;

        const ts = document.createElement('p');
        ts.className = 'text-xs text-slate-400 mt-0.5';
        ts.textContent = new Date(imp.importedAt).toLocaleString();

        const summary = document.createElement('p');
        summary.className = 'text-xs text-slate-500 mt-1';
        summary.textContent = formatImportSummary(imp);

        info.appendChild(fname);
        info.appendChild(ts);
        info.appendChild(summary);
        card.appendChild(typeBadge);
        card.appendChild(info);
        importGrid.appendChild(card);
      });

      importsSection.appendChild(importGrid);
      container.appendChild(importsSection);
    }
  }

  // ── Import form ───────────────────────────────────────

  function showImportForm() {
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';

    const box = document.createElement('div');
    box.className = 'modal-box max-w-lg';

    const title = document.createElement('h3');
    title.className = 'text-lg font-bold text-slate-800 mb-1';
    title.textContent = 'Import Scan File';
    box.appendChild(title);

    const hint = document.createElement('p');
    hint.className = 'text-xs text-slate-400 mb-4';
    hint.textContent = 'Supported: Nmap XML (-oX), Metasploit db_export XML. Recognized but not yet parsed: Nessus, Nuclei, SharpHound, Ghostwriter.';
    box.appendChild(hint);

    // File picker
    const fileWrap = document.createElement('div');
    fileWrap.className = 'mb-3';
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.xml,.nessus,.jsonl,.json,.zip,.csv';
    fileInput.className = 'block w-full text-sm text-slate-600 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-medium file:bg-indigo-50 file:text-indigo-700 hover:file:bg-indigo-100 cursor-pointer';
    fileWrap.appendChild(fileInput);
    box.appendChild(fileWrap);

    // Detection + preview area
    const preview = document.createElement('div');
    preview.className = 'hidden bg-slate-50 rounded-lg px-3 py-2.5 mb-4 text-sm';
    box.appendChild(preview);

    let parsedResult = null;
    let detectedType = null;
    let fileContent  = null;
    let fileName     = null;

    fileInput.onchange = () => {
      const file = fileInput.files[0];
      if (!file) return;
      fileName = file.name;

      // Detect type from filename (ZIP detection only needs the name)
      const earlyType = detectFileType(fileName, '');
      const isZip = earlyType === 'sharphound';

      const reader = new FileReader();
      reader.onload = async e => {
        parsedResult = null;

        preview.className = 'bg-slate-50 rounded-lg px-3 py-2.5 mb-4 text-sm';
        preview.innerHTML = '';

        const typeEl = document.createElement('p');
        typeEl.className = 'font-medium text-slate-700 mb-1';

        if (isZip) {
          detectedType = 'sharphound';
          fileContent  = null; // binary — not stored as text
        } else {
          fileContent  = e.target.result;
          detectedType = detectFileType(fileName, fileContent);
        }

        if (detectedType === 'unknown') {
          typeEl.textContent = 'Unrecognized file format';
          typeEl.className += ' text-amber-600';
          preview.appendChild(typeEl);
          saveBtn.disabled = true;
          return;
        }

        typeEl.innerHTML = `Detected: <span class="font-mono">${detectedType}</span>`;
        preview.appendChild(typeEl);

        try {
          if (detectedType === 'sharphound') {
            parsedResult = await parseSharpHound(e.target.result);
            addPreviewStat(preview, `${parsedResult.computers.length} computers · ${parsedResult.users.length} users · ${parsedResult.groups.length} groups · ${parsedResult.domains.length} domains`);
          } else if (detectedType === 'nmap') {
            parsedResult = parseNmap(fileContent);
            const openPorts = parsedResult.hosts.reduce((n, h) => n + h.ports.filter(p => p.state === 'open').length, 0);
            addPreviewStat(preview, `${parsedResult.hostsUp} hosts up of ${parsedResult.hostsTotal} · ${openPorts} open ports`);
          } else if (detectedType === 'metasploit') {
            parsedResult = parseMetasploit(fileContent);
            addPreviewStat(preview, `${parsedResult.hosts.length} hosts · ${parsedResult.services.length} services · ${parsedResult.vulns.length} vulns · ${parsedResult.credentials.length} creds`);
          } else if (detectedType === 'nessus') {
            parsedResult = parseNessus(fileContent);
            const allFindings = parsedResult.hosts.flatMap(h => h.findings);
            const critCount = allFindings.filter(f => f.severity === 4).length;
            const highCount = allFindings.filter(f => f.severity === 3).length;
            addPreviewStat(preview, `${parsedResult.hosts.length} hosts · ${allFindings.length} findings · ${critCount} critical · ${highCount} high`);
          } else if (detectedType === 'nuclei') {
            parsedResult = parseNuciei(fileContent);
            const findings = parsedResult.findings;
            const critCount = findings.filter(f => f.severity === 'critical').length;
            const highCount = findings.filter(f => f.severity === 'high').length;
            addPreviewStat(preview, `${findings.length} findings · ${critCount} critical · ${highCount} high`);
          } else if (detectedType === 'ghostwriter') {
            parsedResult = parseGhostwriter(fileContent);
            const ops = new Set(parsedResult.entries.map(e => e.operatorName).filter(Boolean));
            addPreviewStat(preview, `${parsedResult.entries.length} log entries · ${ops.size} operator${ops.size !== 1 ? 's' : ''}`);
          } else {
            addPreviewStat(preview, 'Parser not yet implemented — file will be recorded but not analyzed.');
            saveBtn.disabled = false;
          }
          saveBtn.disabled = false;
        } catch (err) {
          const errEl = document.createElement('p');
          errEl.className = 'text-red-500 text-xs mt-1';
          errEl.textContent = `Parse error: ${err.message}`;
          preview.appendChild(errEl);
          saveBtn.disabled = true;
        }
      };

      if (isZip) {
        reader.readAsArrayBuffer(file);
      } else {
        reader.readAsText(file);
      }
    };

    const actions = document.createElement('div');
    actions.className = 'flex gap-3';

    const saveBtn = btn('Import', 'primary');
    saveBtn.className += ' flex-1';
    saveBtn.disabled = true;
    saveBtn.onclick = async () => {
      saveBtn.disabled = true;
      try {
        // Build summary stats
        const summary = buildImportSummary(detectedType, parsedResult);

        const imp = newImport({
          importType: detectedType,
          fileName,
          parsed:  parsedResult,
          summary,
        });

        // Auto-create/update hosts for parseable types
        let hostDelta = { added: 0, updated: 0 };
        if (parsedResult) {
          hostDelta = mergeHostsFromImport(data, imp, snapshots);
          await saveEngagementData(engagementId, data);
        }

        imports = [...imports, imp];
        await saveImports(engagementId, imports);

        const msg = parsedResult
          ? `Imported. ${hostDelta.added} new host${hostDelta.added !== 1 ? 's' : ''}, ${hostDelta.updated} updated.`
          : 'Import recorded.';
        toastSuccess(msg);
        backdrop.remove();
        render();
      } catch (err) {
        toastError(err.message || 'Could not save import.');
        saveBtn.disabled = false;
      }
    };

    const cancelBtn = btn('Cancel', 'ghost');
    cancelBtn.onclick = () => backdrop.remove();
    actions.appendChild(saveBtn);
    actions.appendChild(cancelBtn);
    box.appendChild(actions);

    backdrop.appendChild(box);
    backdrop.onclick = e => { if (e.target === backdrop) backdrop.remove(); };
    document.body.appendChild(backdrop);
  }

  // ── Engagement edit form ──────────────────────────────

  function showEngagementForm() {
    const copy = { ...eng };
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    const box = document.createElement('div');
    box.className = 'modal-box';

    const title = document.createElement('h3');
    title.className = 'text-lg font-bold text-slate-800 mb-4';
    title.textContent = 'Edit Engagement';
    box.appendChild(title);

    function field(labelText, key, placeholder = '') {
      const wrap = document.createElement('div');
      wrap.className = 'mb-3';
      const label = document.createElement('label');
      label.className = 'block text-sm font-medium text-slate-700 mb-1';
      label.textContent = labelText;
      const input = document.createElement('input');
      input.type = 'text';
      input.className = 'field';
      input.placeholder = placeholder;
      input.value = copy[key] || '';
      input.oninput = e => { copy[key] = e.target.value; };
      wrap.appendChild(label);
      wrap.appendChild(input);
      box.appendChild(wrap);
      return input;
    }

    field('Name', 'name');
    field('Client', 'client');
    field('Start date', 'startDate', 'YYYY-MM-DD');

    const wrap = document.createElement('div');
    wrap.className = 'mb-4';
    const lbl = document.createElement('label');
    lbl.className = 'block text-sm font-medium text-slate-700 mb-1';
    lbl.textContent = 'Status';
    const sel = document.createElement('select');
    sel.className = 'field';
    ['active', 'closed'].forEach(s => {
      const opt = document.createElement('option');
      opt.value = s;
      opt.textContent = s.charAt(0).toUpperCase() + s.slice(1);
      opt.selected = copy.status === s;
      sel.appendChild(opt);
    });
    sel.onchange = e => { copy.status = e.target.value; };
    wrap.appendChild(lbl);
    wrap.appendChild(sel);
    box.appendChild(wrap);

    const actions = document.createElement('div');
    actions.className = 'flex gap-3 mt-4';
    const saveBtn = btn('Save', 'primary');
    saveBtn.className += ' flex-1';
    saveBtn.onclick = async () => {
      saveBtn.disabled = true;
      try {
        Object.assign(eng, copy);
        const updated = engagements.map(e => e.id === eng.id ? eng : e);
        await saveEngagements(updated);
        toastSuccess('Saved.');
        backdrop.remove();
        renderSidebar();
        render();
      } catch (err) {
        toastError(err.message || 'Could not save.');
        saveBtn.disabled = false;
      }
    };
    const cancelBtn = btn('Cancel', 'ghost');
    cancelBtn.onclick = () => backdrop.remove();
    actions.appendChild(saveBtn);
    actions.appendChild(cancelBtn);
    box.appendChild(actions);

    backdrop.appendChild(box);
    backdrop.onclick = e => { if (e.target === backdrop) backdrop.remove(); };
    document.body.appendChild(backdrop);
  }

  // ── Host form ─────────────────────────────────────────

  function showHostForm(existing) {
    const isNew = !existing;
    const host  = existing ? { ...existing } : newHost();

    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    const box = document.createElement('div');
    box.className = 'modal-box';

    const title = document.createElement('h3');
    title.className = 'text-lg font-bold text-slate-800 mb-4';
    title.textContent = isNew ? 'Add Host' : 'Edit Host';
    box.appendChild(title);

    function fieldRow(labelText, key, placeholder = '') {
      const wrap = document.createElement('div');
      wrap.className = 'mb-3';
      const label = document.createElement('label');
      label.className = 'block text-sm font-medium text-slate-700 mb-1';
      label.textContent = labelText;
      const input = document.createElement('input');
      input.type = 'text';
      input.className = 'field';
      input.placeholder = placeholder;
      input.value = host[key] || '';
      input.oninput = e => { host[key] = e.target.value; };
      wrap.appendChild(label);
      wrap.appendChild(input);
      box.appendChild(wrap);
      return input;
    }

    const ipInput = fieldRow('IP Address', 'ip', 'e.g. 192.168.1.10');
    fieldRow('Hostname', 'hostname', 'e.g. DC01.corp.local');
    fieldRow('OS', 'os', 'e.g. Windows Server 2019');

    const statusWrap = document.createElement('div');
    statusWrap.className = 'mb-4';
    const statusLabel = document.createElement('label');
    statusLabel.className = 'block text-sm font-medium text-slate-700 mb-1';
    statusLabel.textContent = 'Status';
    const statusSel = document.createElement('select');
    statusSel.className = 'field';
    ['observed', 'compromised', 'unknown'].forEach(s => {
      const opt = document.createElement('option');
      opt.value = s;
      opt.textContent = s.charAt(0).toUpperCase() + s.slice(1);
      opt.selected = host.status === s;
      statusSel.appendChild(opt);
    });
    statusSel.onchange = e => { host.status = e.target.value; };
    statusWrap.appendChild(statusLabel);
    statusWrap.appendChild(statusSel);
    box.appendChild(statusWrap);

    const actions = document.createElement('div');
    actions.className = 'flex gap-3';
    const saveBtn = btn(isNew ? 'Add Host' : 'Save', 'primary');
    saveBtn.className += ' flex-1';
    saveBtn.onclick = async () => {
      host.ip = host.ip?.trim();
      if (!host.ip) { ipInput.focus(); return; }
      saveBtn.disabled = true;
      try {
        data.hosts = isNew
          ? [...(data.hosts || []), host]
          : data.hosts.map(h => h.id === host.id ? host : h);
        await saveEngagementData(engagementId, data);
        toastSuccess(isNew ? 'Host added.' : 'Saved.');
        backdrop.remove();
        render();
      } catch (err) {
        toastError(err.message || 'Could not save.');
        saveBtn.disabled = false;
      }
    };
    const cancelBtn = btn('Cancel', 'ghost');
    cancelBtn.onclick = () => backdrop.remove();
    if (!isNew) {
      const delBtn = btn('Delete', 'danger');
      delBtn.onclick = async () => {
        if (!confirm(`Delete host ${host.ip}?`)) return;
        data.hosts = data.hosts.filter(h => h.id !== host.id);
        try {
          await saveEngagementData(engagementId, data);
          toastSuccess('Host deleted.');
          backdrop.remove();
          render();
        } catch { toastError('Could not delete.'); }
      };
      actions.appendChild(delBtn);
    }
    actions.appendChild(saveBtn);
    actions.appendChild(cancelBtn);
    box.appendChild(actions);
    backdrop.appendChild(box);
    backdrop.onclick = e => { if (e.target === backdrop) backdrop.remove(); };
    document.body.appendChild(backdrop);
    ipInput.focus();
  }

  // ── Note form ─────────────────────────────────────────


  function showNoteForm() {
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    const box = document.createElement('div');
    box.className = 'modal-box';

    const title = document.createElement('h3');
    title.className = 'text-lg font-bold text-slate-800 mb-3';
    title.textContent = 'Add Note';
    box.appendChild(title);

    const textarea = document.createElement('textarea');
    textarea.className = 'field mb-4 resize-none';
    textarea.rows = 5;
    textarea.placeholder = 'What happened…';
    box.appendChild(textarea);

    const actions = document.createElement('div');
    actions.className = 'flex gap-3';
    const saveBtn = btn('Add Note', 'primary');
    saveBtn.className += ' flex-1';
    saveBtn.onclick = async () => {
      const text = textarea.value.trim();
      if (!text) { textarea.focus(); return; }
      saveBtn.disabled = true;
      const note = newNote({ text });
      data.notes = [...(data.notes || []), note];
      try {
        await saveEngagementData(engagementId, data);
        backdrop.remove();
        render();
      } catch (err) {
        toastError(err.message || 'Could not save.');
        saveBtn.disabled = false;
      }
    };
    const cancelBtn = btn('Cancel', 'ghost');
    cancelBtn.onclick = () => backdrop.remove();
    actions.appendChild(saveBtn);
    actions.appendChild(cancelBtn);
    box.appendChild(actions);
    backdrop.appendChild(box);
    backdrop.onclick = e => { if (e.target === backdrop) backdrop.remove(); };
    document.body.appendChild(backdrop);
    textarea.focus();
  }
}

// ── Helpers ───────────────────────────────────────────────

function groupBySubnet(hosts, snapshots) {
  // Returns Map<subnet, Array<{ host, displayIp }>>
  // Dual-NIC hosts appear once per /24 they have an IP in (from primary IP + ipconfig snapshots).
  const map = new Map();

  for (const host of hosts) {
    // Collect all IPv4 addresses for this host
    const allIps = new Set();
    if (host.ip) allIps.add(host.ip);

    const ipcfgSnaps = snapshots.filter(s => s.hostId === host.id && s.commandType === 'ipconfig' && s.parsed);
    for (const snap of ipcfgSnaps) {
      for (const iface of snap.parsed.interfaces || []) {
        for (const addr of iface.addresses || []) {
          if (addr.ip && addr.family !== 'IPv6' && !addr.ip.startsWith('127.') && !addr.ip.startsWith('169.254.')) {
            allIps.add(addr.ip);
          }
        }
      }
    }

    // Place host in each /24 it appears in
    const seenSubnets = new Set();
    for (const ip of allIps) {
      const parts = ip.split('.');
      const key = parts.length === 4 ? parts.slice(0, 3).join('.') : 'Other';
      if (seenSubnets.has(key)) continue;
      seenSubnets.add(key);
      if (!map.has(key)) map.set(key, []);
      map.get(key).push({ host, displayIp: ip });
    }

    if (seenSubnets.size === 0) {
      // No valid IP at all — put in Other
      if (!map.has('Other')) map.set('Other', []);
      map.get('Other').push({ host, displayIp: host.ip || '—' });
    }
  }

  // Sort map by subnet key numerically, then sort each group by IP
  const sorted = new Map(
    [...map.entries()]
      .sort(([a], [b]) => ipToNum(a + '.0') - ipToNum(b + '.0'))
      .map(([k, v]) => [k, v.sort((a, b) => ipToNum(a.displayIp) - ipToNum(b.displayIp))])
  );
  return sorted;
}

function ipToNum(ip) {
  const parts = (ip || '').split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return Infinity;
  return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

// ── Import helpers ────────────────────────────────────────

function addPreviewStat(container, text) {
  const el = document.createElement('p');
  el.className = 'text-xs text-slate-500 mt-0.5';
  el.textContent = text;
  container.appendChild(el);
}

function buildImportSummary(type, parsed) {
  if (!parsed) return {};
  if (type === 'nmap') {
    const openPorts = parsed.hosts.reduce((n, h) => n + h.ports.filter(p => p.state === 'open').length, 0);
    return { hostsUp: parsed.hostsUp, hostsTotal: parsed.hostsTotal, openPorts };
  }
  if (type === 'metasploit') {
    return {
      hostCount:  parsed.hosts.length,
      serviceCount: parsed.services.length,
      vulnCount:  parsed.vulns.length,
      credCount:  parsed.credentials.length,
      sessionCount: parsed.sessions.length,
    };
  }
  return {};
}

function formatImportSummary(imp) {
  const s = imp.summary || {};
  if (imp.importType === 'nmap')
    return `${s.hostsUp ?? '?'} hosts up · ${s.openPorts ?? '?'} open ports`;
  if (imp.importType === 'metasploit')
    return [
      s.hostCount    && `${s.hostCount} hosts`,
      s.serviceCount && `${s.serviceCount} services`,
      s.vulnCount    && `${s.vulnCount} vulns`,
      s.credCount    && `${s.credCount} creds`,
    ].filter(Boolean).join(' · ');
  return '';
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

// Auto-create or update hosts from a parsed import.
// Mutates data.hosts in place; returns { added, updated } counts.
function mergeHostsFromImport(data, imp, _snapshots) {
  let added = 0, updated = 0;
  if (!imp.parsed) return { added, updated };

  const hostList = imp.importType === 'nmap'
    ? imp.parsed.hosts.filter(h => h.ip && h.status === 'up')
    : imp.importType === 'metasploit'
    ? imp.parsed.hosts.filter(h => h.ip)
    : [];

  for (const scanHost of hostList) {
    const existing = (data.hosts || []).find(h => h.ip === scanHost.ip);

    // Derive best hostname from scan data
    const hostname = imp.importType === 'nmap'
      ? (scanHost.hostnames.find(n => n.type === 'PTR') || scanHost.hostnames[0])?.name || ''
      : scanHost.hostname || '';

    // Derive OS string
    const os = imp.importType === 'nmap'
      ? scanHost.os?.name || ''
      : scanHost.os ? [scanHost.os.name, scanHost.os.flavor].filter(Boolean).join(' ') : '';

    if (existing) {
      let changed = false;
      if (!existing.hostname && hostname) { existing.hostname = hostname; changed = true; }
      if (!existing.os && os)             { existing.os = os;             changed = true; }
      if (changed) updated++;
    } else {
      data.hosts = [...(data.hosts || []), {
        id:        crypto.randomUUID(),
        ip:        scanHost.ip,
        hostname,
        os,
        osFamily:  'unknown',
        status:    'observed',
        notes:     '',
        createdAt: Date.now(),
      }];
      added++;
    }
  }

  return { added, updated };
}

// ── Analytic Highlights ───────────────────────────────────

function analyzeEngagement(hosts, snapshots) {
  const findings = [];

  // Group snapshots by hostId, keep latest per commandType
  const byHost = {};
  for (const s of snapshots) {
    if (!byHost[s.hostId]) byHost[s.hostId] = {};
    if (!byHost[s.hostId][s.commandType]) byHost[s.hostId][s.commandType] = s;
  }

  const hostMap = Object.fromEntries(hosts.map(h => [h.id, h]));

  for (const [hostId, latest] of Object.entries(byHost)) {
    const host = hostMap[hostId];
    if (!host) continue;

    // ── Credential exposure ────────────────────────────────

    // Sensitive env vars with non-empty values
    for (const v of (latest.env?.parsed?.vars || []).filter(v => v.isSensitive && v.value?.trim())) {
      findings.push({
        severity: 'high', category: 'Credential Exposure',
        title: `Sensitive env var: ${v.key}`,
        detail: v.value.length > 80 ? v.value.slice(0, 80) + '…' : v.value,
        host,
      });
    }

    // Shadow hashes
    const crackable = (latest.shadow?.parsed?.entries || []).filter(e => e.hasHash);
    if (crackable.length) {
      findings.push({
        severity: 'critical', category: 'Credential Exposure',
        title: `${crackable.length} crackable hash${crackable.length !== 1 ? 'es' : ''} in /etc/shadow`,
        detail: crackable.map(e => `${e.username} (${e.hashAlgo})`).join(', '),
        host,
      });
    }

    // ── Privilege escalation ───────────────────────────────

    // Dangerous Windows privileges enabled
    const dangerPrivs = latest.whoami?.parsed?.dangerousPrivileges || [];
    if (dangerPrivs.length) {
      findings.push({
        severity: 'critical', category: 'Privilege Escalation',
        title: `Dangerous privilege${dangerPrivs.length !== 1 ? 's' : ''} enabled: ${dangerPrivs.join(', ')}`,
        detail: `Running as: ${latest.whoami.parsed.username ?? '(unknown)'}`,
        host,
      });
    }

    // SYSTEM scheduled tasks with non-Windows paths
    for (const t of (latest.schtasks?.parsed?.tasks || [])) {
      const isSystem = /^(system|nt authority\\system)$/i.test(t.runAs?.trim());
      const isNonWindows = t.command && !/^(%windir%|c:\\windows)/i.test(t.command.trim());
      if (isSystem && isNonWindows) {
        findings.push({
          severity: 'high', category: 'Persistence / Privilege Escalation',
          title: `SYSTEM scheduled task with non-Windows path`,
          detail: `${t.name}  →  ${t.command}`,
          host,
        });
      }
    }

    // Non-standard SUID binaries
    const nonStdSuid = (latest.suid?.parsed?.binaries || []).filter(b => b.isNonStandard);
    if (nonStdSuid.length) {
      findings.push({
        severity: 'high', category: 'Privilege Escalation',
        title: `${nonStdSuid.length} non-standard SUID binary`,
        detail: nonStdSuid.map(b => b.path).slice(0, 5).join(', '),
        host,
      });
    }

    // Sudo ALL
    if (latest.sudol?.parsed?.canRunAll) {
      findings.push({
        severity: 'critical', category: 'Privilege Escalation',
        title: `User can run ALL commands via sudo`,
        detail: `As: ${latest.sudol.parsed.username ?? '(unknown)'}`,
        host,
      });
    }

    // ── Lateral movement / TTPs ────────────────────────────

    // Interesting history commands
    const interestingCmds = (latest.history?.parsed?.commands || []).filter(c => c.isInteresting);
    if (interestingCmds.length) {
      findings.push({
        severity: 'medium', category: 'Lateral Movement / TTPs',
        title: `${interestingCmds.length} notable command${interestingCmds.length !== 1 ? 's' : ''} in shell history`,
        detail: interestingCmds.slice(0, 3).map(c => c.cmd).join(' · '),
        host,
      });
    }

    // Active sessions with domain users
    const domainSessions = (latest.sessions?.parsed?.sessions || []).filter(s =>
      s.username && s.username.includes('\\') && s.state === 'Active'
    );
    if (domainSessions.length) {
      findings.push({
        severity: 'medium', category: 'Lateral Movement / TTPs',
        title: `${domainSessions.length} active domain session${domainSessions.length !== 1 ? 's' : ''}`,
        detail: domainSessions.map(s => s.username).join(', '),
        host,
      });
    }

    // ── Suspicious traffic ─────────────────────────────────

    // Established connections to non-RFC1918 / non-loopback IPs
    const extConns = (latest.netstat?.parsed?.connections || []).filter(c => {
      if (c.state !== 'ESTABLISHED') return false;
      const ip = c.remoteAddr ?? '';
      if (!ip || ip === '0.0.0.0' || ip.startsWith('127.') || ip.startsWith('::')) return false;
      return !ip.startsWith('10.') && !ip.startsWith('192.168.') && !/^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip);
    });
    if (extConns.length) {
      const uniq = [...new Set(extConns.map(c => `${c.remoteAddr}:${c.remotePort}`))];
      findings.push({
        severity: 'medium', category: 'Suspicious Traffic',
        title: `${extConns.length} established connection${extConns.length !== 1 ? 's' : ''} to external IP`,
        detail: uniq.slice(0, 4).join(', '),
        host,
      });
    }

    // ── Network exposure ───────────────────────────────────

    // Non-admin shares
    const pubShares = (latest.netshare?.parsed?.shares || []).filter(s => !s.isAdmin);
    if (pubShares.length) {
      findings.push({
        severity: 'info', category: 'Network Exposure',
        title: `${pubShares.length} non-admin share${pubShares.length !== 1 ? 's' : ''} exposed`,
        detail: pubShares.map(s => `${s.name}=${s.path ?? '?'}`).join(', '),
        host,
      });
    }

    // Non-RFC1918 pivot routes (not default, not loopback)
    const pivotRoutes = (latest.routes?.parsed?.routes || []).filter(r => {
      if (r.isDefault) return false;
      const dest = r.destination ?? '';
      if (dest.startsWith('127.') || dest === '0.0.0.0') return false;
      return !dest.startsWith('10.') && !dest.startsWith('192.168.') && !/^172\.(1[6-9]|2[0-9]|3[01])\./.test(dest);
    });
    if (pivotRoutes.length) {
      findings.push({
        severity: 'info', category: 'Network Exposure',
        title: `${pivotRoutes.length} non-RFC1918 route${pivotRoutes.length !== 1 ? 's' : ''} — potential pivot path`,
        detail: pivotRoutes.map(r => r.destination).slice(0, 4).join(', '),
        host,
      });
    }

    // Domain admins in local admins group
    const domAdmins = (latest.localadmins?.parsed?.members || []).filter(m => m.isDomain);
    if (domAdmins.length) {
      findings.push({
        severity: 'info', category: 'Access Control',
        title: `Domain account in local Administrators`,
        detail: domAdmins.map(m => m.name).join(', '),
        host,
      });
    }
  }

  const ORDER = { critical: 0, high: 1, medium: 2, info: 3 };
  findings.sort((a, b) => (ORDER[a.severity] ?? 9) - (ORDER[b.severity] ?? 9));
  return findings;
}

function renderAnalyticsTab(container, hosts, snapshots, onHostClick) {
  const findings = analyzeEngagement(hosts, snapshots);

  if (!findings.length) {
    const empty = document.createElement('p');
    empty.className = 'text-slate-400 text-sm italic text-center py-16';
    empty.textContent = 'No findings yet — add snapshots to hosts to populate analytics.';
    container.appendChild(empty);
    return;
  }

  const SEVERITY_STYLE = {
    critical: { badge: 'bg-red-100 text-red-700',    bar: 'bg-red-500',    label: 'Critical' },
    high:     { badge: 'bg-orange-100 text-orange-700', bar: 'bg-orange-400', label: 'High' },
    medium:   { badge: 'bg-amber-100 text-amber-700',  bar: 'bg-amber-400',  label: 'Medium' },
    info:     { badge: 'bg-slate-100 text-slate-600',  bar: 'bg-slate-400',  label: 'Info' },
  };

  // Summary bar
  const summary = document.createElement('div');
  summary.className = 'flex items-center gap-3 mb-5 flex-wrap';
  for (const sev of ['critical', 'high', 'medium', 'info']) {
    const count = findings.filter(f => f.severity === sev).length;
    if (!count) continue;
    const chip = document.createElement('span');
    chip.className = `inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${SEVERITY_STYLE[sev].badge}`;
    chip.innerHTML = `<span class="inline-block w-2 h-2 rounded-full ${SEVERITY_STYLE[sev].bar}"></span>${count} ${SEVERITY_STYLE[sev].label}`;
    summary.appendChild(chip);
  }
  container.appendChild(summary);

  // Group by category
  const byCategory = {};
  for (const f of findings) {
    (byCategory[f.category] ||= []).push(f);
  }

  for (const [category, items] of Object.entries(byCategory)) {
    const section = document.createElement('div');
    section.className = 'mb-5';

    const catHeader = document.createElement('p');
    catHeader.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2';
    catHeader.textContent = category;
    section.appendChild(catHeader);

    const cards = document.createElement('div');
    cards.className = 'space-y-2';

    for (const f of items) {
      const s = SEVERITY_STYLE[f.severity];
      const card = document.createElement('div');
      card.className = 'bg-white border border-slate-200 rounded-lg px-4 py-3 flex items-start gap-3';

      const dot = document.createElement('span');
      dot.className = `inline-block w-2 h-2 rounded-full flex-shrink-0 mt-1.5 ${s.bar}`;

      const body = document.createElement('div');
      body.className = 'flex-1 min-w-0';

      const titleRow = document.createElement('div');
      titleRow.className = 'flex items-center gap-2 flex-wrap';

      const titleEl = document.createElement('span');
      titleEl.className = 'text-sm font-medium text-slate-800';
      titleEl.textContent = f.title;

      const hostBtn = document.createElement('button');
      hostBtn.type = 'button';
      hostBtn.className = 'text-xs text-indigo-500 hover:text-indigo-700 font-medium flex-shrink-0';
      hostBtn.textContent = f.host.hostname || f.host.ip || f.host.id;
      hostBtn.onclick = () => onHostClick(f.host.id);

      titleRow.appendChild(titleEl);
      titleRow.appendChild(hostBtn);
      body.appendChild(titleRow);

      if (f.detail) {
        const detail = document.createElement('p');
        detail.className = 'text-xs text-slate-500 font-mono mt-0.5 truncate';
        detail.textContent = f.detail;
        detail.title = f.detail;
        body.appendChild(detail);
      }

      card.appendChild(dot);
      card.appendChild(body);
      cards.appendChild(card);
    }

    section.appendChild(cards);
    container.appendChild(section);
  }
}

function renderIngestErrorsTab(container, ingestErrors, hosts, onHostClick) {
  const hostMap = Object.fromEntries(hosts.map(h => [h.id, h]));

  if (ingestErrors.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'text-center py-16 text-slate-400 text-sm';
    empty.textContent = 'No parse errors detected across this engagement.';
    container.appendChild(empty);
    return;
  }

  const note = document.createElement('p');
  note.className = 'text-xs text-slate-400 mb-4';
  note.textContent = 'These snapshots were parsed but returned empty or unexpected results. The raw output may be in an unsupported format variant.';
  container.appendChild(note);

  const list = document.createElement('div');
  list.className = 'space-y-3';

  for (const { snap, check } of ingestErrors) {
    const host = hostMap[snap.hostId];
    const card = document.createElement('div');
    card.className = 'bg-white border border-amber-200 rounded-xl p-4 flex items-start gap-3';

    const icon = document.createElement('span');
    icon.className = 'text-amber-500 text-lg flex-shrink-0';
    icon.textContent = '⚠';

    const body = document.createElement('div');
    body.className = 'flex-1 min-w-0';

    const titleRow = document.createElement('div');
    titleRow.className = 'flex items-center gap-2 flex-wrap';

    const typeBadge = document.createElement('span');
    typeBadge.className = 'text-xs font-mono bg-slate-100 text-slate-600 px-2 py-0.5 rounded';
    typeBadge.textContent = snap.commandType;

    const hostLink = document.createElement('button');
    hostLink.type = 'button';
    hostLink.className = 'text-sm font-medium text-indigo-600 hover:underline truncate';
    hostLink.textContent = host?.label || host?.ip || snap.hostId;
    hostLink.onclick = () => onHostClick(snap.hostId);

    const ts = document.createElement('span');
    ts.className = 'text-xs text-slate-400 ml-auto';
    ts.textContent = snap.timestamp ? new Date(snap.timestamp).toLocaleString() : '';

    titleRow.appendChild(typeBadge);
    titleRow.appendChild(hostLink);
    titleRow.appendChild(ts);

    const msg = document.createElement('p');
    msg.className = 'text-xs text-amber-700 mt-1';
    msg.textContent = check.warning;

    body.appendChild(titleRow);
    body.appendChild(msg);
    card.appendChild(icon);
    card.appendChild(body);
    list.appendChild(card);
  }

  container.appendChild(list);
}
