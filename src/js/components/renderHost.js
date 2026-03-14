import { saveEngagementData, saveSnapshots, newSnapshot, newNote } from '../data/index.js';
import { btn } from '../ui/elements.js';
import { toastSuccess, toastError } from '../ui/toast.js';
import { detectOS, detectCommand, parseNetstat, parsePslist, parseIpconfig, parseUname, parseArp, diffSnapshots } from '../data/parsers.js';

export function renderHost(engagementId, hostId, data, snapshots, onBack) {
  const container = document.getElementById('app-content');
  const host = data.hosts.find(h => h.id === hostId);
  if (!host) { onBack(); return; }

  let activeTab = 'snapshots';

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

    ['snapshots', 'notes'].forEach(tab => {
      const t = document.createElement('button');
      t.type = 'button';
      t.className = `px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
        activeTab === tab
          ? 'border-indigo-600 text-indigo-600'
          : 'border-transparent text-slate-500 hover:text-slate-700'
      }`;
      t.textContent = tab === 'snapshots'
        ? `Snapshots (${hostSnaps.length})`
        : `Notes (${hostNotes.length})`;
      t.onclick = () => { activeTab = tab; render(); };
      tabBar.appendChild(t);
    });
    container.appendChild(tabBar);

    // ── Tab content ───────────────────────────────────────
    if (activeTab === 'snapshots') {
      renderSnapshotsTab(hostSnaps);
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

    hostSnaps.forEach((snap, i) => {
      const prevSnap = hostSnaps.find((s, j) => j > i && s.commandType === snap.commandType);
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
    });
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
    hint.textContent = 'Supports: netstat, ps / tasklist, ipconfig / ifconfig, uname, arp. OS and command type detected automatically.';
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
        if (cmdType === 'netstat')  parsed = parseNetstat(raw, osFamily);
        if (cmdType === 'pslist')   parsed = parsePslist(raw, osFamily);
        if (cmdType === 'ipconfig') parsed = parseIpconfig(raw, osFamily);
        if (cmdType === 'uname')    parsed = parseUname(raw);
        if (cmdType === 'arp')      parsed = parseArp(raw);
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
      table.className = 'w-full text-xs font-mono';
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
    table.className = 'w-full text-xs font-mono';
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
    table.className = 'w-full text-xs font-mono';
    entries.forEach(e => {
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
    card.appendChild(table);
    return;
  }
}

function formatDiffItems(type, items) {
  if (type === 'netstat')  return items.slice(0, 3).map(c => `${c.proto} :${c.localPort}`).join(', ');
  if (type === 'pslist')   return items.slice(0, 5).map(p => p.name).join(', ');
  if (type === 'arp')      return items.slice(0, 3).map(e => `${e.ip} (${e.mac})`).join(', ');
  if (type === 'ipconfig') return items.slice(0, 3).join(', ');
  return '';
}
