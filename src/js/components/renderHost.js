import { saveEngagementData, saveSnapshots, newSnapshot, newNote } from '../data/index.js';
import { btn } from '../ui/elements.js';
import { toastSuccess, toastError } from '../ui/toast.js';
import { detectOS, detectCommand, parseNetstat, parsePslist, parseIpconfig, parseUname, parseArp, diffSnapshots } from '../data/parsers.js';

export function renderHost(engagementId, hostId, data, snapshots, onBack) {
  const container = document.getElementById('app-content');
  const host = data.hosts.find(h => h.id === hostId);
  if (!host) { onBack(); return; }

  render();

  function render() {
    container.innerHTML = '';

    // Header
    const header = document.createElement('div');
    header.className = 'flex items-center gap-3 mb-4';

    const backBtn = btn('← Back', 'ghost');
    backBtn.onclick = onBack;

    const titleEl = document.createElement('div');
    titleEl.className = 'flex-1 min-w-0';

    const ipEl = document.createElement('h2');
    ipEl.className = 'text-lg font-bold font-mono text-slate-800';
    ipEl.textContent = host.ip;

    const metaEl = document.createElement('p');
    metaEl.className = 'text-xs text-slate-400';
    metaEl.textContent = [host.hostname, host.os].filter(Boolean).join(' · ');

    titleEl.appendChild(ipEl);
    titleEl.appendChild(metaEl);

    const statusBadge = document.createElement('span');
    statusBadge.className = `badge badge-${host.status} shrink-0 cursor-pointer`;
    statusBadge.textContent = host.status;
    statusBadge.title = 'Click to toggle status';
    statusBadge.onclick = async () => {
      const next = { observed: 'compromised', compromised: 'unknown', unknown: 'observed' };
      host.status = next[host.status] || 'observed';
      data.hosts = data.hosts.map(h => h.id === hostId ? host : h);
      try { await saveEngagementData(engagementId, data); render(); }
      catch { toastError('Could not update status.'); }
    };

    const addSnapBtn = btn('+ Snapshot', 'primary');
    addSnapBtn.className += ' text-xs shrink-0';
    addSnapBtn.onclick = () => showSnapshotForm();

    header.appendChild(backBtn);
    header.appendChild(titleEl);
    header.appendChild(statusBadge);
    header.appendChild(addSnapBtn);
    container.appendChild(header);

    // Host notes
    const noteRow = document.createElement('div');
    noteRow.className = 'flex items-center justify-between mb-2';
    const notesLabel = document.createElement('span');
    notesLabel.className = 'section-label mb-0';
    notesLabel.textContent = 'Notes';
    const addNoteBtn = btn('+ Note', 'ghost');
    addNoteBtn.className += ' text-xs text-indigo-600';
    addNoteBtn.onclick = () => showNoteForm();
    noteRow.appendChild(notesLabel);
    noteRow.appendChild(addNoteBtn);
    container.appendChild(noteRow);

    const hostNotes = (data.notes || []).filter(n => n.hostId === hostId).sort((a, b) => b.timestamp - a.timestamp);
    if (hostNotes.length > 0) {
      hostNotes.forEach(note => {
        const card = document.createElement('div');
        card.className = 'bg-slate-50 rounded-lg px-3 py-2 mb-2 text-sm text-slate-700';

        const ts = document.createElement('span');
        ts.className = 'text-xs text-slate-400 mr-2';
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

        card.appendChild(delBtn);
        card.appendChild(ts);
        card.appendChild(document.createTextNode(note.text));
        container.appendChild(card);
      });
    }

    // Snapshots
    const hostSnaps = snapshots
      .filter(s => s.hostId === hostId)
      .sort((a, b) => b.timestamp - a.timestamp);

    if (hostSnaps.length > 0) {
      const snapsLabel = document.createElement('span');
      snapsLabel.className = 'section-label mt-4';
      snapsLabel.textContent = 'Snapshots';
      container.appendChild(snapsLabel);

      hostSnaps.forEach((snap, i) => {
        const prevSnap = hostSnaps.find((s, j) => j > i && s.commandType === snap.commandType);
        const diff = prevSnap ? diffSnapshots(prevSnap, snap) : null;
        const hasChanges = diff && (diff.added?.length || diff.removed?.length);

        const card = document.createElement('div');
        card.className = 'card mb-2';

        // Snap header
        const snapHeader = document.createElement('div');
        snapHeader.className = 'flex items-center gap-2 mb-2';

        const cmdBadge = document.createElement('span');
        cmdBadge.className = 'badge bg-indigo-100 text-indigo-700';
        cmdBadge.textContent = snap.commandType;

        const tsBadge = document.createElement('span');
        tsBadge.className = 'text-xs text-slate-400 flex-1';
        tsBadge.textContent = new Date(snap.timestamp).toLocaleString();

        const osBadge = document.createElement('span');
        osBadge.className = 'text-xs text-slate-400';
        osBadge.textContent = snap.osFamily;

        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.textContent = '×';
        delBtn.className = 'text-slate-300 hover:text-red-400 text-lg leading-none';
        delBtn.onclick = async () => {
          const updated = snapshots.filter(s => s.id !== snap.id);
          try { await saveSnapshots(engagementId, updated); snapshots = updated; render(); }
          catch { toastError('Could not delete snapshot.'); }
        };

        snapHeader.appendChild(cmdBadge);
        snapHeader.appendChild(tsBadge);
        snapHeader.appendChild(osBadge);
        snapHeader.appendChild(delBtn);
        card.appendChild(snapHeader);

        // Diff summary
        if (hasChanges) {
          const diffEl = document.createElement('div');
          diffEl.className = 'mb-2 space-y-1';

          if (diff.added?.length) {
            const el = document.createElement('div');
            el.className = 'diff-added rounded px-2 py-1 text-xs font-mono';
            el.textContent = `+ ${diff.added.length} new: ${formatDiffItems(snap.commandType, diff.added)}`;
            diffEl.appendChild(el);
          }
          if (diff.removed?.length) {
            const el = document.createElement('div');
            el.className = 'diff-removed rounded px-2 py-1 text-xs font-mono';
            el.textContent = `− ${diff.removed.length} gone: ${formatDiffItems(snap.commandType, diff.removed)}`;
            diffEl.appendChild(el);
          }
          card.appendChild(diffEl);
        }

        // Parsed summary
        renderParsedSummary(card, snap);

        // Raw toggle
        const rawToggle = document.createElement('button');
        rawToggle.type = 'button';
        rawToggle.className = 'text-xs text-slate-400 hover:text-slate-600 mt-2';
        rawToggle.textContent = 'Show raw output';
        let rawVisible = false;
        const rawEl = document.createElement('pre');
        rawEl.className = 'field-mono bg-slate-50 rounded-lg p-3 mt-2 overflow-x-auto text-xs whitespace-pre hidden max-h-48 overflow-y-auto';
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
  }

  // ── Snapshot form ───────────────────────────────────────

  function showSnapshotForm() {
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';

    const box = document.createElement('div');
    box.className = 'modal-box max-w-lg';

    const title = document.createElement('h3');
    title.className = 'text-lg font-bold text-slate-800 mb-3';
    title.textContent = 'Paste Output';
    box.appendChild(title);

    const hint = document.createElement('p');
    hint.className = 'text-xs text-slate-400 mb-3';
    hint.textContent = 'Paste the output of: netstat, ps / tasklist, ipconfig / ifconfig, uname, or arp. OS and command type will be detected automatically.';
    box.appendChild(hint);

    const textarea = document.createElement('textarea');
    textarea.className = 'field-mono mb-1 resize-none';
    textarea.rows = 12;
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

      // Auto-update host OS if detected and not yet set
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

  // ── Note form ───────────────────────────────────────────

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
    textarea.rows = 4;
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

// ── Rendering helpers ─────────────────────────────────────

function renderParsedSummary(card, snap) {
  if (!snap.parsed) return;

  if (snap.commandType === 'netstat') {
    const conns = snap.parsed.connections || [];
    const listening = conns.filter(c => c.state === 'LISTENING' || c.state === 'LISTEN');
    const established = conns.filter(c => c.state === 'ESTABLISHED');

    const el = document.createElement('div');
    el.className = 'text-xs text-slate-500 space-y-0.5';
    if (listening.length) {
      const row = document.createElement('p');
      row.textContent = `Listening (${listening.length}): ${listening.slice(0, 5).map(c => c.localAddr.split(':').pop()).join(', ')}${listening.length > 5 ? '…' : ''}`;
      el.appendChild(row);
    }
    if (established.length) {
      const row = document.createElement('p');
      row.textContent = `Established (${established.length}): ${established.slice(0, 3).map(c => c.remoteAddr).join(', ')}${established.length > 3 ? '…' : ''}`;
      el.appendChild(row);
    }
    card.appendChild(el);
  }

  if (snap.commandType === 'pslist') {
    const procs = snap.parsed.processes || [];
    const el = document.createElement('p');
    el.className = 'text-xs text-slate-500';
    el.textContent = `${procs.length} processes`;
    card.appendChild(el);
  }

  if (snap.commandType === 'ipconfig') {
    const ifaces = snap.parsed.interfaces || [];
    const el = document.createElement('div');
    el.className = 'text-xs text-slate-500 space-y-0.5';
    ifaces.forEach(iface => {
      iface.addresses.forEach(addr => {
        const row = document.createElement('p');
        row.textContent = `${iface.name}: ${addr.ip}${addr.mask ? ' / ' + addr.mask : ''}`;
        el.appendChild(row);
      });
    });
    card.appendChild(el);
  }

  if (snap.commandType === 'uname') {
    const el = document.createElement('p');
    el.className = 'text-xs text-slate-500 font-mono';
    el.textContent = snap.parsed.raw || '';
    card.appendChild(el);
  }

  if (snap.commandType === 'arp') {
    const entries = snap.parsed.entries || [];
    const el = document.createElement('p');
    el.className = 'text-xs text-slate-500';
    el.textContent = `${entries.length} ARP ${entries.length === 1 ? 'entry' : 'entries'}`;
    card.appendChild(el);
  }
}

function formatDiffItems(type, items) {
  if (type === 'netstat')  return items.slice(0, 3).map(c => `${c.proto} ${c.localAddr}→${c.remoteAddr}`).join(', ');
  if (type === 'pslist')   return items.slice(0, 5).map(p => p.name).join(', ');
  if (type === 'arp')      return items.slice(0, 3).map(e => `${e.ip} (${e.mac})`).join(', ');
  if (type === 'ipconfig') return items.slice(0, 3).join(', ');
  return '';
}
