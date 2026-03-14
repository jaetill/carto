import { engagements, loadEngagementData, saveEngagementData, loadSnapshots, saveSnapshots, newHost, newNote, saveEngagements } from '../data/index.js';
import { btn } from '../ui/elements.js';
import { toastSuccess, toastError } from '../ui/toast.js';
import { renderSidebar } from './renderEngagements.js';

export async function renderEngagement(engagementId) {
  const container = document.getElementById('app-content');
  container.innerHTML = '<p class="text-slate-400 text-sm text-center py-12">Loading…</p>';

  const eng = engagements.find(e => e.id === engagementId);
  if (!eng) { container.innerHTML = '<p class="text-slate-400 text-sm text-center py-12">Engagement not found.</p>'; return; }

  let data      = await loadEngagementData(engagementId);
  let snapshots = await loadSnapshots(engagementId);

  render();

  function render() {
    container.innerHTML = '';

    // ── Header ────────────────────────────────────────────
    const header = document.createElement('div');
    header.className = 'flex items-start justify-between mb-6';

    const titleBlock = document.createElement('div');

    const nameEl = document.createElement('h2');
    nameEl.className = 'text-2xl font-bold text-slate-800';
    nameEl.textContent = eng.name;

    const metaEl = document.createElement('p');
    metaEl.className = 'text-sm text-slate-400 mt-0.5';
    metaEl.textContent = [eng.client, eng.startDate].filter(Boolean).join(' · ');

    titleBlock.appendChild(nameEl);
    titleBlock.appendChild(metaEl);

    const headerActions = document.createElement('div');
    headerActions.className = 'flex items-center gap-2';

    const badge = document.createElement('span');
    badge.className = `badge badge-${eng.status}`;
    badge.textContent = eng.status;

    const editBtn = btn('Edit', 'secondary');
    editBtn.className += ' text-xs';
    editBtn.onclick = () => showEngagementForm();

    headerActions.appendChild(badge);
    headerActions.appendChild(editBtn);
    header.appendChild(titleBlock);
    header.appendChild(headerActions);
    container.appendChild(header);

    // ── Stats row ─────────────────────────────────────────
    const stats = document.createElement('div');
    stats.className = 'grid grid-cols-4 gap-4 mb-6';

    const compromised = data.hosts.filter(h => h.status === 'compromised').length;
    const snapCount   = snapshots.length;
    const noteCount   = (data.notes || []).filter(n => !n.hostId).length;

    [
      { label: 'Hosts',       value: data.hosts.length },
      { label: 'Compromised', value: compromised, accent: compromised > 0 ? 'text-red-600' : '' },
      { label: 'Snapshots',   value: snapCount },
      { label: 'Notes',       value: noteCount },
    ].forEach(({ label, value, accent = '' }) => {
      const card = document.createElement('div');
      card.className = 'bg-white rounded-xl border border-slate-100 p-4';
      const val = document.createElement('p');
      val.className = `text-2xl font-bold text-slate-800 ${accent}`;
      val.textContent = value;
      const lbl = document.createElement('p');
      lbl.className = 'text-xs text-slate-400 mt-0.5';
      lbl.textContent = label;
      card.appendChild(val);
      card.appendChild(lbl);
      stats.appendChild(card);
    });
    container.appendChild(stats);

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
    const addHostBtn = btn('+ Add Host', 'secondary');
    addHostBtn.className += ' text-xs';
    addHostBtn.onclick = () => showHostForm(null);
    hostsHeader.appendChild(hostsTitle);
    hostsHeader.appendChild(addHostBtn);
    hostCol.appendChild(hostsHeader);

    if (data.hosts.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'text-slate-400 text-sm italic';
      empty.textContent = 'No hosts yet.';
      hostCol.appendChild(empty);
    } else {
      const table = document.createElement('table');
      table.className = 'w-full text-sm bg-white rounded-xl border border-slate-100 overflow-hidden';

      const thead = document.createElement('thead');
      thead.innerHTML = `<tr class="border-b border-slate-100">
        <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">IP</th>
        <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">Hostname</th>
        <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">OS</th>
        <th class="text-left px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">Status</th>
        <th class="text-right px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wide">Snaps</th>
      </tr>`;
      table.appendChild(thead);

      const tbody = document.createElement('tbody');
      data.hosts.forEach(host => {
        const snapCount = snapshots.filter(s => s.hostId === host.id).length;
        const tr = document.createElement('tr');
        tr.className = 'border-b border-slate-50 hover:bg-slate-50 cursor-pointer transition-colors';
        tr.innerHTML = `
          <td class="px-4 py-2.5 font-mono text-xs font-semibold text-slate-700">${host.ip || '—'}</td>
          <td class="px-4 py-2.5 text-slate-600 truncate max-w-xs">${host.hostname || '—'}</td>
          <td class="px-4 py-2.5 text-slate-500 text-xs">${host.os || host.osFamily || '—'}</td>
          <td class="px-4 py-2.5"><span class="badge badge-${host.status}">${host.status}</span></td>
          <td class="px-4 py-2.5 text-right text-xs text-slate-400">${snapCount || '—'}</td>
        `;
        tr.onclick = () => import('./renderHost.js').then(m => m.renderHost(engagementId, host.id, data, snapshots, render));
        tbody.appendChild(tr);
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
