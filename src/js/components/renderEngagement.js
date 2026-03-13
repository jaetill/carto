import { engagements, loadEngagementData, saveEngagementData, loadSnapshots, saveSnapshots, newHost, newNote } from '../data/index.js';
import { btn } from '../ui/elements.js';
import { toastSuccess, toastError } from '../ui/toast.js';
import { renderEngagements } from './renderEngagements.js';

export async function renderEngagement(engagementId) {
  const container = document.getElementById('app-content');
  container.innerHTML = '<p class="text-slate-400 text-sm text-center py-12">Loading…</p>';

  const eng  = engagements.find(e => e.id === engagementId);
  if (!eng) { renderEngagements(); return; }

  let data      = await loadEngagementData(engagementId);
  let snapshots = await loadSnapshots(engagementId);

  render();

  function render() {
    container.innerHTML = '';

    // Header
    const header = document.createElement('div');
    header.className = 'flex items-center gap-3 mb-4';

    const backBtn = btn('← Back', 'ghost');
    backBtn.onclick = renderEngagements;

    const titleEl = document.createElement('div');
    titleEl.className = 'flex-1 min-w-0';

    const nameEl = document.createElement('h2');
    nameEl.className = 'text-lg font-bold text-slate-800 truncate';
    nameEl.textContent = eng.name;

    const metaEl = document.createElement('p');
    metaEl.className = 'text-xs text-slate-400';
    metaEl.textContent = [eng.client, eng.startDate].filter(Boolean).join(' · ');

    titleEl.appendChild(nameEl);
    titleEl.appendChild(metaEl);

    const badge = document.createElement('span');
    badge.className = `badge badge-${eng.status} shrink-0`;
    badge.textContent = eng.status;

    header.appendChild(backBtn);
    header.appendChild(titleEl);
    header.appendChild(badge);
    container.appendChild(header);

    // Hosts section
    const hostsLabel = document.createElement('div');
    hostsLabel.className = 'flex items-center justify-between mb-2';

    const hostsTitle = document.createElement('span');
    hostsTitle.className = 'section-label mb-0';
    hostsTitle.textContent = 'Hosts';

    const addHostBtn = btn('+ Add Host', 'ghost');
    addHostBtn.className += ' text-xs text-indigo-600';
    addHostBtn.onclick = () => showHostForm(null);

    hostsLabel.appendChild(hostsTitle);
    hostsLabel.appendChild(addHostBtn);
    container.appendChild(hostsLabel);

    if (data.hosts.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'text-slate-300 text-sm italic mb-4';
      empty.textContent = 'No hosts yet.';
      container.appendChild(empty);
    } else {
      data.hosts.forEach(host => {
        const card = document.createElement('div');
        card.className = 'card cursor-pointer hover:border-indigo-200 transition-colors mb-2';

        const row = document.createElement('div');
        row.className = 'flex items-center gap-3';

        const ipEl = document.createElement('span');
        ipEl.className = 'font-mono text-sm font-semibold text-slate-800 shrink-0';
        ipEl.textContent = host.ip || '—';

        const info = document.createElement('div');
        info.className = 'flex-1 min-w-0';

        const hostname = document.createElement('p');
        hostname.className = 'text-sm text-slate-700 truncate';
        hostname.textContent = host.hostname || '';

        const osMeta = document.createElement('p');
        osMeta.className = 'text-xs text-slate-400';
        osMeta.textContent = host.os || host.osFamily || '';

        info.appendChild(hostname);
        info.appendChild(osMeta);

        const statusBadge = document.createElement('span');
        statusBadge.className = `badge badge-${host.status} shrink-0`;
        statusBadge.textContent = host.status;

        const hostSnapCount = snapshots.filter(s => s.hostId === host.id).length;
        if (hostSnapCount > 0) {
          const snapEl = document.createElement('span');
          snapEl.className = 'text-xs text-slate-400 shrink-0';
          snapEl.textContent = `${hostSnapCount} snap${hostSnapCount !== 1 ? 's' : ''}`;
          row.appendChild(ipEl);
          row.appendChild(info);
          row.appendChild(snapEl);
          row.appendChild(statusBadge);
        } else {
          row.appendChild(ipEl);
          row.appendChild(info);
          row.appendChild(statusBadge);
        }

        card.appendChild(row);
        card.onclick = () => import('./renderHost.js').then(m => m.renderHost(engagementId, host.id, data, snapshots, render));

        container.appendChild(card);
      });
    }

    // Notes section
    const notesLabel = document.createElement('div');
    notesLabel.className = 'flex items-center justify-between mb-2 mt-4';

    const notesTitle = document.createElement('span');
    notesTitle.className = 'section-label mb-0';
    notesTitle.textContent = 'Notes';

    const addNoteBtn = btn('+ Add Note', 'ghost');
    addNoteBtn.className += ' text-xs text-indigo-600';
    addNoteBtn.onclick = () => showNoteForm();

    notesLabel.appendChild(notesTitle);
    notesLabel.appendChild(addNoteBtn);
    container.appendChild(notesLabel);

    const engNotes = (data.notes || []).filter(n => !n.hostId).sort((a, b) => b.timestamp - a.timestamp);

    if (engNotes.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'text-slate-300 text-sm italic';
      empty.textContent = 'No notes yet.';
      container.appendChild(empty);
    } else {
      engNotes.forEach(note => {
        const card = document.createElement('div');
        card.className = 'card mb-2';

        const ts = document.createElement('p');
        ts.className = 'text-xs text-slate-400 mb-1';
        ts.textContent = new Date(note.timestamp).toLocaleString();

        const text = document.createElement('p');
        text.className = 'text-sm text-slate-700 whitespace-pre-wrap';
        text.textContent = note.text;

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
        card.appendChild(text);
        container.appendChild(card);
      });
    }
  }

  // ── Host form ───────────────────────────────────────────

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

    // Status
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
