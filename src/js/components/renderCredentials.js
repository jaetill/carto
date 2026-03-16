import { saveEngagementData, newCredential } from '../data/index.js';
import { btn } from '../ui/elements.js';
import { toastSuccess, toastError } from '../ui/toast.js';

const TYPE_COLORS = {
  plaintext: 'bg-green-100 text-green-700',
  ntlm:      'bg-red-100 text-red-700',
  hash:      'bg-orange-100 text-orange-700',
  kerberos:  'bg-purple-100 text-purple-700',
};

export function renderCredentialsTab(container, engagementId, data, hosts, onHostClick) {
  const creds = data.credentials || [];
  const hostMap = Object.fromEntries(hosts.map(h => [h.id, h]));

  // ── Add credential button ─────────────────────────────
  const topRow = document.createElement('div');
  topRow.className = 'flex justify-between items-center mb-4';

  const countEl = document.createElement('p');
  countEl.className = 'text-sm text-slate-400';
  countEl.textContent = creds.length === 0 ? 'No credentials recorded.' : `${creds.length} credential${creds.length !== 1 ? 's' : ''}`;

  const addBtn = btn('+ Add credential', 'secondary');
  addBtn.className += ' text-xs';
  addBtn.onclick = () => showCredForm(null);

  topRow.appendChild(countEl);
  topRow.appendChild(addBtn);
  container.appendChild(topRow);

  if (creds.length === 0) return;

  // ── Table ─────────────────────────────────────────────
  const tableWrap = document.createElement('div');
  tableWrap.className = 'bg-white rounded-xl border border-slate-100 overflow-hidden';

  const table = document.createElement('table');
  table.className = 'w-full text-sm';

  const thead = document.createElement('thead');
  thead.innerHTML = `
    <tr class="text-xs text-slate-400 border-b border-slate-100">
      <th class="text-left px-4 py-2 font-medium">User</th>
      <th class="text-left px-4 py-2 font-medium">Type</th>
      <th class="text-left px-4 py-2 font-medium">Secret</th>
      <th class="text-left px-4 py-2 font-medium">Source</th>
      <th class="text-left px-4 py-2 font-medium">Notes</th>
      <th class="px-4 py-2"></th>
    </tr>`;
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  for (const cred of creds) {
    tbody.appendChild(makeCredRow(cred, hostMap, onHostClick));
  }
  table.appendChild(tbody);
  tableWrap.appendChild(table);
  container.appendChild(tableWrap);

  // ── Credential form (add / edit) ──────────────────────
  let formEl = null;

  function showCredForm(existing) {
    if (formEl) formEl.remove();

    const overlay = document.createElement('div');
    overlay.className = 'fixed inset-0 bg-black/40 z-50 flex items-center justify-center';

    const modal = document.createElement('div');
    modal.className = 'bg-white rounded-2xl shadow-xl p-6 w-full max-w-md space-y-4';

    const title = document.createElement('h3');
    title.className = 'text-base font-semibold text-slate-800';
    title.textContent = existing ? 'Edit credential' : 'Add credential';
    modal.appendChild(title);

    function field(labelText, inputEl) {
      const wrap = document.createElement('div');
      const lbl = document.createElement('label');
      lbl.className = 'block text-xs text-slate-500 mb-1';
      lbl.textContent = labelText;
      wrap.appendChild(lbl);
      wrap.appendChild(inputEl);
      return wrap;
    }

    function textInput(val = '', placeholder = '') {
      const el = document.createElement('input');
      el.type = 'text';
      el.className = 'field w-full text-sm';
      el.value = val;
      el.placeholder = placeholder;
      return el;
    }

    const usernameEl = textInput(existing?.username || '', 'e.g. jsmith');
    const domainEl   = textInput(existing?.domain   || '', 'e.g. CORP (optional)');

    const typeEl = document.createElement('select');
    typeEl.className = 'field w-full text-sm';
    ['plaintext', 'ntlm', 'hash', 'kerberos'].forEach(t => {
      const opt = document.createElement('option');
      opt.value = t;
      opt.textContent = t;
      opt.selected = (existing?.secretType || 'plaintext') === t;
      typeEl.appendChild(opt);
    });

    const secretEl  = textInput(existing?.secret || '', 'password, hash, or ticket');
    const crackedEl = textInput(existing?.crackedValue || '', 'cracked plaintext (if known)');

    const sourceHostEl = document.createElement('select');
    sourceHostEl.className = 'field w-full text-sm';
    const noneOpt = document.createElement('option');
    noneOpt.value = '';
    noneOpt.textContent = '— none —';
    sourceHostEl.appendChild(noneOpt);
    for (const h of hosts) {
      const opt = document.createElement('option');
      opt.value = h.id;
      opt.textContent = h.label || h.ip;
      opt.selected = existing?.sourceHostId === h.id;
      sourceHostEl.appendChild(opt);
    }

    const notesEl = textInput(existing?.notes || '', 'optional notes');

    modal.appendChild(field('Username *', usernameEl));
    modal.appendChild(field('Domain', domainEl));
    modal.appendChild(field('Type', typeEl));
    modal.appendChild(field('Secret', secretEl));
    modal.appendChild(field('Cracked value', crackedEl));
    modal.appendChild(field('Source host', sourceHostEl));
    modal.appendChild(field('Notes', notesEl));

    const btnRow = document.createElement('div');
    btnRow.className = 'flex justify-end gap-2 pt-2';

    const cancelBtn = btn('Cancel', 'ghost');
    cancelBtn.onclick = () => overlay.remove();

    const saveBtn = btn(existing ? 'Save' : 'Add', 'primary');
    saveBtn.onclick = async () => {
      const username = usernameEl.value.trim();
      if (!username) { usernameEl.focus(); return; }

      const updated = newCredential({
        ...(existing || {}),
        username,
        domain:       domainEl.value.trim() || null,
        secretType:   typeEl.value,
        secret:       secretEl.value.trim(),
        cracked:      !!crackedEl.value.trim(),
        crackedValue: crackedEl.value.trim() || null,
        sourceHostId: sourceHostEl.value || null,
        notes:        notesEl.value.trim(),
      });

      if (existing) {
        const idx = data.credentials.findIndex(c => c.id === existing.id);
        if (idx !== -1) data.credentials[idx] = updated;
      } else {
        data.credentials.push(updated);
      }

      try {
        await saveEngagementData(engagementId, data);
        toastSuccess(existing ? 'Credential updated.' : 'Credential added.');
        overlay.remove();
        // Re-render the tab
        container.innerHTML = '';
        renderCredentialsTab(container, engagementId, data, hosts, onHostClick);
      } catch (e) {
        toastError('Could not save: ' + e.message);
      }
    };

    btnRow.appendChild(cancelBtn);
    btnRow.appendChild(saveBtn);
    modal.appendChild(btnRow);

    overlay.appendChild(modal);
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
    document.body.appendChild(overlay);
    formEl = overlay;
    usernameEl.focus();
  }

  function makeCredRow(cred, hostMap, onHostClick) {
    const tr = document.createElement('tr');
    tr.className = 'border-b border-slate-50 hover:bg-slate-50';

    // Username + domain
    const userTd = document.createElement('td');
    userTd.className = 'px-4 py-2 font-mono text-slate-800';
    userTd.textContent = cred.domain ? `${cred.domain}\\${cred.username}` : cred.username;

    // Type badge
    const typeTd = document.createElement('td');
    typeTd.className = 'px-4 py-2';
    const badge = document.createElement('span');
    badge.className = `text-xs px-2 py-0.5 rounded font-medium ${TYPE_COLORS[cred.secretType] || 'bg-slate-100 text-slate-600'}`;
    badge.textContent = cred.secretType;
    typeTd.appendChild(badge);

    // Secret (masked, click to reveal)
    const secretTd = document.createElement('td');
    secretTd.className = 'px-4 py-2 font-mono text-xs max-w-[200px]';
    const secretSpan = document.createElement('span');
    let revealed = false;
    const displayVal = cred.crackedValue
      ? `${cred.crackedValue} (cracked)`
      : (cred.secret || '—');
    secretSpan.textContent = cred.secret ? '••••••••' : '—';
    secretSpan.className = 'cursor-pointer select-none text-slate-500 hover:text-slate-800';
    secretSpan.title = 'Click to reveal';
    secretSpan.onclick = () => {
      revealed = !revealed;
      secretSpan.textContent = revealed ? displayVal : '••••••••';
    };
    secretTd.appendChild(secretSpan);

    // Source host
    const sourceTd = document.createElement('td');
    sourceTd.className = 'px-4 py-2 text-xs';
    if (cred.sourceHostId && hostMap[cred.sourceHostId]) {
      const hostBtn = document.createElement('button');
      hostBtn.type = 'button';
      hostBtn.className = 'text-indigo-600 hover:underline font-mono';
      hostBtn.textContent = hostMap[cred.sourceHostId].label || hostMap[cred.sourceHostId].ip;
      hostBtn.onclick = () => onHostClick(cred.sourceHostId);
      sourceTd.appendChild(hostBtn);
    } else {
      sourceTd.textContent = '—';
      sourceTd.className += ' text-slate-400';
    }

    // Notes
    const notesTd = document.createElement('td');
    notesTd.className = 'px-4 py-2 text-xs text-slate-500 max-w-[160px] truncate';
    notesTd.textContent = cred.notes || '';

    // Actions
    const actionTd = document.createElement('td');
    actionTd.className = 'px-4 py-2 text-right';
    const editBtn = document.createElement('button');
    editBtn.type = 'button';
    editBtn.className = 'text-xs text-slate-400 hover:text-indigo-600 mr-2';
    editBtn.textContent = 'Edit';
    editBtn.onclick = () => showCredForm(cred);

    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.className = 'text-xs text-slate-400 hover:text-red-600';
    delBtn.textContent = 'Delete';
    delBtn.onclick = async () => {
      if (!confirm(`Delete credential for "${cred.username}"?`)) return;
      data.credentials = data.credentials.filter(c => c.id !== cred.id);
      try {
        await saveEngagementData(engagementId, data);
        toastSuccess('Credential deleted.');
        container.innerHTML = '';
        renderCredentialsTab(container, engagementId, data, hosts, onHostClick);
      } catch (e) {
        toastError('Could not delete: ' + e.message);
      }
    };

    actionTd.appendChild(editBtn);
    actionTd.appendChild(delBtn);

    tr.appendChild(userTd);
    tr.appendChild(typeTd);
    tr.appendChild(secretTd);
    tr.appendChild(sourceTd);
    tr.appendChild(notesTd);
    tr.appendChild(actionTd);
    return tr;
  }
}
