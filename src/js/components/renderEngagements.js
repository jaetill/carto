import { engagements, saveEngagements, newEngagement } from '../data/index.js';
import { btn } from '../ui/elements.js';
import { toastSuccess, toastError } from '../ui/toast.js';

export function renderEngagements() {
  const container = document.getElementById('app-content');
  container.innerHTML = '';

  // Header
  const header = document.createElement('div');
  header.className = 'flex items-center justify-between mb-4';

  const title = document.createElement('h2');
  title.className = 'text-lg font-bold text-slate-800';
  title.textContent = 'Engagements';

  const addBtn = btn('+ New', 'primary');
  addBtn.onclick = () => showEngagementForm(null, renderEngagements);

  header.appendChild(title);
  header.appendChild(addBtn);
  container.appendChild(header);

  if (engagements.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'text-slate-400 text-sm text-center py-12';
    empty.textContent = 'No engagements yet.';
    container.appendChild(empty);
    return;
  }

  const active = engagements.filter(e => e.status === 'active');
  const closed = engagements.filter(e => e.status === 'closed');

  function renderGroup(list, heading) {
    if (list.length === 0) return;
    const label = document.createElement('span');
    label.className = 'section-label';
    label.textContent = heading;
    container.appendChild(label);

    list.forEach(eng => {
      const card = document.createElement('div');
      card.className = 'card flex items-center gap-3 cursor-pointer hover:border-indigo-200 transition-colors';

      const info = document.createElement('div');
      info.className = 'flex-1 min-w-0';

      const nameEl = document.createElement('p');
      nameEl.className = 'font-medium text-slate-900 truncate';
      nameEl.textContent = eng.name;

      const meta = document.createElement('p');
      meta.className = 'text-xs text-slate-400 mt-0.5';
      meta.textContent = [eng.client, eng.startDate].filter(Boolean).join(' · ');

      info.appendChild(nameEl);
      info.appendChild(meta);

      const badge = document.createElement('span');
      badge.className = `badge badge-${eng.status}`;
      badge.textContent = eng.status;

      const editBtn = btn('Edit', 'ghost');
      editBtn.className += ' text-xs shrink-0';
      editBtn.onclick = e => { e.stopPropagation(); showEngagementForm(eng, renderEngagements); };

      card.appendChild(info);
      card.appendChild(badge);
      card.appendChild(editBtn);

      // Lazy import to avoid circular dep
      card.onclick = () => import('./renderEngagement.js').then(m => m.renderEngagement(eng.id));

      container.appendChild(card);
    });
  }

  renderGroup(active, 'Active');
  renderGroup(closed, 'Closed');
}

// ── Engagement form modal ─────────────────────────────────

function showEngagementForm(existing, onDone) {
  const isNew = !existing;
  const eng   = existing ? { ...existing } : newEngagement();

  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';

  const box = document.createElement('div');
  box.className = 'modal-box';

  const title = document.createElement('h3');
  title.className = 'text-lg font-bold text-slate-800 mb-4';
  title.textContent = isNew ? 'New Engagement' : 'Edit Engagement';
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
    input.value = eng[key] || '';
    input.oninput = e => { eng[key] = e.target.value; };
    wrap.appendChild(label);
    wrap.appendChild(input);
    box.appendChild(wrap);
    return input;
  }

  const nameInput = field('Name', 'name', 'e.g. Acme Corp Q1 Assessment');
  field('Client', 'client', 'e.g. Acme Corp');
  field('Start date', 'startDate', 'YYYY-MM-DD');

  // Status toggle (only for existing)
  if (!isNew) {
    const wrap = document.createElement('div');
    wrap.className = 'mb-4';
    const label = document.createElement('label');
    label.className = 'block text-sm font-medium text-slate-700 mb-1';
    label.textContent = 'Status';
    const sel = document.createElement('select');
    sel.className = 'field';
    ['active', 'closed'].forEach(s => {
      const opt = document.createElement('option');
      opt.value = s;
      opt.textContent = s.charAt(0).toUpperCase() + s.slice(1);
      opt.selected = eng.status === s;
      sel.appendChild(opt);
    });
    sel.onchange = e => { eng.status = e.target.value; };
    wrap.appendChild(label);
    wrap.appendChild(sel);
    box.appendChild(wrap);
  }

  const actions = document.createElement('div');
  actions.className = 'flex gap-3 mt-4';

  const saveBtn = btn(isNew ? 'Create' : 'Save', 'primary');
  saveBtn.className += ' flex-1';
  saveBtn.onclick = async () => {
    eng.name = eng.name?.trim();
    if (!eng.name) { nameInput.focus(); return; }
    saveBtn.disabled = true;
    try {
      const updated = isNew
        ? [...engagements, eng]
        : engagements.map(e => e.id === eng.id ? eng : e);
      await saveEngagements(updated);
      toastSuccess(isNew ? 'Engagement created.' : 'Saved.');
      backdrop.remove();
      onDone();
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
  nameInput.focus();
}
