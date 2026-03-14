import { engagements, saveEngagements, newEngagement, loadMockScenario, isMockMode } from '../data/index.js';
import { btn } from '../ui/elements.js';
import { toastSuccess, toastError } from '../ui/toast.js';
import { DEBUG_MODE } from '../config.js';
import { navigateTo, currentEngagementId } from '../nav.js';

export function renderSidebar() {
  const container = document.getElementById('sidebar-content');
  container.innerHTML = '';

  if (DEBUG_MODE && !isMockMode()) {
    const mockBtn = document.createElement('button');
    mockBtn.className = 'w-full text-left px-4 py-2 text-xs text-amber-400 hover:text-amber-300 hover:bg-slate-800 border-b border-slate-800';
    mockBtn.textContent = 'Load Mock Scenario';
    mockBtn.onclick = async () => { await loadMockScenario(); renderSidebar(); };
    container.appendChild(mockBtn);
  }

  if (engagements.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'text-slate-500 text-xs px-4 py-3';
    empty.textContent = 'No engagements yet.';
    container.appendChild(empty);
    return;
  }

  const active = engagements.filter(e => e.status === 'active');
  const closed = engagements.filter(e => e.status === 'closed');

  function renderGroup(list, heading) {
    if (list.length === 0) return;

    const label = document.createElement('p');
    label.className = 'px-4 pt-3 pb-1 text-xs font-semibold uppercase tracking-wider text-slate-500';
    label.textContent = heading;
    container.appendChild(label);

    list.forEach(eng => {
      const isSelected = eng.id === currentEngagementId;
      const item = document.createElement('button');
      item.className = `w-full text-left px-4 py-2.5 flex items-start gap-2 transition-colors ${
        isSelected ? 'bg-indigo-600' : 'hover:bg-slate-800'
      }`;

      const dot = document.createElement('span');
      dot.className = `mt-1.5 w-1.5 h-1.5 rounded-full flex-shrink-0 ${
        eng.status === 'active' ? 'bg-emerald-400' : 'bg-slate-600'
      }`;

      const info = document.createElement('div');
      info.className = 'min-w-0';

      const name = document.createElement('p');
      name.className = `text-sm font-medium truncate ${isSelected ? 'text-white' : 'text-slate-200'}`;
      name.textContent = eng.name;

      const meta = document.createElement('p');
      meta.className = `text-xs truncate ${isSelected ? 'text-indigo-200' : 'text-slate-500'}`;
      meta.textContent = eng.client || eng.startDate || '';

      info.appendChild(name);
      info.appendChild(meta);
      item.appendChild(dot);
      item.appendChild(info);
      item.onclick = () => navigateTo(eng.id);
      container.appendChild(item);
    });
  }

  renderGroup(active, 'Active');
  renderGroup(closed, 'Closed');
}

export function showNewEngagementForm() {
  const eng = newEngagement();

  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';

  const box = document.createElement('div');
  box.className = 'modal-box';

  const title = document.createElement('h3');
  title.className = 'text-lg font-bold text-slate-800 mb-4';
  title.textContent = 'New Engagement';
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

  const actions = document.createElement('div');
  actions.className = 'flex gap-3 mt-4';

  const saveBtn = btn('Create', 'primary');
  saveBtn.className += ' flex-1';
  saveBtn.onclick = async () => {
    eng.name = eng.name?.trim();
    if (!eng.name) { nameInput.focus(); return; }
    saveBtn.disabled = true;
    try {
      await saveEngagements([...engagements, eng]);
      toastSuccess('Engagement created.');
      backdrop.remove();
      renderSidebar();
      navigateTo(eng.id);
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
