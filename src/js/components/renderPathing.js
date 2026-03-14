import cytoscape from 'cytoscape';
import { loadTopology, loadAttackPaths, saveAttackPath, deleteAttackPath } from '../data/graph.js';
import { isMockMode } from '../data/index.js';
import { btn } from '../ui/elements.js';
import { toastSuccess, toastError } from '../ui/toast.js';

// ── Status colors (shared with topology) ─────────────────

const STATUS_COLOR = {
  compromised: { bg: '#dc2626', border: '#991b1b' },
  observed:    { bg: '#059669', border: '#065f46' },
  unknown:     { bg: '#64748b', border: '#475569' },
};

function statusColor(status, prop) {
  return (STATUS_COLOR[status] || STATUS_COLOR.unknown)[prop];
}

// ── Cytoscape stylesheet ──────────────────────────────────

const stylesheet = [
  {
    selector: 'node',
    style: {
      'width':            44,
      'height':           44,
      'background-color': (ele) => statusColor(ele.data('status'), 'bg'),
      'border-color':     (ele) => statusColor(ele.data('status'), 'border'),
      'border-width':     2,
      'label':            'data(label)',
      'font-size':        '10px',
      'color':            '#1e293b',
      'text-valign':      'bottom',
      'text-halign':      'center',
      'text-margin-y':    4,
      'shape':            'ellipse',
    },
  },
  {
    selector: 'node:selected',
    style: {
      'border-width': 3,
      'border-color': '#6366f1',
    },
  },
  {
    selector: 'edge',
    style: {
      'line-color':             '#f59e0b',
      'target-arrow-color':     '#f59e0b',
      'target-arrow-shape':     'triangle',
      'curve-style':            'bezier',
      'width':                  2.5,
      'label':                  'data(technique)',
      'font-size':              '9px',
      'color':                  '#92400e',
      'text-rotation':          'autorotate',
      'text-margin-y':          -8,
      'text-background-color':  '#fffbeb',
      'text-background-opacity': 0.9,
      'text-background-padding': '2px',
    },
  },
  {
    selector: 'edge:selected',
    style: {
      'line-color':         '#ef4444',
      'target-arrow-color': '#ef4444',
    },
  },
];

// ── Add path edge modal ───────────────────────────────────

function showAddPathModal(engagementId, hosts, onSave) {
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';

  const box = document.createElement('div');
  box.className = 'modal-box';

  const title = document.createElement('h3');
  title.className = 'text-lg font-bold text-slate-800 mb-4';
  title.textContent = 'Add Attack Path Edge';
  box.appendChild(title);

  function selectField(labelText, id) {
    const wrap  = document.createElement('div');
    wrap.className = 'mb-3';
    const label = document.createElement('label');
    label.className = 'block text-sm font-medium text-slate-700 mb-1';
    label.textContent = labelText;
    const sel = document.createElement('select');
    sel.className = 'field';
    sel.id = id;
    const blank = document.createElement('option');
    blank.value = '';
    blank.textContent = '— Select host —';
    sel.appendChild(blank);
    for (const h of hosts) {
      const opt = document.createElement('option');
      opt.value = h.id;
      opt.textContent = `${h.hostname || h.ip || h.id} (${h.ip || ''})`;
      sel.appendChild(opt);
    }
    wrap.appendChild(label);
    wrap.appendChild(sel);
    box.appendChild(wrap);
    return sel;
  }

  function textField(labelText, placeholder) {
    const wrap  = document.createElement('div');
    wrap.className = 'mb-3';
    const label = document.createElement('label');
    label.className = 'block text-sm font-medium text-slate-700 mb-1';
    label.textContent = labelText;
    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'field';
    input.placeholder = placeholder;
    wrap.appendChild(label);
    wrap.appendChild(input);
    box.appendChild(wrap);
    return input;
  }

  const fromSel   = selectField('From (attacker moves from)', 'from-host');
  const toSel     = selectField('To (attacker moves to)',     'to-host');
  const techInput = textField('Technique', 'e.g. pass-the-hash, kerberoast, exploit');
  const notesInput = textField('Notes (optional)', 'e.g. used NTLM hash from DC01');

  const actions = document.createElement('div');
  actions.className = 'flex gap-3 mt-4';

  const saveBtn = btn('Add Path', 'primary');
  saveBtn.className += ' flex-1';
  saveBtn.onclick = async () => {
    const fromHostId = fromSel.value;
    const toHostId   = toSel.value;
    const technique  = techInput.value.trim();

    if (!fromHostId) { fromSel.focus(); return; }
    if (!toHostId)   { toSel.focus();   return; }
    if (fromHostId === toHostId) { toastError('From and To must be different hosts.'); return; }

    saveBtn.disabled = true;
    try {
      const edge = {
        edgeId:      crypto.randomUUID(),
        fromHostId,
        toHostId,
        technique,
        notes:     notesInput.value.trim(),
        timestamp: Date.now(),
      };
      await saveAttackPath(engagementId, edge);
      toastSuccess('Path edge added.');
      backdrop.remove();
      onSave();
    } catch (e) {
      toastError(e.message || 'Could not save path edge.');
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
  fromSel.focus();
}

// ── Main render function ──────────────────────────────────

export async function renderPathing(engagementId, container) {
  container.innerHTML = '<p class="text-slate-400 text-sm text-center py-12">Loading attack paths…</p>';

  if (isMockMode()) {
    container.innerHTML = '<p class="text-slate-400 text-sm text-center py-12 italic">Attack pathing not available in debug mode.</p>';
    return;
  }

  let topology, paths;
  try {
    [topology, paths] = await Promise.all([
      loadTopology(engagementId),
      loadAttackPaths(engagementId),
    ]);
  } catch (e) {
    container.innerHTML = `<p class="text-red-500 text-sm text-center py-12">Could not load paths: ${e.message}</p>`;
    return;
  }

  container.innerHTML = '';

  // Toolbar
  const toolbar = document.createElement('div');
  toolbar.className = 'flex items-center gap-3 mb-3';

  const title = document.createElement('span');
  title.className = 'text-sm font-semibold text-slate-700 flex-1';
  title.textContent = paths.length
    ? `${paths.length} attack path edge${paths.length !== 1 ? 's' : ''}`
    : 'No attack path edges yet';

  const addBtn = btn('+ Add Path Edge', 'secondary');
  addBtn.className += ' text-xs';
  addBtn.onclick = () => showAddPathModal(engagementId, topology.nodes, () => renderPathing(engagementId, container));

  toolbar.appendChild(title);
  toolbar.appendChild(addBtn);
  container.appendChild(toolbar);

  if (!topology.nodes.length) {
    const empty = document.createElement('p');
    empty.className = 'text-slate-400 text-sm italic';
    empty.textContent = 'No hosts in the graph yet. Import scan data first.';
    container.appendChild(empty);
    return;
  }

  // Build elements — show all hosts + attack path edges only
  const hostIds = new Set(paths.flatMap(p => [p.source, p.target]));
  // Also include all hosts so operator can see context
  for (const n of topology.nodes) hostIds.add(n.id);

  const hostMap = Object.fromEntries(topology.nodes.map(n => [n.id, n]));
  const elements = [];

  for (const id of hostIds) {
    const node = hostMap[id];
    if (!node) continue;
    elements.push({
      data: {
        id:       node.id,
        label:    node.hostname || node.ip || node.id,
        ip:       node.ip,
        hostname: node.hostname,
        status:   node.status || 'unknown',
      },
    });
  }

  for (const path of paths) {
    elements.push({
      data: {
        id:        path.edgeId,
        source:    path.source,
        target:    path.target,
        technique: path.technique || '',
        notes:     path.notes || '',
        timestamp: path.timestamp,
      },
    });
  }

  const canvas = document.createElement('div');
  canvas.style.cssText = 'width:100%; height:560px; border-radius:12px; overflow:hidden; border:1px solid #e2e8f0;';
  container.appendChild(canvas);

  const cy = cytoscape({
    container: canvas,
    elements,
    style: stylesheet,
    layout: {
      name:      'cose',
      animate:   true,
      animationDuration: 500,
      nodeRepulsion: 10000,
      idealEdgeLength: 150,
      padding: 40,
    },
    minZoom: 0.2,
    maxZoom: 4,
  });

  // Right-click / select edge to delete
  cy.on('tap', 'edge', (e) => {
    const edge = e.target;
    const edgeId    = edge.data('id');
    const technique = edge.data('technique') || '(no technique)';
    const srcLabel  = cy.getElementById(edge.data('source')).data('label');
    const dstLabel  = cy.getElementById(edge.data('target')).data('label');

    if (confirm(`Delete path edge: ${srcLabel} → ${dstLabel} (${technique})?`)) {
      deleteAttackPath(engagementId, edgeId)
        .then(() => {
          toastSuccess('Path edge removed.');
          renderPathing(engagementId, container);
        })
        .catch(err => toastError(err.message || 'Could not delete edge.'));
    }
  });

  // Hint
  const hint = document.createElement('p');
  hint.className = 'text-xs text-slate-400 mt-2';
  hint.textContent = 'Click an edge to delete it · Scroll to zoom · Drag to pan';
  container.appendChild(hint);

  return cy;
}
