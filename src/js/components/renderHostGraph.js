import cytoscape from 'cytoscape';
import { loadTopology } from '../data/graph.js';

// ── Stylesheet (consistent with renderTopology) ───────────

const STATUS_BG = {
  compromised: '#dc2626',
  observed:    '#059669',
  unknown:     '#64748b',
};

const stylesheet = [
  {
    selector: 'node[type="host"]',
    style: {
      'width':              48,
      'height':             48,
      'background-color':   (ele) => STATUS_BG[ele.data('status')] || STATUS_BG.unknown,
      'border-color':       '#ffffff',
      'border-width':       (ele) => ele.data('isFocal') ? 4 : 2,
      'border-opacity':     (ele) => ele.data('isFocal') ? 1 : 0.6,
      'label':              'data(label)',
      'font-size':          '11px',
      'font-weight':        (ele) => ele.data('isFocal') ? 'bold' : 'normal',
      'color':              '#1e293b',
      'text-valign':        'bottom',
      'text-halign':        'center',
      'text-margin-y':      6,
      'shape':              'ellipse',
    },
  },
  {
    selector: 'node[type="host"]:selected',
    style: { 'border-color': '#6366f1', 'border-width': 3, 'border-opacity': 1 },
  },
  {
    selector: 'node[type="user"]',
    style: {
      'width':              34,
      'height':             34,
      'background-color':   (ele) => ele.data('isAdmin') ? '#7c3aed' : '#a78bfa',
      'border-color':       '#ffffff',
      'border-width':       1.5,
      'label':              'data(label)',
      'font-size':          '10px',
      'color':              '#1e293b',
      'text-valign':        'bottom',
      'text-halign':        'center',
      'text-margin-y':      5,
      'shape':              'diamond',
    },
  },
  {
    selector: 'edge[type="IS_LOCAL_ADMIN"]',
    style: {
      'line-color':         '#f59e0b',
      'target-arrow-color': '#f59e0b',
      'target-arrow-shape': 'triangle',
      'curve-style':        'bezier',
      'line-style':         'dashed',
      'line-dash-pattern':  [4, 3],
      'width':              1.5,
      'label':              'admin',
      'font-size':          '8px',
      'color':              '#92400e',
      'text-rotation':      'autorotate',
      'text-margin-y':      -5,
    },
  },
  {
    selector: 'edge[type="HAS_SESSION"]',
    style: {
      'line-color':         '#0891b2',
      'target-arrow-color': '#0891b2',
      'target-arrow-shape': 'triangle',
      'curve-style':        'bezier',
      'line-style':         'dashed',
      'line-dash-pattern':  [4, 3],
      'width':              1.5,
      'label':              'session',
      'font-size':          '8px',
      'color':              '#164e63',
      'text-rotation':      'autorotate',
      'text-margin-y':      -5,
    },
  },
  {
    selector: 'edge[type="connection"]',
    style: {
      'line-color':         '#94a3b8',
      'target-arrow-color': '#94a3b8',
      'target-arrow-shape': 'triangle',
      'curve-style':        'bezier',
      'width':              1.5,
      'label':              'data(label)',
      'font-size':          '9px',
      'font-family':        'monospace',
      'color':              '#94a3b8',
      'text-rotation':      'autorotate',
      'text-margin-y':      -5,
    },
  },
];

// ── Main export ───────────────────────────────────────────

export async function renderHostGraph(engagementId, host, container, onHostNavigate) {
  container.innerHTML = '<p class="text-slate-400 text-sm text-center py-12">Loading graph…</p>';

  let topology;
  try {
    topology = await loadTopology(engagementId);
  } catch (e) {
    container.innerHTML = `<p class="text-red-500 text-sm text-center py-12">Could not load graph data: ${e.message}</p>`;
    return;
  }

  const userMap = Object.fromEntries((topology.users || []).map(u => [u.id, u]));
  const nodeMap = Object.fromEntries((topology.nodes || []).map(n => [n.id, n]));

  // Relationships for this host
  const adminEdges   = (topology.userEdges || []).filter(ue => ue.hostId === host.id && ue.type === 'IS_LOCAL_ADMIN');
  const sessionEdges = (topology.userEdges || []).filter(ue => ue.hostId === host.id && ue.type === 'HAS_SESSION');
  const connEdges    = (topology.edges    || []).filter(e  => e.source === host.id || e.target === host.id);

  // Accordion sections definition
  const sections = [
    {
      id:    'admins',
      label: 'Local Admins',
      color: 'amber',
      items: adminEdges.map(ue => {
        const u = userMap[ue.userId];
        return u ? { nodeId: u.id, label: u.username, type: 'user', isAdmin: u.isAdmin, edgeType: 'IS_LOCAL_ADMIN' } : null;
      }).filter(Boolean),
    },
    {
      id:    'sessions',
      label: 'Sessions',
      color: 'cyan',
      items: sessionEdges.map(ue => {
        const u = userMap[ue.userId];
        return u ? { nodeId: u.id, label: u.username, type: 'user', isAdmin: u.isAdmin, edgeType: 'HAS_SESSION' } : null;
      }).filter(Boolean),
    },
    {
      id:    'connections',
      label: 'Connections',
      color: 'slate',
      items: connEdges.map(e => {
        const peerId = e.source === host.id ? e.target : e.source;
        const peer   = nodeMap[peerId];
        if (!peer) return null;
        const dir    = e.source === host.id ? 'out' : 'in';
        return {
          nodeId:   peer.id,
          label:    peer.hostname || peer.ip || peer.id,
          type:     'host',
          status:   peer.status || 'unknown',
          edgeType: 'connection',
          edgeId:   `${e.source}→${e.target}:${e.port}/${e.protocol}`,
          source:   e.source,
          target:   e.target,
          port:     e.port,
          protocol: e.protocol,
          dir,
        };
      }).filter(Boolean),
    },
  ];

  // Deduplicate connection items by nodeId (one entry per peer host)
  sections[2].items = Object.values(
    Object.fromEntries(sections[2].items.map(i => [i.nodeId, i]))
  );

  // ── State ─────────────────────────────────────────────────
  const openSections = new Set();
  let cy = null;

  // ── Layout ────────────────────────────────────────────────
  container.innerHTML = '';
  const wrap = document.createElement('div');
  wrap.className = 'flex gap-4';
  wrap.style.height = '520px';

  const graphDiv = document.createElement('div');
  graphDiv.className = 'flex-1 rounded-xl border border-slate-200 bg-white overflow-hidden relative';

  const rightPanel = document.createElement('div');
  rightPanel.className = 'w-64 flex-shrink-0 flex flex-col gap-2 overflow-y-auto';

  // Info card — shown on node tap, hidden by default
  const infoCard = document.createElement('div');
  infoCard.className = 'hidden rounded-lg border border-slate-200 bg-white p-3 flex-shrink-0';
  rightPanel.appendChild(infoCard);

  wrap.appendChild(graphDiv);
  wrap.appendChild(rightPanel);
  container.appendChild(wrap);

  // ── Cytoscape init ────────────────────────────────────────

  function focalElement() {
    return {
      data: {
        id:      host.id,
        label:   host.hostname || host.ip || host.id,
        type:    'host',
        status:  host.status || 'unknown',
        isFocal: true,
      },
    };
  }

  function rebuildGraph() {
    const elements = [focalElement()];
    const seenNodes = new Set([host.id]);
    const seenEdges = new Set();

    for (const section of sections) {
      if (!openSections.has(section.id)) continue;
      for (const item of section.items) {
        if (!seenNodes.has(item.nodeId)) {
          seenNodes.add(item.nodeId);
          elements.push({
            data: {
              id:      item.nodeId,
              label:   item.label,
              type:    item.type,
              status:  item.status || 'unknown',
              isAdmin: item.isAdmin || false,
            },
          });
        }
        const edgeKey = item.edgeType === 'connection'
          ? item.edgeId
          : `${item.nodeId}→${host.id}:${item.edgeType}`;
        if (!seenEdges.has(edgeKey)) {
          seenEdges.add(edgeKey);
          elements.push({
            data: {
              id:       edgeKey,
              source:   item.edgeType === 'connection' ? item.source : item.nodeId,
              target:   item.edgeType === 'connection' ? item.target : host.id,
              type:     item.edgeType,
              label:    item.edgeType === 'connection' ? (item.port ? String(item.port) : '') : '',
            },
          });
        }
      }
    }

    cy.elements().remove();
    cy.add(elements);

    const nonFocal = cy.nodes().filter(n => n.data('id') !== host.id);

    if (nonFocal.length === 0) {
      // Just the focal host — place at center
      cy.nodes().first().position({ x: graphDiv.offsetWidth / 2 || 300, y: 240 });
      cy.zoom(1.2);
      cy.center();
    } else {
      cy.layout({
        name:        'concentric',
        concentric:  (n) => n.data('id') === host.id ? 2 : 1,
        levelWidth:  () => 1,
        padding:     60,
        minNodeSpacing: 55,
      }).run();
    }
  }

  cy = cytoscape({
    container: graphDiv,
    elements:  [focalElement()],
    style:     stylesheet,
    layout:    { name: 'preset' },
    minZoom:   0.3,
    maxZoom:   5,
  });

  // Place focal host at center initially
  cy.ready(() => {
    cy.nodes().first().position({ x: graphDiv.offsetWidth / 2 || 300, y: 240 });
    cy.zoom(1.2);
    cy.center();
  });

  // ── Node tap → info card ──────────────────────────────────

  function showInfoCard(d) {
    infoCard.innerHTML = '';
    infoCard.classList.remove('hidden');

    if (d.type === 'host') {
      const isFocal = d.id === host.id;
      const hostData = isFocal ? host : (nodeMap[d.id] || {});
      const status = hostData.status || d.status || 'unknown';
      const statusColor = status === 'compromised' ? 'bg-red-100 text-red-700' :
                          status === 'observed'    ? 'bg-emerald-100 text-emerald-700' :
                                                     'bg-slate-100 text-slate-500';
      infoCard.innerHTML = `
        <div class="flex items-start justify-between gap-2 mb-2">
          <span class="text-sm font-semibold font-mono text-slate-800 break-all">${hostData.ip || d.label || '—'}</span>
          <span class="text-xs px-1.5 py-0.5 rounded-full flex-shrink-0 ${statusColor}">${status}</span>
        </div>
        ${hostData.hostname && hostData.hostname !== hostData.ip ? `<p class="text-xs text-slate-500 mb-1">${hostData.hostname}</p>` : ''}
        ${hostData.os ? `<p class="text-xs text-slate-400">${hostData.os}</p>` : ''}
      `;
      if (!isFocal && onHostNavigate) {
        const navBtn = document.createElement('button');
        navBtn.type = 'button';
        navBtn.className = 'mt-2 w-full text-xs text-indigo-600 hover:text-indigo-800 text-left font-medium';
        navBtn.textContent = 'Go to host detail →';
        navBtn.onclick = () => onHostNavigate(d.id);
        infoCard.appendChild(navBtn);
      }
    } else if (d.type === 'user') {
      infoCard.innerHTML = `
        <p class="text-sm font-semibold text-slate-800 break-all">${d.label}</p>
        ${d.domain ? `<p class="text-xs text-slate-400 mt-0.5">${d.domain}</p>` : ''}
        ${d.isAdmin ? '<p class="text-xs text-violet-600 font-medium mt-1">Local Admin</p>' : '<p class="text-xs text-slate-400 mt-1">Session user</p>'}
      `;
    }
  }

  cy.on('tap', 'node', (e) => showInfoCard(e.target.data()));
  cy.on('tap', (e) => { if (e.target === cy) { infoCard.classList.add('hidden'); infoCard.innerHTML = ''; } });
  cy.on('dbltap', 'node[type="host"]', (e) => {
    const id = e.target.data('id');
    if (id !== host.id && onHostNavigate) onHostNavigate(id);
  });

  // Empty-state hint overlay
  const hint = document.createElement('p');
  hint.className = 'absolute bottom-3 left-0 right-0 text-center text-xs text-slate-400 pointer-events-none';
  hint.textContent = 'Select a relationship type to explore';
  graphDiv.appendChild(hint);

  // ── Accordion panels ──────────────────────────────────────

  const relHeader = document.createElement('div');
  relHeader.className = 'pt-3 pb-1 border-t border-slate-200 mt-1';
  relHeader.innerHTML = '<span class="text-xs font-semibold uppercase tracking-wider text-slate-400">Relationships</span>';
  rightPanel.appendChild(relHeader);

  for (const section of sections) {
    const count = section.items.length;

    const accDiv = document.createElement('div');
    accDiv.className = 'border border-slate-200 rounded-lg overflow-hidden bg-white';

    // Header button
    const header = document.createElement('button');
    header.type = 'button';
    const disabledStyle = count === 0 ? 'opacity-50 cursor-default' : 'hover:bg-slate-50 cursor-pointer';
    header.className = `w-full flex items-center justify-between px-3 py-2.5 text-left ${disabledStyle}`;
    header.disabled = count === 0;

    const activeClass = {
      amber: 'bg-amber-50 border-amber-200',
      cyan:  'bg-cyan-50 border-cyan-200',
      slate: 'bg-slate-50 border-slate-300',
    }[section.color] || 'bg-slate-50';

    const countBadge = {
      amber: 'bg-amber-100 text-amber-700',
      cyan:  'bg-cyan-100 text-cyan-700',
      slate: 'bg-slate-100 text-slate-500',
    }[section.color] || 'bg-slate-100 text-slate-500';

    header.innerHTML = `
      <span class="text-sm font-medium text-slate-700">${section.label}</span>
      <span class="flex items-center gap-2">
        <span class="text-xs px-1.5 py-0.5 rounded-full font-medium ${countBadge}">${count}</span>
        <span class="text-slate-400 text-xs transition-transform duration-150 acc-arrow">▶</span>
      </span>
    `;

    // Body
    const body = document.createElement('div');
    body.className = 'hidden border-t border-slate-100 divide-y divide-slate-50 max-h-52 overflow-y-auto';

    for (const item of section.items) {
      const row = document.createElement('div');
      row.className = 'px-3 py-1.5 text-xs text-slate-600 font-mono flex items-center gap-2';
      if (item.type === 'user') {
        const dot = document.createElement('span');
        dot.className = `inline-block w-2 h-2 rounded-sm rotate-45 flex-shrink-0 ${item.isAdmin ? 'bg-violet-600' : 'bg-violet-400'}`;
        row.appendChild(dot);
      } else {
        const dot = document.createElement('span');
        dot.className = `inline-block w-2 h-2 rounded-full flex-shrink-0 ${
          item.status === 'compromised' ? 'bg-red-500' :
          item.status === 'observed'    ? 'bg-emerald-500' : 'bg-slate-400'
        }`;
        row.appendChild(dot);
      }
      const label = document.createElement('span');
      label.textContent = item.label;
      row.appendChild(label);
      if (item.dir) {
        const dir = document.createElement('span');
        dir.className = 'ml-auto text-slate-300';
        dir.textContent = item.dir === 'out' ? '→' : '←';
        row.appendChild(dir);
      }
      body.appendChild(row);
    }

    // Toggle
    header.onclick = () => {
      if (count === 0) return;
      const isOpen = openSections.has(section.id);
      if (isOpen) {
        openSections.delete(section.id);
        body.classList.add('hidden');
        accDiv.className = 'border border-slate-200 rounded-lg overflow-hidden bg-white';
        header.querySelector('.acc-arrow').style.transform = '';
      } else {
        openSections.add(section.id);
        body.classList.remove('hidden');
        accDiv.className = `border rounded-lg overflow-hidden ${activeClass}`;
        header.querySelector('.acc-arrow').style.transform = 'rotate(90deg)';
      }
      hint.style.display = openSections.size > 0 ? 'none' : '';
      rebuildGraph();
    };

    accDiv.appendChild(header);
    accDiv.appendChild(body);
    rightPanel.appendChild(accDiv);
  }
}
