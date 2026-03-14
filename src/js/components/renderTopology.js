import cytoscape from 'cytoscape';
import { loadTopology } from '../data/graph.js';

// ── Status colors ─────────────────────────────────────────

const STATUS_BG = {
  compromised: '#dc2626',
  observed:    '#059669',
  unknown:     '#64748b',
};

// ── Ego network BFS ───────────────────────────────────────
// Returns { nodeIds: Set, edgeKeys: Set, levels: { [id]: number } }

function egoNetwork(topology, focalId, maxHops) {
  const adj = {};
  for (const edge of topology.edges) {
    (adj[edge.source] ||= []).push({ neighbor: edge.target, edge });
    (adj[edge.target] ||= []).push({ neighbor: edge.source, edge });
  }

  const levels   = { [focalId]: 0 };
  const nodeIds  = new Set([focalId]);
  const edgeKeys = new Set();
  let frontier   = [focalId];

  for (let hop = 0; hop < maxHops; hop++) {
    const next = [];
    for (const id of frontier) {
      for (const { neighbor, edge } of adj[id] || []) {
        if (!nodeIds.has(neighbor)) {
          nodeIds.add(neighbor);
          levels[neighbor] = hop + 1;
          next.push(neighbor);
        }
        edgeKeys.add(`${edge.source}→${edge.target}:${edge.port}/${edge.protocol}`);
      }
    }
    frontier = next;
  }

  return { nodeIds, edgeKeys, levels };
}

// ── Build Cytoscape elements ──────────────────────────────

function buildElements(topology, focalId, maxHops) {
  const nodeMap = Object.fromEntries(topology.nodes.map(n => [n.id, n]));
  let visibleIds, levels, visibleEdgeKeys;

  if (focalId) {
    const result = egoNetwork(topology, focalId, maxHops);
    visibleIds      = result.nodeIds;
    levels          = result.levels;
    visibleEdgeKeys = result.edgeKeys;
  } else {
    // Show all connected nodes (drop isolated ones)
    const connected = new Set(topology.edges.flatMap(e => [e.source, e.target]));
    visibleIds      = connected;
    levels          = {};
    visibleEdgeKeys = null; // show all edges
  }

  const elements = [];

  // Subnet compound nodes — only include subnets that have visible hosts
  const visibleSubnets = new Set();
  for (const id of visibleIds) {
    const node = nodeMap[id];
    if (node?.subnets?.[0]) visibleSubnets.add(node.subnets[0]);
  }

  for (const cidr of visibleSubnets) {
    elements.push({
      data: { id: `subnet-${cidr}`, label: cidr, type: 'subnet' },
    });
  }

  // Host nodes
  for (const id of visibleIds) {
    const node = nodeMap[id];
    if (!node) continue;
    const isFocal  = id === focalId;
    const level    = levels[id] ?? 99;
    const subnet   = node.subnets?.[0];
    elements.push({
      data: {
        id,
        label:         node.hostname || node.ip || id,
        ip:            node.ip,
        hostname:      node.hostname,
        os:            node.os,
        status:        node.status || 'unknown',
        openPortCount: node.openPortCount || 0,
        isFocal,
        level,
        parent:        subnet && visibleSubnets.has(subnet) ? `subnet-${subnet}` : undefined,
        type:          'host',
      },
    });
  }

  // Edges
  const edgeSeen = new Set();
  for (const edge of topology.edges) {
    if (!visibleIds.has(edge.source) || !visibleIds.has(edge.target)) continue;
    const key = `${edge.source}→${edge.target}:${edge.port}/${edge.protocol}`;
    if (visibleEdgeKeys && !visibleEdgeKeys.has(key)) continue;
    if (edgeSeen.has(key)) continue;
    edgeSeen.add(key);
    elements.push({
      data: {
        id:       key,
        source:   edge.source,
        target:   edge.target,
        port:     edge.port,
        protocol: edge.protocol,
        state:    edge.state,
        label:    edge.port ? `${edge.port}` : '',
        type:     'connection',
      },
    });
  }

  return elements;
}

// ── Cytoscape stylesheet ──────────────────────────────────

const stylesheet = [
  {
    selector: 'node[type="subnet"]',
    style: {
      'background-color':   '#f8fafc',
      'background-opacity': 0.85,
      'border-color':       '#cbd5e1',
      'border-width':       1.5,
      'border-style':       'dashed',
      'label':              'data(label)',
      'font-size':          '10px',
      'font-family':        'monospace',
      'color':              '#94a3b8',
      'text-valign':        'top',
      'text-halign':        'center',
      'text-margin-y':      -6,
      'padding':            '20px',
      'shape':              'round-rectangle',
    },
  },
  {
    selector: 'node[type="host"]',
    style: {
      'width':              42,
      'height':             42,
      'background-color':   (ele) => STATUS_BG[ele.data('status')] || STATUS_BG.unknown,
      'border-color':       '#ffffff',
      'border-width':       (ele) => ele.data('isFocal') ? 4 : 2,
      'border-opacity':     (ele) => ele.data('isFocal') ? 1 : 0.6,
      'label':              'data(label)',
      'font-size':          '10px',
      'font-weight':        (ele) => ele.data('isFocal') ? 'bold' : 'normal',
      'color':              '#1e293b',
      'text-valign':        'bottom',
      'text-halign':        'center',
      'text-margin-y':      5,
      'shape':              'ellipse',
    },
  },
  {
    selector: 'node[type="host"]:selected',
    style: {
      'border-color':   '#6366f1',
      'border-width':   3,
      'border-opacity': 1,
    },
  },
  {
    selector: 'edge[type="connection"]',
    style: {
      'line-color':             '#94a3b8',
      'target-arrow-color':     '#94a3b8',
      'target-arrow-shape':     'triangle',
      'curve-style':            'bezier',
      'width':                  1.5,
      'label':                  'data(label)',
      'font-size':              '9px',
      'font-family':            'monospace',
      'color':                  '#94a3b8',
      'text-rotation':          'autorotate',
      'text-margin-y':          -5,
    },
  },
  {
    selector: 'edge[type="connection"]:selected',
    style: {
      'line-color':         '#6366f1',
      'target-arrow-color': '#6366f1',
    },
  },
];

// ── Layout ────────────────────────────────────────────────

function makeLayout(focalId, levels, nodeCount) {
  if (focalId && nodeCount <= 20) {
    const maxLevel = Math.max(...Object.values(levels), 1);
    return {
      name:       'concentric',
      concentric: (node) => {
        if (node.data('type') === 'subnet') return 0;
        const l = levels[node.data('id')] ?? maxLevel;
        return maxLevel - l + 1;
      },
      levelWidth:  () => 1,
      padding:     40,
      minNodeSpacing: 50,
    };
  }
  return {
    name:           'cose',
    animate:        true,
    animationDuration: 500,
    nodeRepulsion:  12000,
    idealEdgeLength: 130,
    gravity:        0.4,
    padding:        32,
  };
}

// ── Tooltip ───────────────────────────────────────────────

function showTooltip(canvas, ele) {
  canvas.querySelector('#cy-tip')?.remove();
  const d   = ele.data();
  const tip = document.createElement('div');
  tip.id = 'cy-tip';
  tip.className = 'absolute z-50 bg-slate-900 text-xs text-slate-100 rounded-lg px-3 py-2 pointer-events-none shadow-xl max-w-xs';

  if (d.type === 'host') {
    tip.innerHTML = `
      <p class="font-semibold">${d.hostname || d.ip || 'Unknown'}</p>
      ${d.ip && d.hostname ? `<p class="text-slate-400 font-mono">${d.ip}</p>` : ''}
      ${d.os  ? `<p class="text-slate-400">${d.os}</p>`  : ''}
      <p class="mt-1"><span class="badge badge-${d.status}">${d.status}</span></p>
      ${d.openPortCount ? `<p class="text-slate-400 mt-1">${d.openPortCount} open port${d.openPortCount !== 1 ? 's' : ''}</p>` : ''}
      <p class="text-indigo-400 mt-1 text-xs">Click to focus</p>
    `;
  } else if (d.type === 'connection') {
    tip.innerHTML = `
      <p class="font-mono">${d.label || '—'}/${(d.protocol || '').toLowerCase()}</p>
      ${d.state ? `<p class="text-slate-400">${d.state}</p>` : ''}
    `;
  }

  const pos = ele.renderedPosition?.() || ele.renderedMidpoint?.();
  if (pos) {
    tip.style.left = `${pos.x + 14}px`;
    tip.style.top  = `${pos.y - 14}px`;
  }
  canvas.style.position = 'relative';
  canvas.appendChild(tip);
}

// ── Main render ───────────────────────────────────────────

export async function renderTopology(engagementId, container, onHostClick) {
  container.innerHTML = '<p class="text-slate-400 text-sm text-center py-12">Loading topology…</p>';

  let topology;
  try {
    topology = await loadTopology(engagementId);
  } catch (e) {
    container.innerHTML = `<p class="text-red-500 text-sm text-center py-12">Could not load topology: ${e.message}</p>`;
    return;
  }

  // State
  let focalId  = null;
  let hopCount = 1;

  draw();

  function draw() {
    container.innerHTML = '';

    const hostMap = Object.fromEntries(topology.nodes.map(n => [n.id, n]));

    // ── Controls bar ──────────────────────────────────────
    const controls = document.createElement('div');
    controls.className = 'flex items-center gap-3 mb-3 flex-wrap';

    // Host picker
    const pickerWrap = document.createElement('div');
    pickerWrap.className = 'flex items-center gap-2';
    const pickerLabel = document.createElement('span');
    pickerLabel.className = 'text-xs text-slate-500 font-medium';
    pickerLabel.textContent = 'Focus:';
    const picker = document.createElement('select');
    picker.className = 'text-xs border border-slate-200 rounded px-2 py-1 bg-white text-slate-700 min-w-48';
    const blankOpt = document.createElement('option');
    blankOpt.value = '';
    blankOpt.textContent = 'All connected hosts';
    picker.appendChild(blankOpt);
    for (const node of topology.nodes.sort((a, b) => (a.hostname || a.ip || '').localeCompare(b.hostname || b.ip || ''))) {
      const opt = document.createElement('option');
      opt.value = node.id;
      opt.textContent = `${node.hostname || node.ip}${node.ip && node.hostname ? ` (${node.ip})` : ''}`;
      opt.selected = node.id === focalId;
      picker.appendChild(opt);
    }
    picker.onchange = () => { focalId = picker.value || null; draw(); };
    pickerWrap.appendChild(pickerLabel);
    pickerWrap.appendChild(picker);
    controls.appendChild(pickerWrap);

    // Hop toggle (only when focused)
    if (focalId) {
      const hopWrap = document.createElement('div');
      hopWrap.className = 'flex items-center gap-1';
      const hopLabel = document.createElement('span');
      hopLabel.className = 'text-xs text-slate-500 font-medium mr-1';
      hopLabel.textContent = 'Hops:';
      hopWrap.appendChild(hopLabel);
      for (const n of [1, 2, 3]) {
        const b = document.createElement('button');
        b.type = 'button';
        b.textContent = n;
        b.className = `text-xs px-2.5 py-1 rounded border ${hopCount === n ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-slate-600 border-slate-200 hover:border-slate-400'}`;
        b.onclick = () => { hopCount = n; draw(); };
        hopWrap.appendChild(b);
      }
      controls.appendChild(hopWrap);
    }

    // Legend
    const legend = document.createElement('div');
    legend.className = 'flex items-center gap-3 ml-auto text-xs text-slate-500';
    legend.innerHTML = `
      <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-red-600"></span>Compromised</span>
      <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-emerald-600"></span>Observed</span>
      <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-slate-500"></span>Unknown</span>
    `;
    controls.appendChild(legend);
    container.appendChild(controls);

    // ── Empty state ───────────────────────────────────────
    if (!topology.nodes.length || (!topology.edges.length && !focalId)) {
      const empty = document.createElement('p');
      empty.className = 'text-slate-400 text-sm italic py-8 text-center';
      empty.textContent = topology.nodes.length
        ? 'No observed connections yet. Save netstat snapshots to populate edges.'
        : 'No hosts in graph yet. Import scan data or add hosts first.';
      container.appendChild(empty);
      return;
    }

    // ── Canvas ────────────────────────────────────────────
    const canvas = document.createElement('div');
    canvas.style.cssText = 'width:100%; height:580px; border-radius:12px; border:1px solid #e2e8f0;';
    container.appendChild(canvas);

    // Compute ego network for layout
    const { levels } = focalId
      ? egoNetwork(topology, focalId, hopCount)
      : { levels: {} };

    const elements = buildElements(topology, focalId, hopCount);
    const nodeCount = elements.filter(e => !e.data.source).length;

    const cy = cytoscape({
      container: canvas,
      elements,
      style:   stylesheet,
      layout:  makeLayout(focalId, levels, nodeCount),
      minZoom: 0.15,
      maxZoom: 5,
    });

    // Tooltips
    cy.on('mouseover', 'node[type="host"], edge', (e) => showTooltip(canvas, e.target));
    cy.on('mouseout',  'node[type="host"], edge', () => canvas.querySelector('#cy-tip')?.remove());

    // Click host → refocus
    cy.on('tap', 'node[type="host"]', (e) => {
      const id = e.target.data('id');
      if (focalId === id) {
        // Second click on focal → navigate to host detail
        if (onHostClick) onHostClick(id);
      } else {
        focalId = id;
        picker.value = id;
        draw();
      }
    });

    // ── Info bar ──────────────────────────────────────────
    const info = document.createElement('p');
    info.className = 'text-xs text-slate-400 mt-2';
    const visibleEdges = elements.filter(e => e.data.source).length;
    const visibleNodes = elements.filter(e => e.data.type === 'host').length;
    info.innerHTML = focalId
      ? `Showing ${visibleNodes} host${visibleNodes !== 1 ? 's' : ''} · ${visibleEdges} connection${visibleEdges !== 1 ? 's' : ''} within ${hopCount} hop${hopCount !== 1 ? 's' : ''} &nbsp;·&nbsp; Click focused host again to open detail`
      : `${visibleNodes} connected host${visibleNodes !== 1 ? 's' : ''} · ${visibleEdges} connection${visibleEdges !== 1 ? 's' : ''} &nbsp;·&nbsp; Click any host to focus`;
    container.appendChild(info);
  }
}
