import cytoscape from 'cytoscape';
import { loadTopology } from '../data/graph.js';

// ── Status colors ─────────────────────────────────────────

const STATUS_COLOR = {
  compromised: { bg: '#dc2626', border: '#991b1b', text: '#ffffff' },
  observed:    { bg: '#059669', border: '#065f46', text: '#ffffff' },
  unknown:     { bg: '#64748b', border: '#475569', text: '#e2e8f0' },
};

function statusColor(status, prop) {
  return (STATUS_COLOR[status] || STATUS_COLOR.unknown)[prop];
}

// ── Build Cytoscape elements ──────────────────────────────

function buildElements(topology) {
  const elements = [];

  // Subnet compound parent nodes
  for (const cidr of topology.subnets) {
    elements.push({
      data: { id: `subnet-${cidr}`, label: cidr, type: 'subnet' },
    });
  }

  // Host nodes — assign to primary subnet (first subnet in list)
  for (const node of topology.nodes) {
    const primarySubnet = node.subnets?.[0];
    elements.push({
      data: {
        id:            node.id,
        label:         node.hostname || node.ip || node.id,
        ip:            node.ip,
        hostname:      node.hostname,
        os:            node.os,
        status:        node.status || 'unknown',
        openPortCount: node.openPortCount || 0,
        parent:        primarySubnet ? `subnet-${primarySubnet}` : undefined,
        type:          'host',
      },
    });
  }

  // Connection edges
  const edgeSeen = new Set();
  for (const edge of topology.edges) {
    // Deduplicate bidirectional edges for display
    const key = [edge.source, edge.target].sort().join('--');
    const edgeId = `conn-${edge.source}-${edge.target}-${edge.port}-${edge.protocol}`;
    elements.push({
      data: {
        id:       edgeId,
        source:   edge.source,
        target:   edge.target,
        port:     edge.port,
        protocol: edge.protocol,
        state:    edge.state,
        label:    edge.port ? `${edge.port}/${(edge.protocol || '').toLowerCase()}` : '',
        type:     'connection',
      },
    });
    edgeSeen.add(key);
  }

  return elements;
}

// ── Cytoscape stylesheet ──────────────────────────────────

const stylesheet = [
  {
    selector: 'node[type="subnet"]',
    style: {
      'background-color':   '#f1f5f9',
      'background-opacity': 0.8,
      'border-color':       '#cbd5e1',
      'border-width':       1.5,
      'border-style':       'dashed',
      'label':              'data(label)',
      'font-size':          '11px',
      'font-family':        'monospace',
      'color':              '#64748b',
      'text-valign':        'top',
      'text-halign':        'center',
      'text-margin-y':      -8,
      'padding':            '24px',
      'shape':              'round-rectangle',
    },
  },
  {
    selector: 'node[type="host"]',
    style: {
      'width':              40,
      'height':             40,
      'background-color':   (ele) => statusColor(ele.data('status'), 'bg'),
      'border-color':       (ele) => statusColor(ele.data('status'), 'border'),
      'border-width':       2,
      'label':              'data(label)',
      'font-size':          '10px',
      'color':              '#1e293b',
      'text-valign':        'bottom',
      'text-halign':        'center',
      'text-margin-y':      4,
      'shape':              'ellipse',
    },
  },
  {
    selector: 'node[type="host"]:selected',
    style: {
      'border-width': 3,
      'border-color': '#6366f1',
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
      'color':                  '#94a3b8',
      'text-rotation':          'autorotate',
      'text-margin-y':          -6,
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

// ── Tooltip ───────────────────────────────────────────────

function showTooltip(container, ele) {
  removeTooltip(container);
  const data = ele.data();
  const tip  = document.createElement('div');
  tip.id = 'cy-tooltip';
  tip.className = 'absolute z-50 bg-slate-900 text-xs text-slate-100 rounded-lg px-3 py-2 pointer-events-none shadow-lg max-w-xs';

  if (data.type === 'host') {
    tip.innerHTML = `
      <p class="font-semibold mb-1">${data.hostname || data.ip || 'Unknown'}</p>
      ${data.ip       ? `<p class="text-slate-400">${data.ip}</p>` : ''}
      ${data.os       ? `<p class="text-slate-400">${data.os}</p>` : ''}
      <p class="mt-1"><span class="badge badge-${data.status}">${data.status}</span></p>
      ${data.openPortCount ? `<p class="text-slate-400 mt-1">${data.openPortCount} open ports</p>` : ''}
    `;
  } else if (data.type === 'connection') {
    tip.innerHTML = `
      <p class="font-mono">${data.port}/${(data.protocol || '').toLowerCase()}</p>
      ${data.state ? `<p class="text-slate-400">${data.state}</p>` : ''}
    `;
  }

  // Position near cursor
  const pos = ele.renderedPosition?.() || ele.renderedMidpoint?.();
  if (pos) {
    const rect = container.getBoundingClientRect();
    tip.style.left = `${pos.x + 12}px`;
    tip.style.top  = `${pos.y - 12}px`;
  }

  container.style.position = 'relative';
  container.appendChild(tip);
}

function removeTooltip(container) {
  container.querySelector('#cy-tooltip')?.remove();
}

// ── Main render function ──────────────────────────────────

export async function renderTopology(engagementId, container, onHostClick) {
  container.innerHTML = '<p class="text-slate-400 text-sm text-center py-12">Loading topology…</p>';

  let topology;
  try {
    topology = await loadTopology(engagementId);
  } catch (e) {
    container.innerHTML = `<p class="text-red-500 text-sm text-center py-12">Could not load topology: ${e.message}</p>`;
    return;
  }

  if (!topology.nodes.length) {
    container.innerHTML = `
      <p class="text-slate-400 text-sm text-center py-12 italic">
        No graph data yet. Save hosts or run a scan import to populate the topology.<br>
        <span class="text-xs text-slate-500 mt-1 block">You can also trigger a full sync from the menu above.</span>
      </p>
    `;
    return;
  }

  // Mount canvas
  container.innerHTML = '';
  const canvas = document.createElement('div');
  canvas.style.cssText = 'width:100%; height:600px; border-radius:12px; overflow:hidden;';
  container.appendChild(canvas);

  // Toolbar
  const toolbar = document.createElement('div');
  toolbar.className = 'flex items-center gap-3 mb-3 text-xs text-slate-500';
  toolbar.innerHTML = `
    <span><span class="inline-block w-3 h-3 rounded-full bg-red-500 mr-1"></span>Compromised</span>
    <span><span class="inline-block w-3 h-3 rounded-full bg-emerald-600 mr-1"></span>Observed</span>
    <span><span class="inline-block w-3 h-3 rounded-full bg-slate-500 mr-1"></span>Unknown</span>
    <span class="ml-auto text-slate-400">Click host to view details · Scroll to zoom · Drag to pan</span>
  `;
  container.insertBefore(toolbar, canvas);

  const cy = cytoscape({
    container,
    elements: buildElements(topology),
    style:    stylesheet,
    layout: {
      name:             'cose',
      animate:          true,
      animationDuration: 600,
      nodeRepulsion:    8000,
      idealEdgeLength:  120,
      gravity:          0.3,
      padding:          32,
    },
    minZoom: 0.2,
    maxZoom: 4,
  });

  // Replace canvas with properly sized div
  cy.mount(canvas);

  // Tooltip on hover
  cy.on('mouseover', 'node, edge', (e) => showTooltip(canvas, e.target));
  cy.on('mouseout',  'node, edge', ()  => removeTooltip(canvas));

  // Click host → navigate to host detail
  if (onHostClick) {
    cy.on('tap', 'node[type="host"]', (e) => {
      onHostClick(e.target.data('id'));
    });
  }

  return cy;
}
