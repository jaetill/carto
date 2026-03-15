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

// ── Ego network BFS — user as focal node ─────────────────
// Returns { nodeIds, edgeKeys, levels, directHostIds }

function egoNetworkUser(topology, userId, maxHops) {
  const userEdgesForUser = (topology.userEdges || []).filter(ue => ue.userId === userId);
  const directHostIds    = new Set(userEdgesForUser.map(ue => ue.hostId));

  const levels  = { [userId]: 0 };
  const nodeIds = new Set([userId]);
  for (const hid of directHostIds) { nodeIds.add(hid); levels[hid] = 1; }

  if (maxHops >= 2) {
    const adj = {};
    for (const edge of topology.edges) {
      (adj[edge.source] ||= []).push({ neighbor: edge.target, edge });
      (adj[edge.target] ||= []).push({ neighbor: edge.source, edge });
    }
    let frontier = [...directHostIds];
    for (let hop = 1; hop < maxHops; hop++) {
      const next = [];
      for (const id of frontier) {
        for (const { neighbor } of adj[id] || []) {
          if (!nodeIds.has(neighbor)) {
            nodeIds.add(neighbor);
            levels[neighbor] = hop + 1;
            next.push(neighbor);
          }
        }
      }
      frontier = next;
    }
  }

  const edgeKeys = new Set();
  for (const edge of topology.edges) {
    if (nodeIds.has(edge.source) && nodeIds.has(edge.target)) {
      edgeKeys.add(`${edge.source}→${edge.target}:${edge.port}/${edge.protocol}`);
    }
  }

  return { nodeIds, edgeKeys, levels, directHostIds };
}

// ── Build Cytoscape elements ──────────────────────────────

function buildElements(topology, focalId, maxHops, showAdmins, showSessions) {
  const nodeMap      = Object.fromEntries(topology.nodes.map(n => [n.id, n]));
  const isUserFocal  = !!(focalId && focalId.startsWith('user_'));
  let visibleIds, levels, visibleEdgeKeys, directHostIds;

  if (focalId && isUserFocal) {
    const result = egoNetworkUser(topology, focalId, maxHops);
    visibleIds      = result.nodeIds;
    levels          = result.levels;
    visibleEdgeKeys = result.edgeKeys;
    directHostIds   = result.directHostIds;
  } else if (focalId) {
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

  // Subnet compound nodes — only in full-graph mode (conflicts with concentric in focal mode)
  const visibleSubnets = new Set();
  for (const id of visibleIds) {
    const node = nodeMap[id];
    if (node?.subnets?.[0]) visibleSubnets.add(node.subnets[0]);
  }

  if (!focalId) {
    for (const cidr of visibleSubnets) {
      elements.push({
        data: { id: `subnet-${cidr}`, label: cidr, type: 'subnet' },
      });
    }
  }

  // Host nodes (skip the focal user ID which lives in users, not nodes)
  for (const id of visibleIds) {
    if (isUserFocal && id === focalId) continue;
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
        parent:        (!focalId && subnet && visibleSubnets.has(subnet)) ? `subnet-${subnet}` : undefined,
        type:          'host',
      },
    });
  }

  // Edges (host ↔ host connections)
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

  // User nodes + edges
  if (topology.users?.length || topology.userEdges?.length) {
    const userMap = Object.fromEntries((topology.users || []).map(u => [u.id, u]));

    if (isUserFocal) {
      // ── User-focal: focal user at center, show their edges to visible hosts ──
      const u = userMap[focalId];
      if (u) {
        elements.push({
          data: { id: focalId, label: u.username, domain: u.domain, isAdmin: u.isAdmin, isFocal: true, level: 0, type: 'user' },
        });
      }
      // Focal user's own edges — always shown, but filtered by type toggle
      for (const ue of topology.userEdges || []) {
        if (ue.userId !== focalId) continue;
        if (!visibleIds.has(ue.hostId)) continue;
        if (ue.type === 'IS_LOCAL_ADMIN' && !showAdmins) continue;
        if (ue.type === 'HAS_SESSION'    && !showSessions) continue;
        const key = `${ue.userId}→${ue.hostId}:${ue.type}`;
        if (edgeSeen.has(key)) continue;
        edgeSeen.add(key);
        elements.push({ data: { id: key, source: ue.userId, target: ue.hostId, type: ue.type, fromIp: ue.fromIp, label: '' } });
      }
      // Other users on visible hosts (optional context — gated on toggles)
      if (showAdmins || showSessions) {
        const otherUserEdges = (topology.userEdges || []).filter(ue => {
          if (ue.userId === focalId) return false;
          if (!visibleIds.has(ue.hostId)) return false;
          if (ue.type === 'IS_LOCAL_ADMIN' && !showAdmins) return false;
          if (ue.type === 'HAS_SESSION'    && !showSessions) return false;
          return true;
        });
        const otherUserIds = new Set(otherUserEdges.map(ue => ue.userId));
        for (const uid of otherUserIds) {
          const ou = userMap[uid];
          if (!ou) continue;
          elements.push({ data: { id: uid, label: ou.username, domain: ou.domain, isAdmin: ou.isAdmin, type: 'user' } });
        }
        for (const ue of otherUserEdges) {
          const key = `${ue.userId}→${ue.hostId}:${ue.type}`;
          if (edgeSeen.has(key)) continue;
          edgeSeen.add(key);
          elements.push({ data: { id: key, source: ue.userId, target: ue.hostId, type: ue.type, fromIp: ue.fromIp, label: '' } });
        }
      }
    } else if (focalId && (showAdmins || showSessions)) {
      // ── Host-focal: show users connected to the focal host ──
      const visibleUserEdges = (topology.userEdges || []).filter(ue => {
        if (ue.hostId !== focalId) return false;
        if (ue.type === 'IS_LOCAL_ADMIN' && !showAdmins) return false;
        if (ue.type === 'HAS_SESSION'    && !showSessions) return false;
        return true;
      });
      const visibleUserIds = new Set(visibleUserEdges.map(ue => ue.userId));
      for (const uid of visibleUserIds) {
        const u = userMap[uid];
        if (!u) continue;
        elements.push({ data: { id: uid, label: u.username, domain: u.domain, isAdmin: u.isAdmin, type: 'user' } });
      }
      for (const ue of visibleUserEdges) {
        if (!visibleUserIds.has(ue.userId)) continue;
        const key = `${ue.userId}→${ue.hostId}:${ue.type}`;
        if (edgeSeen.has(key)) continue;
        edgeSeen.add(key);
        elements.push({ data: { id: key, source: ue.userId, target: ue.hostId, type: ue.type, fromIp: ue.fromIp, label: '' } });
      }
    }
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
    selector: 'node[type="user"]',
    style: {
      'width':            28,
      'height':           28,
      'background-color': (ele) => ele.data('isAdmin') ? '#7c3aed' : '#a78bfa',
      'border-color':     '#ffffff',
      'border-width':     1.5,
      'label':            'data(label)',
      'font-size':        '9px',
      'font-weight':      (ele) => ele.data('isFocal') ? 'bold' : 'normal',
      'color':            '#1e293b',
      'text-valign':      'bottom',
      'text-halign':      'center',
      'text-margin-y':    4,
      'shape':            'diamond',
    },
  },
  {
    selector: 'node[type="user"][?isFocal]',
    style: {
      'width':        40,
      'height':       40,
      'border-width': 4,
      'border-color': '#ffffff',
      'font-size':    '10px',
    },
  },
  {
    selector: 'node[type="user"]:selected',
    style: { 'border-color': '#6366f1', 'border-width': 2.5 },
  },
  {
    selector: 'edge[type="IS_LOCAL_ADMIN"]',
    style: {
      'line-color':             '#f59e0b',
      'target-arrow-color':     '#f59e0b',
      'target-arrow-shape':     'triangle',
      'curve-style':            'bezier',
      'line-style':             'dashed',
      'line-dash-pattern':      [4, 3],
      'width':                  1.5,
      'label':                  'admin',
      'font-size':              '8px',
      'color':                  '#92400e',
      'text-rotation':          'autorotate',
      'text-margin-y':          -5,
    },
  },
  {
    selector: 'edge[type="HAS_SESSION"]',
    style: {
      'line-color':             '#0891b2',
      'target-arrow-color':     '#0891b2',
      'target-arrow-shape':     'triangle',
      'curve-style':            'bezier',
      'line-style':             'dashed',
      'line-dash-pattern':      [4, 3],
      'width':                  1.5,
      'label':                  'session',
      'font-size':              '8px',
      'color':                  '#164e63',
      'text-rotation':          'autorotate',
      'text-margin-y':          -5,
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

function makeLayout(focalId, levels) {
  if (focalId) {
    const maxLevel = Math.max(...Object.values(levels), 1);
    return {
      name:       'concentric',
      concentric: (node) => {
        if (node.data('type') === 'subnet') return 0;
        const id = node.data('id');
        // Non-focal user nodes sit in the outermost ring
        if (node.data('type') === 'user' && id !== focalId) return 1;
        // Focal node (host or user) = innermost; each hop ring moves outward
        const l = levels[id] ?? maxLevel;
        return maxLevel - l + 2;
      },
      levelWidth:  () => 1,
      padding:     40,
      minNodeSpacing: 60,
    };
  }
  return {
    name:           'cose',
    animate:        true,
    animationDuration: 500,
    nodeRepulsion:  14000,
    idealEdgeLength: 100,
    gravity:        0.5,
    padding:        40,
  };
}

// ── User detail panel ─────────────────────────────────────

function renderUserPanel(panel, userId, topology, onHostClick) {
  const hostMap  = Object.fromEntries(topology.nodes.map(n => [n.id, n]));
  const userMap  = Object.fromEntries((topology.users || []).map(u => [u.id, u]));
  const user     = userMap[userId];
  if (!user) return;

  const userEdges   = (topology.userEdges || []).filter(ue => ue.userId === userId);
  const adminHosts  = [...new Map(userEdges.filter(ue => ue.type === 'IS_LOCAL_ADMIN').map(ue => [ue.hostId, hostMap[ue.hostId]])).values()].filter(Boolean);
  const sessionHosts= [...new Map(userEdges.filter(ue => ue.type === 'HAS_SESSION')   .map(ue => [ue.hostId, hostMap[ue.hostId]])).values()].filter(Boolean);

  // Header
  const header = document.createElement('div');
  header.className = 'p-4 border-b border-slate-100';
  const nameRow = document.createElement('div');
  nameRow.className = 'flex items-center gap-2 flex-wrap';
  const icon = document.createElement('span');
  icon.className = 'inline-block w-3 h-3 rotate-45 bg-violet-600 flex-shrink-0';
  const name = document.createElement('span');
  name.className = 'font-semibold text-slate-800 text-sm font-mono break-all';
  name.textContent = user.domain ? `${user.domain}\\${user.username}` : user.username;
  nameRow.appendChild(icon);
  nameRow.appendChild(name);
  if (user.isAdmin) {
    const badge = document.createElement('span');
    badge.className = 'text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded font-semibold flex-shrink-0';
    badge.textContent = 'Admin';
    nameRow.appendChild(badge);
  }
  header.appendChild(nameRow);
  panel.appendChild(header);

  function addSection(title, hosts, countColor) {
    if (!hosts.length) return;
    const details = document.createElement('details');
    details.open = true;
    details.className = 'border-b border-slate-100';
    const summary = document.createElement('summary');
    summary.className = 'flex items-center justify-between px-4 py-2.5 cursor-pointer select-none text-xs font-semibold text-slate-500 uppercase tracking-wider hover:bg-slate-50 [list-style:none] [&::-webkit-details-marker]:hidden';
    const titleSpan = document.createElement('span');
    titleSpan.textContent = title;
    const countBadge = document.createElement('span');
    countBadge.className = `${countColor} text-white text-xs px-1.5 py-0.5 rounded-full font-bold`;
    countBadge.textContent = hosts.length;
    summary.appendChild(titleSpan);
    summary.appendChild(countBadge);
    details.appendChild(summary);
    const body = document.createElement('div');
    body.className = 'px-4 pb-3 pt-1 space-y-1.5';
    hosts.forEach(h => {
      const row = document.createElement('div');
      row.className = 'flex items-center gap-2';
      const dot = document.createElement('span');
      dot.className = `inline-block w-2 h-2 rounded-full flex-shrink-0 ${
        h.status === 'compromised' ? 'bg-red-500' : h.status === 'observed' ? 'bg-emerald-500' : 'bg-slate-400'
      }`;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'text-xs text-left text-indigo-600 hover:text-indigo-800 font-mono truncate';
      btn.textContent = h.hostname || h.ip;
      btn.title = (h.hostname && h.ip) ? `${h.hostname} (${h.ip})` : (h.ip || h.hostname || '');
      btn.onclick = () => { if (onHostClick) onHostClick(h.id); };
      row.appendChild(dot);
      row.appendChild(btn);
      body.appendChild(row);
    });
    details.appendChild(body);
    panel.appendChild(details);
  }

  addSection('Admin on', adminHosts, 'bg-amber-500');
  addSection('Sessions on', sessionHosts, 'bg-cyan-600');

  if (!adminHosts.length && !sessionHosts.length) {
    const empty = document.createElement('p');
    empty.className = 'text-xs text-slate-400 px-4 py-4 italic';
    empty.textContent = 'No relationships found.';
    panel.appendChild(empty);
  }
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
  } else if (d.type === 'user') {
    tip.innerHTML = `
      <p class="font-semibold">${d.domain ? `${d.domain}\\` : ''}${d.label}</p>
      ${d.isAdmin ? '<p class="text-red-400 font-semibold text-xs mt-0.5">Local Admin</p>' : ''}
      ${d.isFocal ? '' : '<p class="text-violet-400 mt-1 text-xs">Click to focus</p>'}
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
  let focalId      = null;
  let hopCount     = 1;
  let showAdmins   = true;
  let showSessions = true;

  draw();

  function draw() {
    container.innerHTML = '';

    const hostMap = Object.fromEntries(topology.nodes.map(n => [n.id, n]));

    // ── Controls bar ──────────────────────────────────────
    const controls = document.createElement('div');
    controls.className = 'flex items-center gap-3 mb-3 flex-wrap';

    const isUserFocal = !!(focalId && focalId.startsWith('user_'));
    const userMap     = Object.fromEntries((topology.users || []).map(u => [u.id, u]));

    // Host picker
    const pickerWrap = document.createElement('div');
    pickerWrap.className = 'flex items-center gap-2 flex-wrap';
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
      opt.selected = !isUserFocal && node.id === focalId;
      picker.appendChild(opt);
    }
    picker.onchange = () => { focalId = picker.value || null; draw(); };
    pickerWrap.appendChild(pickerLabel);
    pickerWrap.appendChild(picker);

    // User focal badge — shown instead of a picker selection when a user is focal
    if (isUserFocal) {
      const focalUser = userMap[focalId];
      if (focalUser) {
        const badge = document.createElement('span');
        badge.className = 'inline-flex items-center gap-1.5 text-xs bg-violet-100 text-violet-800 px-2 py-1 rounded-full font-medium';
        badge.innerHTML = `<span class="inline-block w-2 h-2 rotate-45 bg-violet-600 flex-shrink-0"></span>${focalUser.domain ? `${focalUser.domain}\\` : ''}${focalUser.username}`;
        const clearBtn = document.createElement('button');
        clearBtn.type = 'button';
        clearBtn.className = 'ml-0.5 text-violet-500 hover:text-violet-800 font-bold leading-none';
        clearBtn.textContent = '×';
        clearBtn.title = 'Clear user focus';
        clearBtn.onclick = () => { focalId = null; draw(); };
        badge.appendChild(clearBtn);
        pickerWrap.appendChild(badge);
      }
    }

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

    // Relationship toggles — show when focused and focal has relevant user edges
    const hasFocalUserEdges = isUserFocal
      ? topology.userEdges?.some(ue => ue.userId === focalId)
      : focalId && topology.userEdges?.some(ue => ue.hostId === focalId);
    if (hasFocalUserEdges) {
      const relWrap = document.createElement('div');
      relWrap.className = 'flex items-center gap-1';
      const relLabel = document.createElement('span');
      relLabel.className = 'text-xs text-slate-500 font-medium mr-1';
      relLabel.textContent = 'Show:';
      relWrap.appendChild(relLabel);

      for (const [label, key, activeClass] of [
        ['Admins',   'admins',   'bg-amber-600 text-white border-amber-600'],
        ['Sessions', 'sessions', 'bg-cyan-600 text-white border-cyan-600'],
      ]) {
        const active = key === 'admins' ? showAdmins : showSessions;
        const b = document.createElement('button');
        b.type = 'button';
        b.textContent = label;
        b.className = `text-xs px-2.5 py-1 rounded border ${active ? activeClass : 'bg-white text-slate-600 border-slate-200 hover:border-slate-400'}`;
        b.onclick = () => {
          if (key === 'admins') showAdmins = !showAdmins;
          else showSessions = !showSessions;
          draw();
        };
        relWrap.appendChild(b);
      }
      controls.appendChild(relWrap);
    }

    // Legend
    const legend = document.createElement('div');
    legend.className = 'flex items-center gap-3 ml-auto text-xs text-slate-500';
    legend.innerHTML = `
      <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-red-600"></span>Compromised</span>
      <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-emerald-600"></span>Observed</span>
      <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-slate-500"></span>Unknown</span>
      <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rotate-45 bg-violet-600"></span>User</span>
    `;
    controls.appendChild(legend);
    container.appendChild(controls);

    // ── Empty state ───────────────────────────────────────
    if (!topology.nodes.length || (!topology.edges.length && !focalId && !isUserFocal)) {
      const empty = document.createElement('p');
      empty.className = 'text-slate-400 text-sm italic py-8 text-center';
      empty.textContent = topology.nodes.length
        ? 'No observed connections yet. Save netstat snapshots to populate edges.'
        : 'No hosts in graph yet. Import scan data or add hosts first.';
      container.appendChild(empty);
      return;
    }

    // ── Canvas + side panel ───────────────────────────────
    const graphRow = document.createElement('div');
    graphRow.className = 'flex gap-3 items-start';
    container.appendChild(graphRow);

    const canvas = document.createElement('div');
    canvas.style.cssText = 'flex:1; min-width:0; height:580px; border-radius:12px; border:1px solid #e2e8f0;';
    graphRow.appendChild(canvas);

    if (isUserFocal) {
      const panel = document.createElement('div');
      panel.className = 'w-56 flex-shrink-0 bg-white rounded-xl border border-slate-200 overflow-y-auto';
      panel.style.maxHeight = '580px';
      renderUserPanel(panel, focalId, topology, onHostClick);
      graphRow.appendChild(panel);
    }

    // Compute ego network for layout
    const { levels } = isUserFocal
      ? egoNetworkUser(topology, focalId, hopCount)
      : focalId
        ? egoNetwork(topology, focalId, hopCount)
        : { levels: {} };

    const elements = buildElements(topology, focalId, hopCount, showAdmins, showSessions);

    const cy = cytoscape({
      container: canvas,
      elements,
      style:   stylesheet,
      layout:  makeLayout(focalId, levels),
      minZoom: 0.15,
      maxZoom: 5,
    });

    // Tooltips
    cy.on('mouseover', 'node[type="host"], node[type="user"], edge', (e) => showTooltip(canvas, e.target));
    cy.on('mouseout',  'node[type="host"], node[type="user"], edge', () => canvas.querySelector('#cy-tip')?.remove());

    // Single tap → refocus; double-tap → navigate to host detail
    let _tapTimer = null;
    cy.on('tap', 'node[type="host"]', (e) => {
      const id = e.target.data('id');
      if (_tapTimer?.id === id) {
        clearTimeout(_tapTimer.t);
        _tapTimer = null;
        if (onHostClick) onHostClick(id);
      } else {
        if (_tapTimer) clearTimeout(_tapTimer.t);
        _tapTimer = { id, t: setTimeout(() => {
          _tapTimer = null;
          focalId = id;
          picker.value = id;
          draw();
        }, 280) };
      }
    });

    // Click user → set as focal (panel appears via draw); second click clears
    cy.on('tap', 'node[type="user"]', (e) => {
      const id = e.target.data('id');
      focalId = (isUserFocal && focalId === id) ? null : id;
      picker.value = '';
      draw();
    });

    // ── Info bar ──────────────────────────────────────────
    const info = document.createElement('p');
    info.className = 'text-xs text-slate-400 mt-2';
    const visibleHostNodes = elements.filter(e => e.data.type === 'host').length;
    const visibleUserNodes = elements.filter(e => e.data.type === 'user' && !e.data.isFocal).length;
    const visibleEdges     = elements.filter(e => e.data.source && e.data.type === 'connection').length;
    const userPart = visibleUserNodes ? ` · ${visibleUserNodes} other user${visibleUserNodes !== 1 ? 's' : ''}` : '';
    if (isUserFocal) {
      const adminCount   = elements.filter(e => e.data.type === 'IS_LOCAL_ADMIN').length;
      const sessionCount = elements.filter(e => e.data.type === 'HAS_SESSION').length;
      const parts = [];
      if (adminCount)   parts.push(`admin on ${adminCount} host${adminCount !== 1 ? 's' : ''}`);
      if (sessionCount) parts.push(`session on ${sessionCount} host${sessionCount !== 1 ? 's' : ''}`);
      info.innerHTML = `${parts.join(' · ') || `${visibleHostNodes} host${visibleHostNodes !== 1 ? 's' : ''}`}${userPart} &nbsp;·&nbsp; Click user again to clear focus`;
    } else {
      info.innerHTML = focalId
        ? `Showing ${visibleHostNodes} host${visibleHostNodes !== 1 ? 's' : ''}${userPart} · ${visibleEdges} connection${visibleEdges !== 1 ? 's' : ''} within ${hopCount} hop${hopCount !== 1 ? 's' : ''} &nbsp;·&nbsp; Double-click any host to open detail`
        : `${visibleHostNodes} connected host${visibleHostNodes !== 1 ? 's' : ''} · ${visibleEdges} connection${visibleEdges !== 1 ? 's' : ''} &nbsp;·&nbsp; Click to focus · Double-click to open detail · Click any user to focus`;
    }
    container.appendChild(info);
  }
}
