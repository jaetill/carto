import { btn } from '../ui/elements.js';
import { loadTopology } from '../data/graph.js';

export async function renderUser(engagementId, userId, data, snapshots, onBack) {
  const container = document.getElementById('app-content');
  container.innerHTML = '<p class="text-slate-400 text-sm text-center py-12">Loading…</p>';

  const topology = await loadTopology(engagementId);
  const user = topology.users.find(u => u.id === userId);
  if (!user) { onBack(); return; }

  const userEdges = topology.userEdges.filter(e => e.userId === userId);
  const adminHostIds   = userEdges.filter(e => e.type === 'IS_LOCAL_ADMIN').map(e => e.hostId);
  const sessionHostIds = userEdges.filter(e => e.type === 'HAS_SESSION').map(e => e.hostId);
  const hostMap = Object.fromEntries(data.hosts.map(h => [h.id, h]));

  // Snapshots that mention this username
  const norm = user.username.toLowerCase();
  const mentioningSnaps = snapshots.filter(snap => {
    if (!snap.rawOutput) return false;
    return snap.rawOutput.toLowerCase().includes(norm);
  });
  // Group by host
  const mentionByHost = {};
  for (const snap of mentioningSnaps) {
    if (!mentionByHost[snap.hostId]) mentionByHost[snap.hostId] = [];
    mentionByHost[snap.hostId].push(snap);
  }

  render();

  function render() {
    container.innerHTML = '';

    // ── Header ────────────────────────────────────────────
    const header = document.createElement('div');
    header.className = 'flex items-start gap-4 mb-6';

    const backBtn = btn('← Back', 'ghost');
    backBtn.className += ' text-xs flex-shrink-0';
    backBtn.onclick = onBack;

    const titleBlock = document.createElement('div');
    titleBlock.className = 'flex-1 min-w-0';

    const nameRow = document.createElement('div');
    nameRow.className = 'flex items-center gap-2 flex-wrap';

    const nameEl = document.createElement('h2');
    nameEl.className = 'text-2xl font-bold text-slate-800 font-mono';
    nameEl.textContent = user.username;

    if (user.domain) {
      const domainBadge = document.createElement('span');
      domainBadge.className = 'text-xs bg-slate-100 text-slate-500 px-2 py-0.5 rounded font-mono';
      domainBadge.textContent = user.domain;
      nameRow.appendChild(nameEl);
      nameRow.appendChild(domainBadge);
    } else {
      nameRow.appendChild(nameEl);
    }

    if (user.isAdmin) {
      const adminBadge = document.createElement('span');
      adminBadge.className = 'text-xs bg-amber-100 text-amber-700 px-2 py-0.5 rounded font-medium';
      adminBadge.textContent = 'local admin';
      nameRow.appendChild(adminBadge);
    }

    titleBlock.appendChild(nameRow);
    header.appendChild(backBtn);
    header.appendChild(titleBlock);
    container.appendChild(header);

    // ── Sections ──────────────────────────────────────────
    const sections = document.createElement('div');
    sections.className = 'space-y-6';

    // Credentials for this user
    const userCreds = (data.credentials || []).filter(c =>
      c.username.toLowerCase() === user.username.toLowerCase()
    );
    if (userCreds.length > 0) {
      const credSection = document.createElement('div');
      const credHeading = document.createElement('h3');
      credHeading.className = 'text-sm font-semibold text-slate-600 mb-2';
      credHeading.textContent = `Credentials (${userCreds.length})`;
      credSection.appendChild(credHeading);

      const credList = document.createElement('div');
      credList.className = 'space-y-2';
      for (const cred of userCreds) {
        const chip = document.createElement('div');
        chip.className = 'flex items-center gap-2 bg-white border border-slate-100 rounded-lg px-3 py-2 text-xs';
        const typeBadge = document.createElement('span');
        typeBadge.className = `px-2 py-0.5 rounded font-medium ${
          cred.secretType === 'plaintext' ? 'bg-green-100 text-green-700' :
          cred.secretType === 'ntlm'      ? 'bg-red-100 text-red-700' :
          cred.secretType === 'kerberos'  ? 'bg-purple-100 text-purple-700' :
                                            'bg-orange-100 text-orange-700'
        }`;
        typeBadge.textContent = cred.secretType;
        const secretSpan = document.createElement('span');
        secretSpan.className = 'font-mono text-slate-500 cursor-pointer hover:text-slate-800';
        secretSpan.textContent = cred.secret ? '••••••••' : '—';
        secretSpan.title = 'Click to reveal';
        let revealed = false;
        secretSpan.onclick = () => {
          revealed = !revealed;
          secretSpan.textContent = revealed
            ? (cred.crackedValue ? `${cred.crackedValue} (cracked)` : cred.secret || '—')
            : '••••••••';
        };
        chip.appendChild(typeBadge);
        chip.appendChild(secretSpan);
        if (cred.notes) {
          const notes = document.createElement('span');
          notes.className = 'text-slate-400 ml-auto truncate max-w-[120px]';
          notes.textContent = cred.notes;
          chip.appendChild(notes);
        }
        credList.appendChild(chip);
      }
      credSection.appendChild(credList);
      sections.appendChild(credSection);
    }

    // Admin on
    sections.appendChild(makeHostSection(
      `Admin on (${adminHostIds.length})`,
      adminHostIds,
      hostMap,
      'bg-amber-50 border-amber-200 text-amber-700',
      engagementId, data, snapshots, onBack
    ));

    // Sessions on
    sections.appendChild(makeHostSection(
      `Sessions on (${sessionHostIds.length})`,
      sessionHostIds,
      hostMap,
      'bg-cyan-50 border-cyan-200 text-cyan-700',
      engagementId, data, snapshots, onBack
    ));

    // Snapshot mentions
    const mentionHostIds = Object.keys(mentionByHost);
    sections.appendChild(makeMentionsSection(
      `Appears in snapshots (${mentionHostIds.length} host${mentionHostIds.length !== 1 ? 's' : ''})`,
      mentionByHost,
      hostMap,
      onBack,
      engagementId,
      data,
      snapshots
    ));

    container.appendChild(sections);
  }
}

function makeHostSection(title, hostIds, hostMap, colorClasses, engagementId, data, snapshots, onBack) {
  const section = document.createElement('div');

  const heading = document.createElement('h3');
  heading.className = 'text-sm font-semibold text-slate-600 mb-2';
  heading.textContent = title;
  section.appendChild(heading);

  if (hostIds.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'text-xs text-slate-400';
    empty.textContent = 'None recorded.';
    section.appendChild(empty);
    return section;
  }

  const list = document.createElement('div');
  list.className = 'flex flex-wrap gap-2';

  for (const hostId of hostIds) {
    const host = hostMap[hostId];
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = `text-xs px-3 py-1.5 rounded-lg border font-mono ${colorClasses} hover:opacity-80 transition-opacity`;
    chip.textContent = host?.label || host?.ip || hostId;
    chip.onclick = () => {
      import('./renderHost.js').then(m =>
        m.renderHost(engagementId, hostId, data, snapshots, onBack)
      );
    };
    list.appendChild(chip);
  }

  section.appendChild(list);
  return section;
}

function makeMentionsSection(title, mentionByHost, hostMap, onBack, engagementId, data, snapshots) {
  const section = document.createElement('div');

  const heading = document.createElement('h3');
  heading.className = 'text-sm font-semibold text-slate-600 mb-2';
  heading.textContent = title;
  section.appendChild(heading);

  const hostIds = Object.keys(mentionByHost);
  if (hostIds.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'text-xs text-slate-400';
    empty.textContent = 'No snapshots mention this username.';
    section.appendChild(empty);
    return section;
  }

  const list = document.createElement('div');
  list.className = 'space-y-3';

  for (const hostId of hostIds) {
    const host = hostMap[hostId];
    const snaps = mentionByHost[hostId];

    const row = document.createElement('div');
    row.className = 'bg-white border border-slate-100 rounded-xl p-3';

    const hostBtn = document.createElement('button');
    hostBtn.type = 'button';
    hostBtn.className = 'text-sm font-medium text-indigo-600 hover:underline font-mono mb-2 block';
    hostBtn.textContent = host?.label || host?.ip || hostId;
    hostBtn.onclick = () =>
      import('./renderHost.js').then(m => m.renderHost(engagementId, hostId, data, snapshots, onBack));

    row.appendChild(hostBtn);

    const badges = document.createElement('div');
    badges.className = 'flex flex-wrap gap-1';
    for (const snap of snaps) {
      const badge = document.createElement('span');
      badge.className = 'text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded font-mono';
      badge.textContent = snap.commandType;
      badges.appendChild(badge);
    }
    row.appendChild(badges);
    list.appendChild(row);
  }

  section.appendChild(list);
  return section;
}
