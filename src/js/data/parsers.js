// ── OS detection ──────────────────────────────────────────

export function detectOS(raw) {
  const text = raw.toLowerCase();
  // Strong Windows signals
  if (/tcp\s+\d+\.\d+\.\d+\.\d+:\d+.*\s+(established|listening|time_wait|close_wait)/i.test(raw) &&
      /\s+\d+\s*$/m.test(raw)) return 'windows'; // netstat with PID column
  if (/image name/i.test(raw) && /pid/i.test(raw) && /mem usage/i.test(raw)) return 'windows'; // tasklist
  if (/windows ip configuration/i.test(raw)) return 'windows'; // ipconfig
  if (/ethernet adapter|wireless lan adapter/i.test(raw)) return 'windows';
  // Strong Linux signals
  if (/linux/i.test(raw)) return 'linux';
  if (/^[a-z0-9_-]+\s+\d+\s+\w+\s+\w+\s+[\d,]+\s+\w+\s+\?/m.test(raw)) return 'linux'; // ps aux
  if (/inet\s+\d+\.\d+\.\d+\.\d+/i.test(raw) && /netmask/i.test(raw)) return 'linux'; // ifconfig
  if (text.includes('gnu/linux') || text.includes('ubuntu') || text.includes('debian') ||
      text.includes('centos') || text.includes('rhel') || text.includes('fedora') ||
      text.includes('kali')) return 'linux';
  return 'unknown';
}

export function detectCommand(raw) {
  const text = raw.toLowerCase();
  // netstat patterns
  if (/active connections|active internet|proto\s+local address/i.test(raw)) return 'netstat';
  if (/tcp\s+\d+\.\d+\.\d+\.\d+.*\d+\.\d+\.\d+\.\d+/i.test(raw)) return 'netstat';
  // process list
  if (/image name.*pid.*session/i.test(raw)) return 'pslist'; // tasklist
  if (/pid\s+ppid|command\s+pid|%cpu.*%mem/i.test(raw)) return 'pslist'; // ps
  if (/^\s*pid\s+/im.test(raw) && /cmd|command/i.test(raw)) return 'pslist';
  // ipconfig / ifconfig
  if (/windows ip configuration/i.test(raw)) return 'ipconfig';
  if (/ethernet adapter|wireless lan adapter/i.test(raw)) return 'ipconfig';
  if (/inet\s+\d+\.\d+\.\d+\.\d+/i.test(raw) && /netmask|broadcast/i.test(raw)) return 'ipconfig';
  // uname
  if (/^(linux|darwin|freebsd|windows)\s+\S+\s+\S+/im.test(raw.trim())) return 'uname';
  if (/uname/i.test(raw) || raw.trim().split(/\s+/).length < 10 && /kernel/i.test(raw)) return 'uname';
  // arp
  if (/internet address.*physical address/i.test(raw)) return 'arp'; // windows
  if (/\(\d+\.\d+\.\d+\.\d+\)\s+at\s+[0-9a-f:]+/i.test(raw)) return 'arp'; // linux
  if (/address\s+hwtype\s+hwaddress/i.test(raw)) return 'arp';
  return 'unknown';
}

// ── Helpers ───────────────────────────────────────────────

function extractPort(addr) {
  const m = addr.match(/:(\d+)$/);
  return m ? parseInt(m[1], 10) : null;
}

function nullIfEmpty(val) {
  return (val === '' || val === undefined) ? null : val;
}

// ── Netstat ───────────────────────────────────────────────
// Schema: { connections: [{ proto, localAddr, localPort, remoteAddr, remotePort, state, pid }] }

export function parseNetstat(raw, osFamily) {
  const connections = [];
  const lines = raw.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || /^(active|proto|tcp|udp)/i.test(trimmed) === false) continue;

    // Windows: TCP    0.0.0.0:135    0.0.0.0:0    LISTENING    1234
    const winMatch = trimmed.match(
      /^(tcp|udp)v?[46]?\s+([\d.:*]+)\s+([\d.:*]+)\s+(\w+)(?:\s+(\d+))?/i
    );
    if (winMatch) {
      const localAddr  = winMatch[2];
      const remoteAddr = winMatch[3];
      connections.push({
        proto:      winMatch[1].toUpperCase(),
        localAddr,
        localPort:  extractPort(localAddr),
        remoteAddr,
        remotePort: extractPort(remoteAddr),
        state:      winMatch[4].toUpperCase(),
        pid:        nullIfEmpty(winMatch[5]),
      });
      continue;
    }

    // Linux: tcp  0  0  0.0.0.0:22  0.0.0.0:*  LISTEN  1234/sshd
    const linMatch = trimmed.match(
      /^(tcp|udp)6?\s+\d+\s+\d+\s+([\d.:*]+)\s+([\d.:*]+)\s+(\w+)(?:\s+(-|\d+\/\S+))?/i
    );
    if (linMatch) {
      const localAddr  = linMatch[2];
      const remoteAddr = linMatch[3];
      const pidRaw     = linMatch[5];
      connections.push({
        proto:      linMatch[1].toUpperCase(),
        localAddr,
        localPort:  extractPort(localAddr),
        remoteAddr,
        remotePort: extractPort(remoteAddr),
        state:      linMatch[4].toUpperCase(),
        pid:        (pidRaw && pidRaw !== '-') ? pidRaw.split('/')[0] : null,
      });
    }
  }

  return { connections };
}

// ── Process list ─────────────────────────────────────────
// Schema: { processes: [{ name, pid, ppid, user, cmd }] }

export function parsePslist(raw, osFamily) {
  const processes = [];
  const lines = raw.split('\n').map(l => l.trim()).filter(Boolean);

  // Windows tasklist: Image Name, PID, Session Name, Session#, Mem Usage
  if (/image name/i.test(raw)) {
    for (const line of lines) {
      const match = line.match(/^(.+?)\s{2,}(\d+)\s{2,}(\S+)\s{2,}(\d+)\s{2,}([\d,]+ K)/i);
      if (match) {
        processes.push({
          name: match[1].trim(),
          pid:  match[2],
          ppid: null,
          user: null,
          cmd:  null,
        });
      }
    }
    return { processes };
  }

  // Simple "name pid ppid" format (e.g. Volatility pslist, custom output)
  if (/^\S+\s+\d+\s+\d+$/m.test(raw) && !/USER|%CPU/i.test(raw)) {
    for (const line of lines) {
      const m = line.match(/^(\S+)\s+(\d+)\s+(\d+)$/);
      if (m) {
        processes.push({ name: m[1], pid: m[2], ppid: m[3], user: null, cmd: null });
      }
    }
    if (processes.length) return { processes };
  }

  // Linux ps -ef: UID PID PPID C STIME TTY TIME CMD
  if (/uid\s+pid\s+ppid/i.test(raw) || (lines[0] && /^\S+\s+\d+\s+\d+\s+\d+/.test(lines[1] || ''))) {
    let headerSkipped = false;
    for (const line of lines) {
      if (!headerSkipped) { headerSkipped = true; continue; }
      const parts = line.split(/\s+/);
      if (parts.length < 8) continue;
      const user = parts[0], pid = parts[1], ppid = parts[2];
      const cmd  = parts.slice(7).join(' ');
      if (/^\d+$/.test(pid)) {
        processes.push({ name: cmd.split('/').pop().split(' ')[0], pid, ppid, user, cmd: nullIfEmpty(cmd) });
      }
    }
    if (processes.length) return { processes };
  }

  // Linux ps aux: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
  let headerSkipped = false;
  for (const line of lines) {
    if (!headerSkipped) { headerSkipped = true; continue; }
    const parts = line.split(/\s+/);
    if (parts.length < 11) continue;
    const user = parts[0], pid = parts[1];
    const cmd  = parts.slice(10).join(' ');
    if (/^\d+$/.test(pid)) {
      processes.push({ name: cmd.split('/').pop().split(' ')[0], pid, ppid: null, user, cmd: nullIfEmpty(cmd) });
    }
  }

  return { processes };
}

// ── ipconfig / ifconfig ───────────────────────────────────
// Schema: { interfaces: [{ name, addresses: [{ ip, mask, gateway, broadcast, family }] }] }

export function parseIpconfig(raw, osFamily) {
  const interfaces = [];

  // Simple "Host Name / IPv4 Address / Subnet Mask / Default Gateway" format
  if (/host name/i.test(raw) && /ipv4 address/i.test(raw) && !/ethernet adapter/i.test(raw)) {
    const ip  = raw.match(/ipv4 address[^:]*:\s*([\d.]+)/i);
    const mask = raw.match(/subnet mask[^:]*:\s*([\d.]+)/i);
    const gw   = raw.match(/default gateway[^:]*:\s*([\d.]+)/i);
    if (ip) {
      interfaces.push({
        name: 'Ethernet',
        addresses: [{ ip: ip[1], mask: mask?.[1] ?? null, gateway: gw?.[1] ?? null, broadcast: null, family: 'IPv4' }],
      });
    }
    return { interfaces };
  }

  if (/windows ip configuration/i.test(raw) || /ethernet adapter/i.test(raw)) {
    // Windows ipconfig /all
    const blocks = raw.split(/\n\n+/);
    for (const block of blocks) {
      const nameMatch = block.match(/^(.+?adapter.+?):/im);
      if (!nameMatch) continue;
      const iface = { name: nameMatch[1].trim(), addresses: [] };
      const ipv4  = block.match(/ipv4 address[^:]*:\s*([\d.]+)/i);
      const mask  = block.match(/subnet mask[^:]*:\s*([\d.]+)/i);
      const gw    = block.match(/default gateway[^:]*:\s*([\d.]+)/i);
      if (ipv4) iface.addresses.push({ ip: ipv4[1], mask: mask?.[1] ?? null, gateway: gw?.[1] ?? null, broadcast: null, family: 'IPv4' });
      const ipv6 = block.match(/ipv6 address[^:]*:\s*([\da-f:]+)/i);
      if (ipv6) iface.addresses.push({ ip: ipv6[1], mask: null, gateway: null, broadcast: null, family: 'IPv6' });
      if (iface.addresses.length) interfaces.push(iface);
    }
  } else {
    // Linux ifconfig
    const blocks = raw.split(/\n(?=\S)/);
    for (const block of blocks) {
      const nameMatch = block.match(/^(\S+)/);
      if (!nameMatch) continue;
      const iface = { name: nameMatch[1], addresses: [] };
      const ipv4      = block.match(/inet\s+([\d.]+).*?netmask\s+([\d.]+)/i);
      const broadcast = block.match(/broadcast\s+([\d.]+)/i);
      if (ipv4) iface.addresses.push({ ip: ipv4[1], mask: ipv4[2], gateway: null, broadcast: broadcast?.[1] ?? null, family: 'IPv4' });
      const ipv6 = block.match(/inet6\s+([\da-f:]+)/i);
      if (ipv6) iface.addresses.push({ ip: ipv6[1], mask: null, gateway: null, broadcast: null, family: 'IPv6' });
      if (iface.addresses.length) interfaces.push(iface);
    }
  }

  return { interfaces };
}

// ── uname ─────────────────────────────────────────────────
// Schema: { raw, os, node, kernel, arch }

export function parseUname(raw) {
  const line = raw.trim().split('\n')[0];
  const parts = line.split(/\s+/);
  return {
    raw:    line,
    os:     nullIfEmpty(parts[0]),
    node:   nullIfEmpty(parts[1]),
    kernel: nullIfEmpty(parts[2]),
    arch:   nullIfEmpty(parts[parts.length - 1]),
  };
}

// ── ARP ───────────────────────────────────────────────────
// Schema: { entries: [{ ip, mac, type, iface }] }

export function parseArp(raw) {
  const entries = [];

  // Windows: Internet Address  Physical Address  Type
  if (/internet address/i.test(raw)) {
    for (const line of raw.split('\n')) {
      const match = line.trim().match(/([\d.]+)\s+([0-9a-f-]+)\s+(\w+)/i);
      if (match) entries.push({ ip: match[1], mac: match[2].replace(/-/g, ':'), type: match[3], iface: null });
    }
  } else {
    // Linux: host (ip) at mac [ether] on iface
    for (const line of raw.split('\n')) {
      const match1 = line.match(/\(([\d.]+)\)\s+at\s+([0-9a-f:]+)(?:.*\bon\s+(\S+))?/i);
      if (match1) { entries.push({ ip: match1[1], mac: match1[2], type: null, iface: match1[3] ?? null }); continue; }
      // arp -n table format: ADDRESS HW_TYPE HW_ADDR FLAGS IFACE
      const match2 = line.trim().match(/^([\d.]+)\s+\S+\s+([0-9a-f:]+)\s+\S+\s+(\S+)/i);
      if (match2 && match2[2] !== '00:00:00:00:00:00') {
        entries.push({ ip: match2[1], mac: match2[2], type: null, iface: match2[3] });
      }
    }
  }

  return { entries };
}

// ── Diff helpers ──────────────────────────────────────────

export function diffSnapshots(prev, curr) {
  if (!prev || prev.commandType !== curr.commandType) return null;

  const type = curr.commandType;

  if (type === 'netstat') {
    const key  = c => `${c.proto}|${c.localAddr}|${c.remoteAddr}|${c.state}`;
    const prevSet = new Set((prev.parsed?.connections || []).map(key));
    const currSet = new Set((curr.parsed?.connections || []).map(key));
    return {
      added:   (curr.parsed?.connections || []).filter(c => !prevSet.has(key(c))),
      removed: (prev.parsed?.connections || []).filter(c => !currSet.has(key(c))),
    };
  }

  if (type === 'pslist') {
    const prevNames = new Set((prev.parsed?.processes || []).map(p => p.name));
    const currNames = new Set((curr.parsed?.processes || []).map(p => p.name));
    return {
      added:   (curr.parsed?.processes || []).filter(p => !prevNames.has(p.name)),
      removed: (prev.parsed?.processes || []).filter(p => !currNames.has(p.name)),
    };
  }

  if (type === 'arp') {
    const key  = e => `${e.ip}|${e.mac}`;
    const prevSet = new Set((prev.parsed?.entries || []).map(key));
    const currSet = new Set((curr.parsed?.entries || []).map(key));
    return {
      added:   (curr.parsed?.entries || []).filter(e => !prevSet.has(key(e))),
      removed: (prev.parsed?.entries || []).filter(e => !currSet.has(key(e))),
    };
  }

  if (type === 'ipconfig') {
    const prevIPs = new Set((prev.parsed?.interfaces || []).flatMap(i => i.addresses.map(a => a.ip)));
    const currIPs = new Set((curr.parsed?.interfaces || []).flatMap(i => i.addresses.map(a => a.ip)));
    return {
      added:   [...currIPs].filter(ip => !prevIPs.has(ip)),
      removed: [...prevIPs].filter(ip => !currIPs.has(ip)),
    };
  }

  return null;
}
