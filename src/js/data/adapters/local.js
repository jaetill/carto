// Local storage adapter — mirrors the cloud adapter's interface.
// Data is persisted in localStorage under 'carto:' prefixed keys.
//
// Path → key mapping:
//   /engagements                    → carto:engagements
//   /engagement/:id/data            → carto:data:id
//   /engagement/:id/snapshots       → carto:snapshots:id
//   /engagement/:id/imports         → carto:imports:id

function pathToKey(path) {
  if (path === '/engagements') return 'carto:engagements';
  const m = path.match(/^\/engagement\/([^/]+)\/(\w+)$/);
  if (m) return `carto:${m[2]}:${m[1]}`;
  throw new Error(`[local adapter] Unknown path: ${path}`);
}

export function apiGet(path) {
  const raw = localStorage.getItem(pathToKey(path));
  return Promise.resolve(raw ? JSON.parse(raw) : null);
}

export function apiPost(path, body) {
  localStorage.setItem(pathToKey(path), JSON.stringify(body));
  return Promise.resolve({});
}
