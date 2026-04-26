import { getIdToken } from '../../auth.js';

const API_URL = 'https://9o7c3668a4.execute-api.us-east-2.amazonaws.com/prod';

export async function apiGet(path) {
  const token = getIdToken();
  const res = await fetch(`${API_URL}${path}`, {
    headers: { Authorization: token },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Fetch failed: ${res.status}`);
  return res.json();
}

export async function apiPost(path, body) {
  const token = getIdToken();
  const res = await fetch(`${API_URL}${path}`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', Authorization: token },
    body:    JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Request failed: ${res.status}`);
  }
  return res.json();
}
