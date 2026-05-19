import './feedback.js';
import { isAuthenticated, startLogin, logout, parseIdToken } from './auth.js';
import { DEBUG_MODE } from './config.js';
import { loadEngagements } from './data/index.js';
import { renderSidebar } from './components/renderEngagements.js';
import { renderEngagement } from './components/renderEngagement.js';
import { setNavigate, setCurrentEngagement } from './nav.js';

const PORTAL_URL     = 'https://jaetill.com';
const REQUIRED_GROUP = 'carto-users';

async function navigate(engagementId) {
  setCurrentEngagement(engagementId);
  renderSidebar();
  if (engagementId) {
    await renderEngagement(engagementId);
  } else {
    showWelcome();
  }
}

function showWelcome() {
  const el = document.getElementById('app-content');
  el.innerHTML = '<p class="text-slate-400 text-sm text-center py-24">Select an engagement from the sidebar.</p>';
}

document.getElementById('sign-out-btn').addEventListener('click', () => logout());

document.getElementById('new-eng-btn').addEventListener('click', () => {
  import('./components/renderEngagements.js').then(m => m.showNewEngagementForm());
});

async function init() {
  // Auth gate
  if (!isAuthenticated()) {
    return startLogin();
  }

  // Authz gate: must be in carto-users group
  const claims = parseIdToken() || {};
  const groups = Array.isArray(claims['cognito:groups']) ? claims['cognito:groups'] : [];
  if (!groups.includes(REQUIRED_GROUP)) {
    window.location.replace(PORTAL_URL);
    return;
  }

  setNavigate(navigate);

  try {
    await loadEngagements();
  } catch (err) {
    console.warn('[App] Could not load engagements:', err);
  }

  if (DEBUG_MODE) {
    const badge = document.getElementById('debug-badge');
    badge.innerHTML = '<span class="text-xs text-amber-400 font-mono">DEBUG</span>';
  }

  renderSidebar();
  showWelcome();
}

window.addEventListener('DOMContentLoaded', init);
