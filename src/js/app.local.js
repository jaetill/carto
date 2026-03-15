import { loadEngagements } from './data/index.js';
import { renderSidebar } from './components/renderEngagements.js';
import { renderEngagement } from './components/renderEngagement.js';
import { setNavigate, setCurrentEngagement } from './nav.js';

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

document.getElementById('new-eng-btn').addEventListener('click', () => {
  import('./components/renderEngagements.js').then(m => m.showNewEngagementForm());
});

async function init() {
  setNavigate(navigate);

  try {
    await loadEngagements();
  } catch (err) {
    console.warn('[App] Could not load engagements:', err);
  }

  renderSidebar();
  showWelcome();
}

window.addEventListener('DOMContentLoaded', init);
