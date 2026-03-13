import { Amplify, Auth } from 'aws-amplify';
import amplifyConfig from './config.js';
import { loadEngagements } from './data/index.js';
import { renderEngagements } from './components/renderEngagements.js';

Amplify.configure(amplifyConfig);

document.getElementById('sign-out-btn').addEventListener('click', async () => {
  await Auth.signOut();
  window.location.href = 'login.html';
});

async function init() {
  try {
    await Auth.currentAuthenticatedUser();
  } catch {
    window.location.href = 'login.html';
    return;
  }

  try {
    await loadEngagements();
  } catch (err) {
    console.warn('[App] Could not load engagements:', err);
  }

  renderEngagements();
}

window.addEventListener('DOMContentLoaded', init);
