// Navigation state — shared between app.js and components to avoid circular deps

export let currentEngagementId = null;
let _navigateFn = null;

export function setNavigate(fn) { _navigateFn = fn; }

export function setCurrentEngagement(id) { currentEngagementId = id; }

export function navigateTo(engagementId) {
  if (_navigateFn) _navigateFn(engagementId);
}
