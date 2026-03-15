// Default: cloud adapter. In local builds, vite.config.js aliases this
// file to adapters/local.js so Amplify is never bundled.
export { apiGet, apiPost } from './adapters/cloud.js';
