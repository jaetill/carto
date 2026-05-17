// Sentry init shared across carto Lambdas per platform ADR-0009.
//
// Usage:
//   import { Sentry } from './lib/sentry.mjs';
//   export const handler = Sentry.wrapHandler(async (event, context) => {
//     // existing handler logic
//   });
//
// Set SENTRY_DSN, DEPLOY_ENV, RELEASE_VERSION env vars on the Lambda.
// When SENTRY_DSN is empty Sentry.init is a no-op and wrapHandler passes through.

import * as Sentry from '@sentry/aws-serverless';

const EMAIL_RE = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g;
const JWT_RE = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

function scrubString(s) {
  if (typeof s !== 'string') return s;
  return s.replace(EMAIL_RE, '[REDACTED_EMAIL]').replace(JWT_RE, '[REDACTED_JWT]');
}

function scrubObject(obj, depth = 0) {
  if (depth > 4 || obj === null || typeof obj !== 'object') return;
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string') obj[k] = scrubString(v);
    else if (typeof v === 'object') scrubObject(v, depth + 1);
  }
}

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.DEPLOY_ENV || 'production',
  release: process.env.RELEASE_VERSION || 'unknown',
  tracesSampleRate: 0.1,

  // PII scrubbing per ADR-0006. Default integrations include consoleIntegration
  // which captures every console.log as a breadcrumb on subsequent captureException.
  // Without scrubbing here, PII in upstream error strings can land in Sentry.
  beforeSend(event) {
    if (event.user) {
      delete event.user.email;
      delete event.user.username;
      delete event.user.ip_address;
    }
    if (event.breadcrumbs) {
      for (const bc of event.breadcrumbs) {
        if (bc.message) bc.message = scrubString(bc.message);
        if (bc.data) scrubObject(bc.data);
      }
    }
    if (event.exception?.values) {
      for (const ex of event.exception.values) {
        if (ex.value) ex.value = scrubString(ex.value);
      }
    }
    if (event.extra) scrubObject(event.extra);
    return event;
  },

  beforeBreadcrumb(breadcrumb) {
    if (breadcrumb.message) breadcrumb.message = scrubString(breadcrumb.message);
    if (breadcrumb.data) scrubObject(breadcrumb.data);
    return breadcrumb;
  },
});

export { Sentry };