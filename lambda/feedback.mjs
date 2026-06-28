// Lambda: POST /feedback — user feedback widget endpoint (Standard 11 / ADR-0012).
// ESM variant for carto (lambda/package.json has "type": "module").

import { Sentry } from './lib/sentry.mjs';
import logger from './lib/logger.mjs';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

const REGION = process.env.AWS_REGION || 'us-east-2';
const REPO_OWNER = process.env.GITHUB_REPO_OWNER || 'jaetill';
const REPO_NAME = process.env.GITHUB_REPO_NAME || 'carto';
const SECRET_ID = process.env.GITHUB_SECRET_ID || 'carto/github-token';

const ALLOWED_ORIGINS = new Set(['https://carto.jaetill.com', 'http://localhost:5173']);

const SAFE_PAGE_ENTRIES = [{ origin: 'https://carto.jaetill.com', pathPrefix: '' }];

function isSafePageUrl(url) {
  if (typeof url !== 'string') return false;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  return SAFE_PAGE_ENTRIES.some((e) => parsed.origin === e.origin);
}

const WINDOW_MS = 60 * 60 * 1000;
const LIMIT = 10;

function makeRateLimiter() {
  const buckets = new Map();
  return function checkRateLimit(ip) {
    const now = Date.now();
    const existing = buckets.get(ip);
    if (!existing || now - existing.windowStart >= WINDOW_MS) {
      if (buckets.size >= 10_000) {
        for (const [k, e] of buckets.entries()) {
          if (now - e.windowStart >= WINDOW_MS) buckets.delete(k);
        }
      }
      buckets.set(ip, { count: 1, windowStart: now });
      return { allowed: true };
    }
    if (existing.count >= LIMIT) {
      return {
        allowed: false,
        retryAfter: Math.ceil((WINDOW_MS - (now - existing.windowStart)) / 1000),
      };
    }
    existing.count += 1;
    return { allowed: true };
  };
}

function escapeMarkdown(str) {
  return str.replace(/[\\*_#[\]`<>!]/g, '\\$&');
}

const ALLOWED_TYPES = new Set(['bug', 'feature', 'other']);

function validate(input) {
  if (!input || typeof input !== 'object') return 'body must be an object';
  if (!ALLOWED_TYPES.has(input.type)) return 'type must be one of: bug, feature, other';
  if (typeof input.description !== 'string') return 'description must be a string';
  if (input.description.length < 10 || input.description.length > 2000) {
    return 'description must be 10-2000 characters';
  }
  if (
    input.email !== undefined &&
    (typeof input.email !== 'string' || !input.email.includes('@'))
  ) {
    return 'email must be a valid email address';
  }
  return null;
}

function corsHeaders(event) {
  const origin = event.headers?.origin || event.headers?.Origin || '';
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGINS.has(origin)
      ? origin
      : 'https://carto.jaetill.com',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
    'Content-Type': 'application/json',
  };
}

function respond(status, body, headers) {
  return { statusCode: status, headers, body: JSON.stringify(body) };
}

const smClient = new SecretsManagerClient({ region: REGION });
const checkRateLimit = makeRateLimiter();

let _secrets;
async function getSecrets() {
  if (!_secrets) {
    const res = await smClient.send(new GetSecretValueCommand({ SecretId: SECRET_ID }));
    _secrets = JSON.parse(res.SecretString);
  }
  return _secrets;
}

let _octokit;
async function getOctokit() {
  if (!_octokit) {
    const { Octokit } = await import('@octokit/rest');
    const { GITHUB_TOKEN } = await getSecrets();
    if (!GITHUB_TOKEN) throw new Error('GITHUB_TOKEN missing from Secrets Manager value');
    _octokit = new Octokit({ auth: GITHUB_TOKEN });
  }
  return _octokit;
}

export async function handler(event, context) {
  logger.info('handler.invoked', { request_id: context?.awsRequestId });

  const CORS = corsHeaders(event);
  const method = event.httpMethod;

  if (method === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' };
  if (method !== 'POST') return respond(405, { error: 'method_not_allowed' }, CORS);

  const ip = event.requestContext?.identity?.sourceIp || 'unknown';
  const rl = checkRateLimit(ip);
  if (!rl.allowed) {
    return respond(
      429,
      { error: 'rate_limited', retry_after_seconds: rl.retryAfter },
      { ...CORS, 'Retry-After': String(rl.retryAfter) },
    );
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return respond(400, { error: 'invalid_json' }, CORS);
  }

  if (typeof body.website === 'string' && body.website.length > 0) {
    return respond(201, { id: `FB-DROPPED-${Date.now()}`, status: 'received' }, CORS);
  }

  const violation = validate(body);
  if (violation) return respond(400, { error: 'validation_error', detail: violation }, CORS);

  const titleBody =
    body.description.length > 60 ? body.description.slice(0, 60).trim() + '...' : body.description;
  const issueTitle = `[${body.type}] ${escapeMarkdown(titleBody)}`;
  const issueBody = [
    '## Description',
    escapeMarkdown(body.description),
    '',
    '## Context',
    body.page_url && isSafePageUrl(body.page_url)
      ? `- Page: ${escapeMarkdown(body.page_url)}`
      : null,
    body.user_agent ? `- UA: ${escapeMarkdown(body.user_agent)}` : null,
    body.email ? `- Email: ${escapeMarkdown(body.email)}` : null,
    `- Source IP: ${ip}`,
    `- Lambda request: ${context?.awsRequestId || 'unknown'}`,
  ]
    .filter(Boolean)
    .join('\n');

  let octokit;
  try {
    octokit = await getOctokit();
  } catch (err) {
    logger.error('feedback.secrets_failed', { error: err.message });
    Sentry.captureException(err);
    return respond(500, { error: 'configuration_error' }, CORS);
  }

  try {
    const result = await octokit.rest.issues.create({
      owner: REPO_OWNER,
      repo: REPO_NAME,
      title: issueTitle,
      body: issueBody,
      labels: ['feedback:user-submitted', `type:${body.type}`],
    });
    const id = `FB-${new Date().getFullYear()}-${String(result.data.number).padStart(6, '0')}`;
    logger.info('feedback.received', { id, type: body.type, issue_number: result.data.number });
    return respond(201, { id, status: 'received' }, CORS);
  } catch (err) {
    logger.error('feedback.github_failed', { error: err.message, status: err.status });
    Sentry.captureException(err);
    return respond(502, { error: 'github_issue_creation_failed' }, CORS);
  }
}
