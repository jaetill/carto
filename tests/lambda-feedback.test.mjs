// Unit tests for lambda/feedback.mjs — checkRateLimit (in-memory rate limiter).
//
// PR #64 (DynamoDB variant) was closed; the current implementation uses makeRateLimiter()
// — an in-memory fixed-window counter. These tests exercise its three observable
// behaviours: allow, block (429 + Retry-After), and per-IP isolation.
//
// Strategy: each test calls vi.resetModules() + dynamic re-import so every test
// starts with a fresh makeRateLimiter() instance (module-level state).
// The honeypot field (body.website) short-circuits the handler before it reaches
// Octokit or Secrets Manager, so those callers need no mocks.

import { vi, describe, it, expect, beforeEach } from 'vitest';

vi.mock('../lambda/lib/sentry.mjs', () => ({
  Sentry: { wrapHandler: (fn) => fn, captureException: vi.fn() },
}));

// SecretsManagerClient is constructed at module level; mock the constructor so
// the import doesn't reach AWS even though send() is never called in these tests.
vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: vi.fn(() => ({ send: vi.fn() })),
  GetSecretValueCommand: vi.fn(),
}));

const LIMIT = 10; // mirrors the constant in lambda/feedback.mjs

function makeEvent(ip = '1.2.3.4') {
  return {
    httpMethod: 'POST',
    headers: { origin: 'https://carto.jaetill.com', 'Content-Type': 'application/json' },
    // Honeypot field causes the handler to return 201 early, before getOctokit() is called.
    body: JSON.stringify({ website: 'trap' }),
    requestContext: { identity: { sourceIp: ip } },
  };
}

const ctx = { awsRequestId: 'test-id' };

describe('lambda/feedback.mjs — checkRateLimit (in-memory rate limiter)', () => {
  let handler;

  beforeEach(async () => {
    vi.resetModules();
    ({ handler } = await import('../lambda/feedback.mjs'));
  });

  it('allow path: first request from an IP is not rate limited', async () => {
    const res = await handler(makeEvent('10.0.0.1'), ctx);
    expect(res.statusCode).not.toBe(429);
  });

  it('allow path: all LIMIT (10) requests within the same window are allowed', async () => {
    for (let i = 0; i < LIMIT; i++) {
      const res = await handler(makeEvent('10.0.0.2'), ctx);
      expect(res.statusCode).not.toBe(429);
    }
  });

  it('block path: (LIMIT+1)-th request returns 429 with rate_limited error', async () => {
    for (let i = 0; i < LIMIT; i++) {
      await handler(makeEvent('10.0.0.3'), ctx);
    }
    const blocked = await handler(makeEvent('10.0.0.3'), ctx);
    expect(blocked.statusCode).toBe(429);
    const body = JSON.parse(blocked.body);
    expect(body.error).toBe('rate_limited');
    expect(typeof body.retry_after_seconds).toBe('number');
    expect(body.retry_after_seconds).toBeGreaterThan(0);
  });

  it('block path: Retry-After response header is set when rate limited', async () => {
    for (let i = 0; i < LIMIT; i++) {
      await handler(makeEvent('10.0.0.4'), ctx);
    }
    const blocked = await handler(makeEvent('10.0.0.4'), ctx);
    expect(blocked.headers['Retry-After']).toBeDefined();
    expect(Number(blocked.headers['Retry-After'])).toBeGreaterThan(0);
  });

  it('boundary: LIMIT-th (10th) request is still allowed; (LIMIT+1)-th is blocked', async () => {
    for (let i = 0; i < LIMIT - 1; i++) {
      await handler(makeEvent('10.0.0.5'), ctx);
    }
    const tenth = await handler(makeEvent('10.0.0.5'), ctx);
    expect(tenth.statusCode).not.toBe(429);

    const eleventh = await handler(makeEvent('10.0.0.5'), ctx);
    expect(eleventh.statusCode).toBe(429);
  });

  it('per-IP: a blocked IP does not affect requests from a different IP', async () => {
    for (let i = 0; i < LIMIT; i++) {
      await handler(makeEvent('10.0.0.6'), ctx);
    }
    const blockedA = await handler(makeEvent('10.0.0.6'), ctx);
    expect(blockedA.statusCode).toBe(429);

    const allowedB = await handler(makeEvent('10.0.0.7'), ctx);
    expect(allowedB.statusCode).not.toBe(429);
  });
});
