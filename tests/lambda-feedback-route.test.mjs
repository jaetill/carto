import { vi, describe, it, expect, beforeEach } from 'vitest';

vi.mock('../lambda/feedback.mjs', () => ({
  handler: vi.fn().mockResolvedValue({
    statusCode: 201,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: 'FB-2026-000001', status: 'received' }),
  }),
}));

vi.mock('../lambda/lib/sentry.mjs', () => ({
  Sentry: { wrapHandler: vi.fn((fn) => fn) },
}));

vi.mock('../lambda/s3.mjs', () => ({ s3Get: vi.fn(), s3Put: vi.fn() }));
vi.mock('../lambda/graph.mjs', () => ({
  getTopology: vi.fn(),
  getAttackPaths: vi.fn(),
  addAttackPath: vi.fn(),
  removeAttackPath: vi.fn(),
}));
vi.mock('../lambda/sync.mjs', () => ({
  afterDataSave: vi.fn(),
  afterSnapshotSave: vi.fn(),
  afterImportSave: vi.fn(),
  syncEngagementFull: vi.fn(),
}));

describe('lambda/index.mjs — feedback routing', () => {
  let handler;
  let feedbackHandler;
  let wrapHandler;

  beforeEach(async () => {
    vi.resetModules();
    const sentryMod = await import('../lambda/lib/sentry.mjs');
    wrapHandler = sentryMod.Sentry.wrapHandler;
    wrapHandler.mockClear();
    const indexMod = await import('../lambda/index.mjs');
    const feedbackMod = await import('../lambda/feedback.mjs');
    handler = indexMod.handler;
    feedbackHandler = feedbackMod.handler;
  });

  it('routes POST /feedback to feedbackHandler without requiring carto-users group', async () => {
    const event = {
      httpMethod: 'POST',
      path: '/feedback',
      headers: { origin: 'https://carto.jaetill.com' },
      body: JSON.stringify({ type: 'bug', description: 'Something broke on the graph page' }),
      requestContext: { authorizer: { claims: {} } },
    };
    const context = { awsRequestId: 'test-request-id' };

    const result = await handler(event, context);

    expect(result.statusCode).toBe(201);
    expect(feedbackHandler).toHaveBeenCalledWith(event, context);
  });

  it('routes OPTIONS /feedback to feedbackHandler without requiring carto-users group', async () => {
    const event = {
      httpMethod: 'OPTIONS',
      path: '/feedback',
      headers: { origin: 'https://carto.jaetill.com' },
      body: null,
      requestContext: { authorizer: { claims: {} } },
    };

    const result = await handler(event, {});

    expect(result.statusCode).toBe(201);
    expect(feedbackHandler).toHaveBeenCalled();
  });

  it('returns 403 for other routes when not in carto-users group', async () => {
    const event = {
      httpMethod: 'GET',
      path: '/engagements',
      headers: {},
      body: null,
      requestContext: { authorizer: { claims: {} } },
    };

    const result = await handler(event, {});

    expect(result.statusCode).toBe(403);
    expect(result.body).toContain('carto-users');
  });

  it('Sentry.wrapHandler is called exactly once — feedback.mjs must not wrap its own handler', () => {
    // index.mjs wraps the top-level export once; feedback.mjs must export a plain
    // async function so that /feedback requests do not open a second Sentry transaction.
    expect(wrapHandler).toHaveBeenCalledTimes(1);
  });
});
