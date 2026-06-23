import { vi, describe, it, expect, afterEach } from 'vitest';

describe('config.js', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it('exports API_BASE pointing to the production API gateway', async () => {
    const { API_BASE } = await import('../src/js/config.js');
    expect(API_BASE).toBe('https://9o7c3668a4.execute-api.us-east-2.amazonaws.com/prod');
  });

  it('COGNITO has the expected pool, client, and region', async () => {
    const { COGNITO } = await import('../src/js/config.js');
    expect(COGNITO).toMatchObject({
      region: 'us-east-2',
      userPoolId: 'us-east-2_xneeJzaDJ',
      clientId: '3r633l045s8fse9v1ebubk8re6',
    });
  });

  it('COGNITO.redirectUri ends with /callback.html', async () => {
    const { COGNITO } = await import('../src/js/config.js');
    expect(COGNITO.redirectUri).toMatch(/\/callback\.html$/);
  });

  it('COGNITO.redirectUri uses localhost origin when DEV is true', async () => {
    vi.stubEnv('DEV', true);
    vi.resetModules();
    const { COGNITO } = await import('../src/js/config.js');
    expect(COGNITO.redirectUri).toContain('localhost:5173');
  });

  it('COGNITO.redirectUri uses production origin when DEV is false', async () => {
    vi.stubEnv('DEV', false);
    vi.resetModules();
    const { COGNITO } = await import('../src/js/config.js');
    expect(COGNITO.redirectUri).toContain('carto.jaetill.com');
  });
});
