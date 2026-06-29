import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

const mockSend = vi.fn();
vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: vi.fn(() => ({ send: mockSend })),
  GetSecretValueCommand: vi.fn(),
}));

const mockDriverFn = vi.fn(() => ({
  session: vi.fn(() => ({
    run: vi.fn().mockResolvedValue({ records: [] }),
    close: vi.fn().mockResolvedValue(undefined),
  })),
}));
vi.mock('neo4j-driver', () => ({
  default: { driver: mockDriverFn, auth: { basic: vi.fn(() => ({})) } },
}));

const TTL = 15 * 60 * 1000;
const T0 = 1_700_000_000_000; // fixed epoch anchor for tests

describe('lambda/graph.mjs — getSecrets TTL', () => {
  let syncEngagement;
  let dateSpy;

  beforeEach(async () => {
    vi.resetModules();
    mockSend.mockClear();
    mockDriverFn.mockClear();
    mockSend.mockResolvedValue({
      SecretString: JSON.stringify({ NEO4J_PASSWORD: 'test-password' }),
    });
    dateSpy = vi.spyOn(Date, 'now').mockReturnValue(T0);
    process.env.NEO4J_URI = 'bolt://localhost:7687';
    process.env.NEO4J_USERNAME = 'neo4j';
    process.env.NEO4J_DATABASE = 'neo4j';
    ({ syncEngagement } = await import('../lambda/graph.mjs'));
  });

  afterEach(() => {
    dateSpy.mockRestore();
  });

  const eng = { id: 'e1', name: 'Test', client: 'Acme', status: 'active', startDate: '2024-01-01' };

  it('fetches secrets on first invocation', async () => {
    await syncEngagement(eng);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it('does not re-fetch secrets within the 15-minute TTL', async () => {
    await syncEngagement(eng);
    dateSpy.mockReturnValue(T0 + 14 * 60 * 1000); // 14 min later — within TTL
    await syncEngagement({ ...eng, id: 'e2' });
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it('re-fetches secrets after TTL expires', async () => {
    await syncEngagement(eng);
    dateSpy.mockReturnValue(T0 + TTL + 1); // 1 ms past TTL
    await syncEngagement({ ...eng, id: 'e2' });
    expect(mockSend).toHaveBeenCalledTimes(2);
  });

  it('reconnects neo4j driver after secrets expiry', async () => {
    await syncEngagement(eng);
    expect(mockDriverFn).toHaveBeenCalledTimes(1);
    dateSpy.mockReturnValue(T0 + TTL + 1);
    await syncEngagement({ ...eng, id: 'e2' });
    expect(mockDriverFn).toHaveBeenCalledTimes(2);
  });
});
