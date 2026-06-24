import { describe, it, expect } from 'vitest';

describe('config', () => {
  it('DEBUG_MODE is false in production config', async () => {
    const { DEBUG_MODE } = await import('../src/js/config.js');
    expect(DEBUG_MODE).toBe(false);
  });
});
