import { vi, describe, it, expect, beforeEach } from 'vitest';

vi.mock('../src/js/config.js', () => ({
  API_BASE: 'https://api.test',
  DEBUG_MODE: false,
}));

const ENDPOINT = 'https://api.test/feedback';

describe('src/js/feedback.js', () => {
  beforeEach(() => {
    vi.resetModules();
    document.body.innerHTML = '';
    global.fetch = vi.fn();
  });

  async function loadWidget() {
    await import('../src/js/feedback.js');
  }

  function openDialog() {
    document.getElementById('carto-feedback-btn').click();
    return document.getElementById('carto-feedback-dialog');
  }

  // Flush async submit handler (fetch → json chain) without fake timers.
  // setTimeout(0) fires after microtasks, so the full async chain completes.
  const flushPromises = () => new Promise((r) => setTimeout(r, 0));

  async function fillAndSubmit(opts = {}) {
    const form = document.getElementById('carto-feedback-form');
    form.querySelector('[name="description"]').value = opts.description ?? 'Enough detail here.';
    if (opts.website !== undefined) {
      form.querySelector('[name="website"]').value = opts.website;
    }
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await flushPromises();
  }

  // ── Button injection ──────────────────────────────────────────────────────

  it('injects the Feedback button into document.body', async () => {
    await loadWidget();
    const btn = document.getElementById('carto-feedback-btn');
    expect(btn).not.toBeNull();
    expect(btn.textContent).toBe('Feedback');
    expect(btn.getAttribute('aria-label')).toBe('Send feedback');
  });

  it('is idempotent — calling initFeedbackWidget again does not inject a duplicate button', async () => {
    const { initFeedbackWidget } = await import('../src/js/feedback.js');
    initFeedbackWidget();
    expect(document.querySelectorAll('#carto-feedback-btn').length).toBe(1);
  });

  // ── Happy path ────────────────────────────────────────────────────────────

  it('happy path — shows reference ID and auto-closes dialog after 1800 ms', async () => {
    vi.useFakeTimers();
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: 'FB-2026-000001' }),
    });

    await loadWidget();
    openDialog();

    const form = document.getElementById('carto-feedback-form');
    form.querySelector('[name="description"]').value = 'Something broke on the graph page.';
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));

    // Two microtask flushes: one past `await fetch()`, one past `await res.json()`.
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    expect(document.getElementById('carto-feedback-status').textContent).toBe(
      'Thanks! Reference: FB-2026-000001',
    );
    expect(document.getElementById('carto-feedback-dialog')).not.toBeNull();

    vi.runAllTimers();
    expect(document.getElementById('carto-feedback-dialog')).toBeNull();

    vi.useRealTimers();
  });

  // ── Error branches ────────────────────────────────────────────────────────

  it('429 — shows rate-limit message and re-enables submit button', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 429 });

    await loadWidget();
    openDialog();
    await fillAndSubmit();

    expect(document.getElementById('carto-feedback-status').textContent).toBe(
      'Too many submissions; please try again later.',
    );
    expect(document.getElementById('carto-feedback-submit').disabled).toBe(false);
  });

  it('400 with detail — surfaces data.detail from the response body', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({ detail: 'Description must be at least 10 characters' }),
    });

    await loadWidget();
    openDialog();
    await fillAndSubmit();

    expect(document.getElementById('carto-feedback-status').textContent).toBe(
      'Description must be at least 10 characters',
    );
    expect(document.getElementById('carto-feedback-submit').disabled).toBe(false);
  });

  it('400 with unparseable body — falls back to generic validation message', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: () => Promise.reject(new Error('not JSON')),
    });

    await loadWidget();
    openDialog();
    await fillAndSubmit();

    expect(document.getElementById('carto-feedback-status').textContent).toBe('Validation error.');
    expect(document.getElementById('carto-feedback-submit').disabled).toBe(false);
  });

  it('network error — shows connection error message and re-enables submit button', async () => {
    global.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));

    await loadWidget();
    openDialog();
    await fillAndSubmit();

    expect(document.getElementById('carto-feedback-status').textContent).toBe(
      'Network error. Please check your connection.',
    );
    expect(document.getElementById('carto-feedback-submit').disabled).toBe(false);
  });

  // ── Honeypot guard ────────────────────────────────────────────────────────

  it('honeypot — website value is included in the POST payload when a bot populates it', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: 'FB-999' }),
    });

    await loadWidget();
    openDialog();
    await fillAndSubmit({ website: 'http://bot.example.com' });

    const [url, init] = global.fetch.mock.calls[0];
    expect(url).toBe(ENDPOINT);
    const body = JSON.parse(init.body);
    expect(body.website).toBe('http://bot.example.com');
  });

  it('honeypot — website field is absent from payload when blank (human user)', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: 'FB-998' }),
    });

    await loadWidget();
    openDialog();
    await fillAndSubmit();

    const body = JSON.parse(global.fetch.mock.calls[0][1].body);
    expect(Object.prototype.hasOwnProperty.call(body, 'website')).toBe(false);
  });
});
