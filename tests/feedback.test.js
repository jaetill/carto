import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

vi.mock('../src/js/config.js', () => ({
  API_BASE: 'https://test-api.example.com',
  DEBUG_MODE: false,
  COGNITO: {},
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function loadWidget() {
  vi.resetModules();
  await import('../src/js/feedback.js');
}

function clickFeedbackButton() {
  document.getElementById('carto-feedback-btn').click();
  return document.getElementById('carto-feedback-dialog');
}

async function triggerSubmit(dialog, overrides = {}) {
  const form = dialog.querySelector('#carto-feedback-form');
  form.querySelector('[name="type"]').value = overrides.type ?? 'bug';
  form.querySelector('[name="description"]').value =
    overrides.description ?? 'A reproducible issue found during testing';
  if (overrides.email) form.querySelector('[name="email"]').value = overrides.email;
  if (overrides.website !== undefined)
    form.querySelector('[name="website"]').value = overrides.website;
  form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  // Flush pending microtasks (fetch + json awaits in the handler).
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

// Flush all microtasks via a macrotask boundary (safe without fake timers).
const flushPromises = () => new Promise((resolve) => setTimeout(resolve, 0));

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('feedback.js', () => {
  beforeEach(() => {
    document.getElementById('carto-feedback-btn')?.remove();
    document.getElementById('carto-feedback-dialog')?.remove();
    global.fetch = vi.fn();
    // Polyfill dialog methods that may be absent in happy-dom.
    HTMLDialogElement.prototype.showModal = vi.fn(function () {
      this.setAttribute('open', '');
    });
    HTMLDialogElement.prototype.close = vi.fn(function () {
      this.removeAttribute('open');
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // initFeedbackWidget()
  // -------------------------------------------------------------------------

  describe('initFeedbackWidget()', () => {
    it('injects a feedback button into the DOM on load', async () => {
      await loadWidget();
      expect(document.getElementById('carto-feedback-btn')).not.toBeNull();
    });

    it('is idempotent — calling again does not create a second button', async () => {
      await loadWidget();
      const { initFeedbackWidget } = await import('../src/js/feedback.js');
      initFeedbackWidget();
      expect(document.querySelectorAll('#carto-feedback-btn').length).toBe(1);
    });

    it('clicking the button opens the feedback dialog', async () => {
      await loadWidget();
      const dialog = clickFeedbackButton();
      expect(dialog).not.toBeNull();
    });

    it('clicking the button when dialog already exists does not duplicate it', async () => {
      await loadWidget();
      clickFeedbackButton();
      clickFeedbackButton();
      expect(document.querySelectorAll('#carto-feedback-dialog').length).toBe(1);
    });

    it('cancel button closes and removes the dialog', async () => {
      await loadWidget();
      const dialog = clickFeedbackButton();
      dialog.querySelector('#carto-feedback-cancel').click();
      expect(document.getElementById('carto-feedback-dialog')).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // Form submission
  // -------------------------------------------------------------------------

  describe('form submission', () => {
    it('happy path — shows reference ID in status and auto-closes dialog', async () => {
      vi.useFakeTimers();
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ id: 'FB-2026-000001' }),
      });

      await loadWidget();
      const dialog = clickFeedbackButton();
      const status = dialog.querySelector('#carto-feedback-status');

      await triggerSubmit(dialog);
      await vi.runAllTimersAsync();

      expect(status.textContent).toContain('FB-2026-000001');
      expect(document.getElementById('carto-feedback-dialog')).toBeNull();
    });

    it('429 — re-enables submit button and shows rate-limit message', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 429 });

      await loadWidget();
      const dialog = clickFeedbackButton();
      const submitBtn = dialog.querySelector('#carto-feedback-submit');

      await triggerSubmit(dialog);
      await flushPromises();

      expect(dialog.querySelector('#carto-feedback-status').textContent).toContain('Too many');
      expect(submitBtn.disabled).toBe(false);
    });

    it('400 — surfaces data.detail from response body', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ detail: 'Description too short' }),
      });

      await loadWidget();
      const dialog = clickFeedbackButton();
      const submitBtn = dialog.querySelector('#carto-feedback-submit');

      await triggerSubmit(dialog);
      await flushPromises();

      expect(dialog.querySelector('#carto-feedback-status').textContent).toBe(
        'Description too short',
      );
      expect(submitBtn.disabled).toBe(false);
    });

    it('400 — falls back to generic message when response body has no detail', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: () => Promise.reject(new Error('not JSON')),
      });

      await loadWidget();
      const dialog = clickFeedbackButton();

      await triggerSubmit(dialog);
      await flushPromises();

      expect(dialog.querySelector('#carto-feedback-status').textContent).toBe('Validation error.');
    });

    it('network error — shows error message and re-enables submit button', async () => {
      global.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));

      await loadWidget();
      const dialog = clickFeedbackButton();
      const submitBtn = dialog.querySelector('#carto-feedback-submit');

      await triggerSubmit(dialog);
      await flushPromises();

      expect(dialog.querySelector('#carto-feedback-status').textContent).toContain('Network error');
      expect(submitBtn.disabled).toBe(false);
    });

    it('posts to the configured feedback endpoint with correct method and headers', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ id: 'FB-001' }),
      });

      await loadWidget();
      const dialog = clickFeedbackButton();
      await triggerSubmit(dialog);
      await flushPromises();

      expect(global.fetch).toHaveBeenCalledWith(
        'https://test-api.example.com/feedback',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    });
  });

  // -------------------------------------------------------------------------
  // Honeypot field
  // -------------------------------------------------------------------------

  describe('honeypot field (website)', () => {
    it('includes website in payload when the honeypot field is filled (bot scenario)', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ id: 'FB-001' }),
      });

      await loadWidget();
      const dialog = clickFeedbackButton();
      await triggerSubmit(dialog, { website: 'http://bot.example.com' });
      await flushPromises();

      const body = JSON.parse(global.fetch.mock.calls[0][1].body);
      expect(body.website).toBe('http://bot.example.com');
    });

    it('omits website from payload when the honeypot field is empty (legitimate user)', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ id: 'FB-001' }),
      });

      await loadWidget();
      const dialog = clickFeedbackButton();
      await triggerSubmit(dialog);
      await flushPromises();

      const body = JSON.parse(global.fetch.mock.calls[0][1].body);
      expect('website' in body).toBe(false);
    });
  });
});
