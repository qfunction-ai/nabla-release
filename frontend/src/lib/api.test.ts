import { describe, it, expect, vi, beforeEach } from 'vitest';
import { apiFetch, API_URL } from './api';

describe('apiFetch (cookie session model)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns JSON data on success', async () => {
    const data = { phase: 'detection' };
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve(JSON.stringify(data)),
    });

    const result = await apiFetch('/api/dashboard');
    expect(result).toEqual(data);
  });

  it('sends credentials on every request (cookie flows)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve('{"ok":true}'),
    });

    await apiFetch('/api/test');
    const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(fetchCall[1].credentials).toBe('include');
  });

  it('dispatches api:unauthorized and throws on 401', async () => {
    const handler = vi.fn();
    window.addEventListener('api:unauthorized', handler);

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: () => Promise.resolve('Unauthorized'),
    });

    await expect(apiFetch('/api/dashboard')).rejects.toThrow('Unauthorized');
    expect(handler).toHaveBeenCalledTimes(1);

    window.removeEventListener('api:unauthorized', handler);
  });

  it('does NOT touch localStorage on 401 (cookie model — no token in JS)', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: () => Promise.resolve('Unauthorized'),
    });

    await expect(apiFetch('/api/dashboard')).rejects.toThrow('Unauthorized');
    // No navigation side effects either (the event handles state)
    expect(window.location.href).not.toContain('login');
  });

  it('throws with error detail on non-OK response', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      text: () => Promise.resolve('Internal Server Error'),
    });

    await expect(apiFetch('/api/dashboard')).rejects.toThrow('Internal Server Error');
  });

  it('throws with truncated text on non-JSON response', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve('<html>not json</html>'),
    });

    await expect(apiFetch('/api/dashboard')).rejects.toThrow('Expected JSON');
  });

  it('sends Content-Type application/json for non-FormData', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve('{"ok":true}'),
    });

    await apiFetch('/api/test', { method: 'POST', body: JSON.stringify({ a: 1 }) });
    const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const headers = fetchCall[1].headers;
    expect(headers['Content-Type']).toBe('application/json');
  });

  it('omits Content-Type for FormData body', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve('{"ok":true}'),
    });

    const formData = new FormData();
    formData.append('file', new Blob(['test']), 'test.csv');
    await apiFetch('/api/upload', { method: 'POST', body: formData });
    const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const headers = fetchCall[1].headers;
    expect(headers['Content-Type']).toBeUndefined();
  });
});

describe('API_URL', () => {
  it('defaults to empty string', () => {
    expect(API_URL).toBe('');
  });
});
