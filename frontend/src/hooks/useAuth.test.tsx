import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import { AuthProvider, useAuth } from './useAuth';

// Mock the api module
vi.mock('../lib/api', () => ({
  apiFetch: vi.fn(),
}));

function wrapper({ children }: { children: React.ReactNode }) {
  return <AuthProvider>{children}</AuthProvider>;
}

describe('useAuth (cookie session model)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('hydrates authenticated state from /me', async () => {
    const { apiFetch } = await import('../lib/api');
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValue({ username: 'alice', role: 'admin' });

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.isAuthenticated).toBe(true);
    expect(result.current.username).toBe('alice');
    expect(result.current.role).toBe('admin');
  });

  it('lands unauthenticated when /me rejects', async () => {
    const { apiFetch } = await import('../lib/api');
    (apiFetch as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Unauthorized'));

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.username).toBeNull();
  });

  it('401-on-init does NOT fire a logout POST (no-loop discipline)', async () => {
    const { apiFetch } = await import('../lib/api');
    // /me rejects on mount (fresh visit, no session)
    (apiFetch as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Unauthorized'));

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));

    // Drain microtasks so any erroneous logout POST would have been issued
    await new Promise((r) => setTimeout(r, 10));

    // apiFetch called exactly once — the /me hydration. No /logout call.
    expect(apiFetch).toHaveBeenCalledTimes(1);
    expect((apiFetch as ReturnType<typeof vi.fn>).mock.calls[0][0]).toBe('/api/auth/me');
    expect(result.current.isAuthenticated).toBe(false);
  });

  it('unauthorized event after a session drops state AND posts logout', async () => {
    const { apiFetch } = await import('../lib/api');
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValue({ username: 'alice', role: 'admin' });

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true));

    (apiFetch as ReturnType<typeof vi.fn>).mockClear();
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValue({ ok: true });

    act(() => {
      window.dispatchEvent(new CustomEvent('api:unauthorized'));
    });

    await waitFor(() => expect(result.current.isAuthenticated).toBe(false));
    // Logout POST was issued (we held a session)
    const calls = (apiFetch as ReturnType<typeof vi.fn>).mock.calls.map((c) => `${c[1]?.method || 'GET'} ${c[0]}`);
    expect(calls).toContain('POST /api/auth/logout');
  });

  it('logout clears state and posts to the logout endpoint', async () => {
    const { apiFetch } = await import('../lib/api');
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValue({ username: 'alice', role: 'admin' });

    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.isAuthenticated).toBe(true));

    (apiFetch as ReturnType<typeof vi.fn>).mockClear();
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValue({ ok: true });

    act(() => {
      result.current.logout();
    });

    await waitFor(() => expect(result.current.isAuthenticated).toBe(false));
    const calls = (apiFetch as ReturnType<typeof vi.fn>).mock.calls.map((c) => `${c[1]?.method || 'GET'} ${c[0]}`);
    expect(calls).toContain('POST /api/auth/logout');
  });
});
