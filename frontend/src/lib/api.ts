const API_URL = import.meta.env.VITE_API_URL || '';

/**
 * Cookie-session API client.
 *
 * Auth flows via httpOnly cookie — the session token is never handled
 * by JavaScript. credentials: 'include' makes the cookie flow on every
 * request (same-origin via the nginx proxy in deployment; cross-origin
 * dev relies on the backend CORS allow-credentials list).
 *
 * Any 401 dispatches the 'api:unauthorized' window event; the
 * AuthProvider listens and drops auth state (single choke point for
 * session-expiry handling — no page checks 401 manually).
 */
export async function apiFetch<T = unknown>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const isFormData = options.body instanceof FormData;

  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    credentials: 'include',
    headers: {
      ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
      ...(options.headers || {}),
    },
  });

  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent('api:unauthorized'));
    throw new Error('Unauthorized');
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => res.statusText);
    throw new Error(detail);
  }

  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`Expected JSON, got: ${text.slice(0, 200)}`);
  }
}

export { API_URL };
