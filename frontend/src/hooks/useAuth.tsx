import { createContext, useContext, useState, useEffect, ReactNode, useCallback, useRef } from 'react';
import { apiFetch } from '../lib/api';

interface AuthContextType {
  isAuthenticated: boolean;
  username: string | null;
  role: string | null;
  loading: boolean;
  refreshAuth: () => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType>({
  isAuthenticated: false,
  username: null,
  role: null,
  loading: true,
  refreshAuth: async () => {},
  logout: () => {},
});

/**
 * Cookie-session auth state.
 *
 * Hydrated from GET /api/auth/me — the JWT lives in an httpOnly cookie
 * and is never handled by JavaScript. The 'api:unauthorized' event
 * (dispatched by apiFetch on any 401) drops auth state.
 *
 * The mount-time 401 (fresh visit, no session) sets unauthenticated
 * WITHOUT firing a logout POST — a logout storm on every fresh visit
 * was a real bug class in a sibling codebase.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [username, setUsername] = useState<string | null>(null);
  const [role, setRole] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const hasSession = useRef(false);

  const refreshAuth = useCallback(async () => {
    try {
      const me = await apiFetch<{ username: string; role: string }>('/api/auth/me');
      setUsername(me.username);
      setRole(me.role);
      hasSession.current = true;
    } catch {
      setUsername(null);
      setRole(null);
      hasSession.current = false;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshAuth();
  }, [refreshAuth]);

  useEffect(() => {
    const onUnauthorized = () => {
      // Drop state locally. Only POST /logout when we actually held a
      // session — a mount-time 401 (no session) must not trigger a
      // logout request loop.
      if (hasSession.current) {
        hasSession.current = false;
        apiFetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
      }
      setUsername(null);
      setRole(null);
      setLoading(false);
    };
    window.addEventListener('api:unauthorized', onUnauthorized);
    return () => window.removeEventListener('api:unauthorized', onUnauthorized);
  }, []);

  const logout = useCallback(() => {
    hasSession.current = false;
    apiFetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
    setUsername(null);
    setRole(null);
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated: !!username, username, role, loading, refreshAuth, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
