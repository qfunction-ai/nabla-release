import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiFetch } from '../lib/api';
import { useAuth } from '../hooks/useAuth';
import { validateRegistration } from './login.utils';

interface SetupStatus {
  needs_setup: boolean;
  requires_setup_token?: boolean;
}

/** Cyan corner brackets framing the viewport — Nabla's frame element. */
function CornerDecorations() {
  const corner = (position: React.CSSProperties) => (
    <div
      aria-hidden="true"
      style={{
        position: 'fixed',
        width: 24,
        height: 24,
        borderColor: 'rgba(0, 217, 255, 0.35)',
        borderStyle: 'solid',
        borderWidth: 0,
        pointerEvents: 'none',
        zIndex: 1,
        ...position,
      }}
    />
  );
  return (
    <>
      {corner({ top: 16, left: 16, borderTopWidth: 1, borderLeftWidth: 1 })}
      {corner({ top: 16, right: 16, borderTopWidth: 1, borderRightWidth: 1 })}
      {corner({ bottom: 16, left: 16, borderBottomWidth: 1, borderLeftWidth: 1 })}
      {corner({ bottom: 16, right: 16, borderBottomWidth: 1, borderRightWidth: 1 })}
    </>
  );
}

export default function Login() {
  const navigate = useNavigate();
  const { refreshAuth } = useAuth();

  const [checking, setChecking] = useState(true);
  const [needsSetup, setNeedsSetup] = useState(false);
  const [requiresToken, setRequiresToken] = useState(false);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [setupToken, setSetupToken] = useState('');

  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiFetch<SetupStatus>('/api/auth/setup-status')
      .then((s) => {
        setNeedsSetup(s.needs_setup);
        setRequiresToken(!!s.requires_setup_token);
      })
      .catch(() => setError('Cannot reach the Nabla API'))
      .finally(() => setChecking(false));
  }, []);

  const extractError = async (res: Response): Promise<string> => {
    try {
      const body = await res.json();
      return body.detail || 'Request failed';
    } catch {
      return 'Request failed';
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    const validation = validateRegistration(username, password, confirm);
    if (validation) {
      setError(validation);
      return;
    }
    setBusy(true);
    setError('');
    try {
      const payload: Record<string, string> = { username, password };
      if (requiresToken) payload.setup_token = setupToken;
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        setError(await extractError(res));
        return;
      }
      await refreshAuth();
      navigate('/');
    } catch {
      setError('Connection failed — is the Nabla API running?');
    } finally {
      setBusy(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        setError(await extractError(res));
        return;
      }
      await refreshAuth();
      navigate('/');
    } catch {
      setError('Connection failed — is the Nabla API running?');
    } finally {
      setBusy(false);
    }
  };

  if (checking) return null; // no flash of the wrong form

  const isRegister = needsSetup;

  return (
    <div className="login-page">
      <CornerDecorations />
      <div className="login-container">
        <div className="card" style={{ padding: '2.5rem 2rem', borderTop: '2px solid var(--accent)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem', justifyContent: 'center', marginBottom: '1.25rem' }}>
            <div
              aria-hidden="true"
              style={{
                width: 56,
                height: 56,
                border: '2px solid var(--accent)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontFamily: 'var(--font-display)',
                fontSize: '1.75rem',
                fontWeight: 700,
                color: 'var(--accent)',
                boxShadow: '0 0 15px rgba(0, 217, 255, 0.3)',
                position: 'relative',
              }}
            >
              ∇
            </div>
            <div>
              <div style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: '1.25rem', letterSpacing: '0.05em' }}>
                <span style={{ color: 'var(--accent)' }}>N</span>ABLA
              </div>
              <div
                style={{
                  fontFamily: 'var(--font-display)',
                  fontSize: '0.625rem',
                  color: 'var(--text-tertiary)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.1em',
                }}
              >
                QFunction
              </div>
            </div>
          </div>

          <p
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: '0.75rem',
              color: 'var(--text-tertiary)',
              textAlign: 'center',
              marginBottom: '1.75rem',
            }}
          >
            <span style={{ color: 'var(--accent)', opacity: 0.7 }}>∇f(x)</span> = detect → correlate → respond
          </p>

          {error && (
            <div className="error" style={{ marginBottom: '1rem' }}>
              {error}
            </div>
          )}

          {isRegister ? (
            <form onSubmit={handleRegister} noValidate>
              <div className="form-group">
                <label className="form-label" htmlFor="reg-username">Username</label>
                <input
                  id="reg-username"
                  className="input"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  minLength={3}
                  maxLength={50}
                  pattern="[a-zA-Z0-9_]+"
                  title="Letters, digits, and underscores"
                  autoFocus
                />
                <div className="form-hint">3-50 characters — letters, digits, underscores</div>
              </div>
              <div className="form-group">
                <label className="form-label" htmlFor="reg-password">Password</label>
                <input
                  id="reg-password"
                  className="input"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                  minLength={8}
                />
                <div className="form-hint">At least 8 characters. First user becomes admin.</div>
              </div>
              <div className="form-group">
                <label className="form-label" htmlFor="reg-confirm">Confirm password</label>
                <input
                  id="reg-confirm"
                  className="input"
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  autoComplete="new-password"
                />
              </div>
              {requiresToken && (
                <div className="form-group">
                  <label className="form-label" htmlFor="reg-token">Setup token</label>
                  <input
                    id="reg-token"
                    className="input"
                    type="password"
                    value={setupToken}
                    onChange={(e) => setSetupToken(e.target.value)}
                    placeholder="NABLA_SETUP_TOKEN"
                  />
                  <div className="form-hint">Required on first registration while NABLA_SETUP_TOKEN is set</div>
                </div>
              )}
              <button className="btn btn-primary" type="submit" disabled={busy} style={{ width: '100%' }}>
                {busy ? 'Creating…' : 'Create account'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleLogin} noValidate>
              <div className="form-group">
                <label className="form-label" htmlFor="login-username">Username</label>
                <input
                  id="login-username"
                  className="input"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  autoFocus
                />
              </div>
              <div className="form-group">
                <label className="form-label" htmlFor="login-password">Password</label>
                <input
                  id="login-password"
                  className="input"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                />
              </div>
              <button className="btn btn-primary" type="submit" disabled={busy} style={{ width: '100%' }}>
                {busy ? 'Please wait…' : 'Sign in'}
              </button>
            </form>
          )}
        </div>
      </div>
      <div
        aria-hidden="true"
        style={{
          position: 'fixed',
          bottom: 12,
          right: 16,
          fontFamily: 'var(--font-display)',
          fontSize: '0.625rem',
          color: 'var(--text-tertiary)',
          opacity: 0.4,
          pointerEvents: 'none',
        }}
      >
        nabla v0.2.0
      </div>
    </div>
  );
}
