import { useState, useEffect } from 'react';
import { apiFetch } from '../lib/api';

interface EnvData {
  environment: string[];
  entities: Record<string, string[]>;
  network_ranges: string[];
  new_accounts: string[];
  service_accounts: string[];
  admin_accounts: string[];
  benign_patterns: string[];
}

/**
 * Environment context editor (env facts, entity facts, network ranges,
 * account lists, benign patterns). Formerly the standalone Environment
 * page; merged into Config as a tab per the redesign plan.
 */
export default function EnvironmentEditor() {
  const [data, setData] = useState<EnvData | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [newEnvFact, setNewEnvFact] = useState('');
  const [newRange, setNewRange] = useState('');
  const [newAccount, setNewAccount] = useState('');
  const [newServiceAccount, setNewServiceAccount] = useState('');
  const [newAdminAccount, setNewAdminAccount] = useState('');
  const [newPattern, setNewPattern] = useState('');

  const fetchData = () => {
    setLoading(true);
    apiFetch<EnvData>('/api/config/environment')
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const save = async (updated: EnvData) => {
    setSaving(true);
    setSaveError('');
    try {
      const result = await apiFetch<EnvData>('/api/config/environment', {
        method: 'PUT',
        body: JSON.stringify(updated),
      });
      setData(result);
    } catch (e) {
      setSaveError(`Save failed: ${String(e)}`);
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div className="loading">Loading</div>;
  if (!data) return <div className="error-state">Failed to load environment context</div>;

  const addEnvFact = () => {
    if (!newEnvFact.trim()) return;
    save({ ...data, environment: [...data.environment, newEnvFact.trim()] });
    setNewEnvFact('');
  };

  const removeEnvFact = (idx: number) => {
    save({ ...data, environment: data.environment.filter((_, i) => i !== idx) });
  };



  const addRange = () => {
    if (!newRange.trim()) return;
    save({ ...data, network_ranges: [...data.network_ranges, newRange.trim()] });
    setNewRange('');
  };

  const removeRange = (idx: number) => {
    save({ ...data, network_ranges: data.network_ranges.filter((_, i) => i !== idx) });
  };

  const addAccount = (field: 'new_accounts' | 'service_accounts' | 'admin_accounts', value: string, setter: (v: string) => void) => {
    if (!value.trim()) return;
    save({ ...data, [field]: [...data[field], value.trim()] });
    setter('');
  };

  const removeAccount = (field: 'new_accounts' | 'service_accounts' | 'admin_accounts', idx: number) => {
    save({ ...data, [field]: data[field].filter((_, i) => i !== idx) });
  };

  const addPattern = () => {
    if (!newPattern.trim()) return;
    save({ ...data, benign_patterns: [...data.benign_patterns, newPattern.trim()] });
    setNewPattern('');
  };

  const removePattern = (idx: number) => {
    save({ ...data, benign_patterns: data.benign_patterns.filter((_, i) => i !== idx) });
  };

  return (
    <div>
      {saving && <div className="badge badge-investigating" style={{ marginBottom: 12 }}>Saving…</div>}
      {saveError && <div className="error-state" style={{ marginBottom: 12 }}>{saveError}</div>}

      {/* Section 1: Environment Facts */}
      <div className="section">
        <div className="section-title">Environment Facts</div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', marginBottom: 8 }}>
            Structural truths about the whole deployment — the supervisor treats these as ground truth
          </div>
        <div className="card">
          <ul className="inline-list">
            {data.environment.map((fact, i) => (
              <li key={i}>
                {fact}
                <button className="remove-btn" onClick={() => removeEnvFact(i)}>×</button>
              </li>
            ))}
          </ul>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <input value={newEnvFact} onChange={(e) => setNewEnvFact(e.target.value)} placeholder="e.g. AWS VPC 172.31.0.0/16" onKeyDown={(e) => e.key === 'Enter' && addEnvFact()} />
            <button className="btn" onClick={addEnvFact}>Add</button>
          </div>
        </div>
      </div>

      {/* Entity Context moved to the Entities page detail panel (UI-2/UI-5) —
          per-entity facts are edited where analysts meet the entity. */}

      {/* Section 3: Network Ranges */}
      <div className="section">
        <div className="section-title">Network Ranges</div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', marginBottom: 8 }}>
            Internal ranges — private-IP "impossible travel" between these is not flagged
          </div>
        <div className="card">
          <div className="tag-list" style={{ marginBottom: 8 }}>
            {data.network_ranges.map((range, i) => (
              <span className="tag" key={i} style={{ cursor: 'pointer' }} onClick={() => removeRange(i)}>
                {range} ×
              </span>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input value={newRange} onChange={(e) => setNewRange(e.target.value)} placeholder="e.g. 10.0.0.0/8" style={{ maxWidth: 200 }} onKeyDown={(e) => e.key === 'Enter' && addRange()} />
            <button className="btn" onClick={addRange}>Add</button>
          </div>
        </div>
      </div>

      {/* Section 4: Account Lists */}
      <div className="grid-3">
        <div className="section">
          <div className="section-title">New Accounts</div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', marginBottom: 8 }}>
              Recently created — expected to have high volume without tripping new-user detectors
            </div>
          <div className="card">
            <ul className="inline-list">
              {data.new_accounts.map((acct, i) => (
                <li key={i}>{acct}<button className="remove-btn" onClick={() => removeAccount('new_accounts', i)}>×</button></li>
              ))}
            </ul>
            <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
              <input value={newAccount} onChange={(e) => setNewAccount(e.target.value)} placeholder="Username" onKeyDown={(e) => e.key === 'Enter' && addAccount('new_accounts', newAccount, setNewAccount)} />
              <button className="btn" onClick={() => addAccount('new_accounts', newAccount, setNewAccount)}>Add</button>
            </div>
          </div>
        </div>

        <div className="section">
          <div className="section-title">Service Accounts</div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', marginBottom: 8 }}>
              Machine accounts — expected to operate off-hours
            </div>
          <div className="card">
            <ul className="inline-list">
              {data.service_accounts.map((acct, i) => (
                <li key={i}>{acct}<button className="remove-btn" onClick={() => removeAccount('service_accounts', i)}>×</button></li>
              ))}
            </ul>
            <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
              <input value={newServiceAccount} onChange={(e) => setNewServiceAccount(e.target.value)} placeholder="svc_account" onKeyDown={(e) => e.key === 'Enter' && addAccount('service_accounts', newServiceAccount, setNewServiceAccount)} />
              <button className="btn" onClick={() => addAccount('service_accounts', newServiceAccount, setNewServiceAccount)}>Add</button>
            </div>
          </div>
        </div>

        <div className="section">
          <div className="section-title">Admin Accounts</div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', marginBottom: 8 }}>
              Named admins — privilege-escalation commands are expected from these
            </div>
          <div className="card">
            <ul className="inline-list">
              {data.admin_accounts.map((acct, i) => (
                <li key={i}>{acct}<button className="remove-btn" onClick={() => removeAccount('admin_accounts', i)}>×</button></li>
              ))}
            </ul>
            <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
              <input value={newAdminAccount} onChange={(e) => setNewAdminAccount(e.target.value)} placeholder="admin_user" onKeyDown={(e) => e.key === 'Enter' && addAccount('admin_accounts', newAdminAccount, setNewAdminAccount)} />
              <button className="btn" onClick={() => addAccount('admin_accounts', newAdminAccount, setNewAdminAccount)}>Add</button>
            </div>
          </div>
        </div>
      </div>

      {/* Section 5: Benign Patterns */}
      <div className="section" style={{ marginTop: 24 }}>
        <div className="section-title">Benign Patterns</div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', marginBottom: 8 }}>
            Known-good activity descriptions — matching findings get extra scrutiny before confirmation
          </div>
        <div className="card">
          <ul className="inline-list">
            {data.benign_patterns.map((pattern, i) => (
              <li key={i}>{pattern}<button className="remove-btn" onClick={() => removePattern(i)}>×</button></li>
            ))}
          </ul>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <input value={newPattern} onChange={(e) => setNewPattern(e.target.value)} placeholder="e.g. Scheduled scan from 10.0.1.5 every Sunday" onKeyDown={(e) => e.key === 'Enter' && addPattern()} />
            <button className="btn" onClick={addPattern}>Add</button>
          </div>
        </div>
      </div>
    </div>
  );
}
