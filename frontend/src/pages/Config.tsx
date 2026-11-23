import { useState, useEffect } from 'react';
import { apiFetch } from '../lib/api';
import EnvironmentEditor from '../components/EnvironmentEditor';
import type { components } from '../types/api';

interface ScheduleData {
  running: boolean;
  next_run: string | null;
  interval: number;
  log_types: string;
  log_count: number;
}

interface ConnectorData {
  splunk: { configured: boolean; last_ingestion: Record<string, string> };
  sumologic: { configured: boolean; last_ingestion: Record<string, string> };
}

// Generated from the Pydantic response model (FR-4). The hand-copied
// interface this replaces served four phantom fields (updates,
// observations, total_threshold_updates, total_bandit_observations)
// that the backend never sent — the columns rendered empty forever.
type RLData = components['schemas']['RLStateResponse'];

interface HealthData {
  letta: { healthy: boolean; detail?: string };
  ollama: { healthy: boolean; detail?: string };
  data_dir: { path: string; writable: boolean; exists: boolean };
}

export default function ConfigPage() {
  const [tab, setTab] = useState<'schedule' | 'connectors' | 'environment' | 'rl' | 'system' | 'export'>('schedule');
  const [schedule, setSchedule] = useState<ScheduleData | null>(null);
  const [connectors, setConnectors] = useState<ConnectorData | null>(null);
  const [rl, setRL] = useState<RLData | null>(null);
  const [health, setHealth] = useState<HealthData | null>(null);
  const [systemMsg, setSystemMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [confirmAction, setConfirmAction] = useState<{ label: string; action: () => void } | null>(null);

  useEffect(() => {
    apiFetch<ScheduleData>('/api/config/schedule').then(setSchedule).catch(() => {});
    apiFetch<ConnectorData>('/api/config/connectors').then(setConnectors).catch(() => {});
    apiFetch<RLData>('/api/system/rl').then(setRL).catch(() => {});
    apiFetch<HealthData>('/api/system/health').then(setHealth).catch(() => {});
  }, []);

  const [scheduleMsg, setScheduleMsg] = useState('');

  const saveSchedule = (updates: Partial<ScheduleData> & { enabled?: boolean }) => {
    setScheduleMsg('');
    apiFetch<ScheduleData>('/api/config/schedule', {
      method: 'PUT',
      body: JSON.stringify({
        enabled: updates.enabled ?? schedule?.running ?? false,
        interval: updates.interval ?? schedule?.interval ?? 5,
        log_types: updates.log_types ?? schedule?.log_types ?? 'all',
        log_count: updates.log_count ?? schedule?.log_count ?? 50,
      }),
    })
      .then((updated) => {
        setSchedule(updated);
        setScheduleMsg('Saved');
        window.setTimeout(() => setScheduleMsg(''), 2000);
      })
      .catch((e) => setScheduleMsg(`Save failed: ${String(e).slice(0, 120)}`));
  };

  const doExport = () => {
    apiFetch<Record<string, unknown>>('/api/system/export')
      .then((data) => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `nabla-export-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        setSystemMsg({ type: 'success', text: 'Export complete' });
      })
      .catch((e) => setSystemMsg({ type: 'error', text: `Export failed: ${String(e)}` }));
  };

  const doImport = (merge: boolean) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      const formData = new FormData();
      formData.append('file', file);
      fetch(`/api/system/import?merge=${merge}`, {
        method: 'POST',
        credentials: 'include',
        body: formData,
      })
        .then((res) => {
          if (res.ok) setSystemMsg({ type: 'success', text: 'Import successful' });
          else setSystemMsg({ type: 'error', text: 'Import failed' });
        })
        .catch(() => setSystemMsg({ type: 'error', text: 'Import failed' }));
    };
    input.click();
  };

  const doBootstrap = () => {
    setConfirmAction({
      label: 'Bootstrap the agent system?',
      action: () => {
        apiFetch('/api/system/bootstrap', { method: 'POST' })
          .then(() => setSystemMsg({ type: 'success', text: 'Bootstrap complete' }))
          .catch((e) => setSystemMsg({ type: 'error', text: String(e) }));
      },
    });
  };

  const doTeardown = () => {
    setConfirmAction({
      label: 'Tear down all agents? This cannot be undone.',
      action: () => {
        apiFetch('/api/system/teardown', { method: 'POST' })
          .then(() => setSystemMsg({ type: 'success', text: 'Teardown complete' }))
          .catch((e) => setSystemMsg({ type: 'error', text: String(e) }));
      },
    });
  };

  const tabs = [
    { key: 'schedule', label: 'Schedule' },
    { key: 'connectors', label: 'Connectors' },
    { key: 'environment', label: 'Environment' },
    { key: 'rl', label: 'RL State' },
    { key: 'system', label: 'System' },
    { key: 'export', label: 'Export/Import' },
  ] as const;

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">CONFIG</h1>
        <p className="page-subtitle"><span className="math">∂θ/∂t</span> = adaptive parameters</p>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 24, borderBottom: '1px solid var(--border)' }}>
        {tabs.map((t) => (
          <button
            key={t.key}
            className={`btn ${tab === t.key ? 'btn-primary' : ''}`}
            onClick={() => setTab(t.key)}
            style={{ border: 'none', borderRadius: 0, borderBottom: tab === t.key ? '2px solid var(--accent)' : '2px solid transparent' }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Schedule tab */}
      {tab === 'schedule' && schedule && (
        <div>
          <div className="doc-tip" style={{ marginBottom: 16 }}>
            The scheduler runs the full detection pipeline automatically every N minutes — identical to manual
            Pipeline runs, including supervisor review, risk updates, and threshold tuning.
          </div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="section-title" data-symbol="∇">SCHEDULER STATUS</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span className={`badge ${schedule.running ? 'badge-investigating' : 'badge-resolved'}`}>
                {schedule.running ? 'Running' : 'Stopped'}
              </span>
              {schedule.running && schedule.next_run && (
                <span style={{ fontFamily: 'var(--font-display)', fontSize: 12, color: 'var(--text-tertiary)' }}>
                  Next: {new Date(schedule.next_run).toLocaleTimeString()}
                </span>
              )}
            </div>
          </div>
          <div className="card">
            <div className="section-title" data-symbol="∂">CONFIGURATION</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginBottom: 16 }}>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label" htmlFor="sched-interval">Interval (minutes)</label>
                <input
                  id="sched-interval"
                  className="input"
                  type="number"
                  min={1}
                  max={1440}
                  defaultValue={schedule.interval}
                  onBlur={(e) => {
                    const v = Number(e.target.value);
                    if (v >= 1 && v <= 1440 && v !== schedule.interval) saveSchedule({ interval: v });
                  }}
                />
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label" htmlFor="sched-types">Log types</label>
                <select
                  id="sched-types"
                  className="input"
                  value={schedule.log_types}
                  onChange={(e) => saveSchedule({ log_types: e.target.value })}
                >
                  <option value="all">all</option>
                  <option value="auth">auth</option>
                  <option value="network">network</option>
                  <option value="dns">dns</option>
                  <option value="endpoint">endpoint</option>
                </select>
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label" htmlFor="sched-count">Log count (per run)</label>
                <input
                  id="sched-count"
                  className="input"
                  type="number"
                  min={10}
                  max={5000}
                  defaultValue={schedule.log_count}
                  onBlur={(e) => {
                    const v = Number(e.target.value);
                    if (v >= 10 && v <= 5000 && v !== schedule.log_count) saveSchedule({ log_count: v });
                  }}
                />
              </div>
            </div>
            {scheduleMsg && (
              <div style={{ fontFamily: 'var(--font-display)', fontSize: 11, color: scheduleMsg.startsWith('Save failed') ? 'var(--danger)' : 'var(--success)', marginBottom: 12 }}>
                {scheduleMsg}
              </div>
            )}
            <button
              className={`btn ${schedule.running ? 'btn-danger' : 'btn-primary'}`}
              onClick={() => saveSchedule({ enabled: !schedule.running })}
            >
              {schedule.running ? 'Stop Scheduler' : 'Start Scheduler'}
            </button>
          </div>
        </div>
      )}

      {/* Connectors tab */}
      {tab === 'connectors' && connectors && (
        <div>
          <div className="doc-tip" style={{ marginBottom: 16 }}>
            Credentials are configured via environment variables at deployment — read-only in the UI.
            Set <code>NABLA_SPLUNK_*</code> / <code>NABLA_SUMOLOGIC_*</code> in your <code>.env</code> and redeploy
            (<code>docker compose up -d --build</code>). See Help → Config for the full list.
          </div>
          <div className="grid-2">
          <div className="card">
            <div className="section-title" data-symbol="∇">SPLUNK</div>
            <div className="entity-field">
              <div className="field-label">Status</div>
              <div className="field-value">
                <span className={`badge ${connectors.splunk.configured ? 'badge-resolved' : 'badge-false_positive'}`}>
                  {connectors.splunk.configured ? 'Configured' : 'Not configured'}
                </span>
              </div>
            </div>
            {Object.entries(connectors.splunk.last_ingestion).map(([key, ts]) => (
              <div className="entity-field" key={key}>
                <div className="field-label">{key}</div>
                <div className="field-value">{new Date(ts).toLocaleString()}</div>
              </div>
            ))}
          </div>
          <div className="card">
            <div className="section-title" data-symbol="∂">SUMOLOGIC</div>
            <div className="entity-field">
              <div className="field-label">Status</div>
              <div className="field-value">
                <span className={`badge ${connectors.sumologic.configured ? 'badge-resolved' : 'badge-false_positive'}`}>
                  {connectors.sumologic.configured ? 'Configured' : 'Not configured'}
                </span>
              </div>
            </div>
            {Object.entries(connectors.sumologic.last_ingestion).map(([key, ts]) => (
              <div className="entity-field" key={key}>
                <div className="field-label">{key}</div>
                <div className="field-value">{new Date(ts).toLocaleString()}</div>
              </div>
            ))}
          </div>
          </div>
        </div>
      )}

      {/* Environment tab (merged from the former Environment page) */}
      {tab === 'environment' && <EnvironmentEditor />}

      {/* RL State tab */}
      {tab === 'rl' && rl && (
        <div>
          <div className="grid-2" style={{ marginBottom: 24 }}>
            <div className="card">
              <div className="section-title" data-symbol="∇">FEEDBACK LABELS</div>
              <div className="card-value accent">{rl.feedback_labels}</div>
            </div>
            <div className="card">
              <div className="section-title" data-symbol="∂">MIN LABELS / METHOD</div>
              <div className="card-value accent">{rl.min_labels}</div>
            </div>
          </div>

          <div className="section">
            <div className="section-title" data-symbol="∇">ADAPTIVE THRESHOLDS — HONEST STATES</div>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Method</th>
                    <th>Current</th>
                    <th>Default</th>
                    <th>State</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(rl.thresholds).map(([name, t]) => {
                    const stateTag = t.pinned ? (
                      <span className="tag" style={{ borderColor: 'var(--warning-border)', color: 'var(--warning)' }}>PINNED</span>
                    ) : t.state === 'held' ? (
                      <span className="tag" style={{ borderColor: 'var(--info-border, var(--accent))', color: 'var(--info, var(--accent))' }}>HELD — {t.label_count}/{t.min_labels} LABELS</span>
                    ) : t.state === 'not_calibratable' ? (
                      <span className="tag">NOT CALIBRATABLE</span>
                    ) : t.changed ? (
                      <span className="tag" style={{ borderColor: 'var(--accent-border, var(--accent))', color: 'var(--accent)' }}>MOVED {t.default} → {t.current}</span>
                    ) : (
                      <span className="tag" style={{ borderColor: 'var(--success-border, var(--success))', color: 'var(--success)' }}>CALIBRATABLE</span>
                    );
                    const evidence = t.pinned
                      ? 'operator guardrail — never tuned'
                      : t.state === 'held' && t.reason
                        ? t.reason
                      : t.label_count > 0
                        ? `${t.label_count} labels · ${t.fp_count} FP / ${t.tp_count} TP`
                        : t.reason || 'no labels yet';
                    return (
                      <tr key={name}>
                        <td className="mono" style={{ color: t.changed ? 'var(--accent)' : 'inherit' }} title={t.methods.length > 0 ? `fed by: ${t.methods.join(', ')}` : ''}>{name}</td>
                        <td className="mono" style={{ color: t.changed ? 'var(--accent)' : 'inherit' }}>{t.current}</td>
                        <td className="mono" style={{ color: 'var(--text-tertiary)' }}>{t.default}</td>
                        <td>{stateTag}</td>
                        <td className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{evidence}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 6 }}>
              The four states: <b style={{ color: 'var(--accent)' }}>MOVED</b> — calibration changed it from the default, label evidence shown.{' '}
              <b style={{ color: 'var(--warning)' }}>PINNED</b> — guardrailed by policy, never auto-tuned.{' '}
              <b>HELD</b> — calibratable but label evidence is still below min_labels.{' '}
              <b>NOT CALIBRATABLE</b> — no method emits a score in this knob's units; tuning it would be theater.
            </div>
          </div>

          <div className="section">
            <div className="section-title" data-symbol="∂">DETECTION METHOD EFFECTIVENESS</div>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Method</th>
                    <th>Mean</th>
                    <th>α</th>
                    <th>β</th>
                    <th>Obs</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(rl.effectiveness)
                    .sort(([, a], [, b]) => b.mean - a.mean)
                    .map(([method, e]) => (
                      <tr key={method}>
                        <td>{method}</td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <div style={{ width: 60, height: 4, background: 'var(--border)' }}>
                              <div style={{ width: `${e.mean * 100}%`, height: '100%', background: 'var(--accent)' }} />
                            </div>
                            {e.mean.toFixed(3)}
                          </div>
                        </td>
                        <td>{e.alpha.toFixed(0)}</td>
                        <td>{e.beta.toFixed(0)}</td>
                        <td>{e.alpha + e.beta - 2}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* System tab */}
      {tab === 'system' && health && (
        <div>
          <div className="grid-3" style={{ marginBottom: 24 }}>
            <div className="card">
              <div className="card-header">Letta</div>
              <div className="card-value">
                <span className={`health-dot ${health.letta.healthy ? 'healthy' : 'unhealthy'}`} />
                {health.letta.healthy ? 'OK' : 'Down'}
              </div>
              {health.letta.detail && <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 4 }}>{health.letta.detail}</div>}
            </div>
            <div className="card">
              <div className="card-header">Ollama</div>
              <div className="card-value">
                <span className={`health-dot ${health.ollama.healthy ? 'healthy' : 'unhealthy'}`} />
                {health.ollama.healthy ? 'OK' : 'Down'}
              </div>
              {health.ollama.detail && <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 4 }}>{health.ollama.detail}</div>}
            </div>
            <div className="card">
              <div className="card-header">Data Directory</div>
              <div className="card-value" style={{ fontSize: 16 }}>
                {health.data_dir.exists ? '✓' : '✗'} {health.data_dir.writable ? 'rw' : 'ro'}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 4 }}>{health.data_dir.path}</div>
            </div>
          </div>

          <div className="section">
            <div className="section-title" data-symbol="∂">BOOTSTRAP / TEARDOWN</div>
            {systemMsg && (
              <div className={systemMsg.type === 'error' ? 'error-state' : 'badge badge-resolved'} style={{ marginBottom: 12 }}>
                {systemMsg.text}
              </div>
            )}
            <div style={{ display: 'flex', gap: 12 }}>
              <button className="btn btn-primary" onClick={doBootstrap}>
                Bootstrap
              </button>
              <button className="btn btn-danger" onClick={doTeardown}>
                Teardown
              </button>
            </div>
            {confirmAction && (
              <div className="modal-overlay" onClick={() => setConfirmAction(null)}>
                <div className="modal-card" onClick={(e) => e.stopPropagation()}>
                  <div className="modal-title">Confirm</div>
                  <div className="modal-message">{confirmAction.label}</div>
                  <div className="modal-actions">
                    <button className="btn" onClick={() => setConfirmAction(null)}>Cancel</button>
                    <button className="btn btn-danger" onClick={() => { confirmAction.action(); setConfirmAction(null); }}>Confirm</button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Export/Import tab */}
      {tab === 'export' && (
        <div>
          {systemMsg && tab === 'export' && (
            <div className={systemMsg.type === 'error' ? 'error-state' : 'badge badge-resolved'} style={{ marginBottom: 12 }}>
              {systemMsg.text}
            </div>
          )}
          <div className="section">
            <div className="section-title" data-symbol="∇">EXPORT STATE</div>
            <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 12 }}>
              Download all learned state (entity profiles, RL thresholds, GCN-LOF model, environment context, incidents, run history).
            </p>
            <button className="btn btn-primary" onClick={doExport}>
              Export JSON
            </button>
          </div>

          <div className="section">
            <div className="section-title" data-symbol="∂">IMPORT STATE</div>
            <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 12 }}>
              Upload a previously exported JSON file. Overwrite replaces all state; Merge combines with existing.
            </p>
            <div style={{ display: 'flex', gap: 12 }}>
              <button className="btn" onClick={() => doImport(false)}>
                Overwrite Import
              </button>
              <button className="btn" onClick={() => doImport(true)}>
                Merge Import
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
