import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiFetch } from '../lib/api';

interface RunRecord {
  run_id: string;
  started_at: string | null;
  duration_ms: number | null;
  anomaly_count: number;
  findings_count: number;
  success: boolean;
}

interface IncidentRecord {
  incident_id: string;
  entity: string;
  finding_type: string;
  severity: string;
  status: string;
  updated_at: string | null;
}

interface DashboardData {
  phase: string;
  days_remaining: number | null;
  warm_up: {
    users: { total: number; warm: number; pct: number };
    hosts: { total: number; warm: number; pct: number };
    ips: { total: number; warm: number; pct: number };
    min_observations: number;
  };
  entity_counts: { users: number; hosts: number; ips: number };
  health: {
    letta: { healthy: boolean; detail?: string };
    ollama: { healthy: boolean; detail?: string };
  };
  incident_stats: {
    total: number;
    by_status: Record<string, number>;
    by_severity: Record<string, number>;
  };
  recent_runs: RunRecord[];
  recent_incidents: IncidentRecord[];
  top_risky: {
    entity_id: string;
    entity_type: string;
    overall: number;
    categories: Record<string, number>;
    trend: number;
    trend_label: string;
    peak: number;
  }[];
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    apiFetch<DashboardData>('/api/dashboard')
      .then(setData)
      .catch((e) => setError(String(e)));
  }, []);

  if (error) return <div className="error-state">{error}</div>;
  if (!data) return <div className="loading">Loading system state</div>;

  const lastRun = data.recent_runs[0];
  const totalEntities = data.entity_counts.users + data.entity_counts.hosts + data.entity_counts.ips;
  const peakRisk = data.top_risky && data.top_risky.length > 0
    ? Math.max(...data.top_risky.map((r) => r.overall))
    : 0;

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h1 className="page-title">DASHBOARD</h1>
        <p className="page-subtitle"><span className="math">∇f(x)</span> = detect → correlate → respond — {data.phase} phase{data.days_remaining !== null && data.days_remaining > 0 ? ` · ${data.days_remaining}d to detection` : ''}</p>
      </div>

      {/* Health grid */}
      <div className="section-header" data-symbol="∇">SYSTEM HEALTH</div>
      <div className="health-grid">
        <div className="health-item">
          <div className={`health-dot ${data.health.letta.healthy ? 'healthy' : 'unhealthy'}`} />
          <span className="health-label">Letta</span>
          <span className={`health-status ${data.health.letta.healthy ? 'healthy' : 'unhealthy'}`}>
            {data.health.letta.healthy ? 'Connected' : 'Down'}
          </span>
        </div>
        <div className="health-item">
          <div className={`health-dot ${data.health.ollama.healthy ? 'healthy' : 'unhealthy'}`} />
          <span className="health-label">Ollama</span>
          <span className={`health-status ${data.health.ollama.healthy ? 'healthy' : 'unhealthy'}`}>
            {data.health.ollama.healthy ? 'Connected' : 'Down'}
          </span>
        </div>
        <div className="health-item">
          <div className={`health-dot ${data.phase === 'detection' ? 'healthy' : 'degraded'}`} />
          <span className="health-label">System Phase</span>
          <span className={`health-status ${data.phase === 'detection' ? 'healthy' : 'degraded'}`}>{data.phase}</span>
        </div>
      </div>

      {/* Detection surface stats */}
      <div className="section-header" data-symbol="∂">DETECTION SURFACE</div>
      <div className="stats-grid">
        <div className="stat-card" role="button" tabIndex={0} onClick={() => navigate('/incidents')} onKeyDown={(e) => e.key === 'Enter' && navigate('/incidents')}>
          <div className="stat-number">{data.incident_stats.total}</div>
          <div className="stat-label">Incidents</div>
          <div className="stat-formula"><code>{data.incident_stats.by_status.new || 0} new · {data.incident_stats.by_status.investigating || 0} investigating</code></div>
        </div>
        <div className="stat-card" role="button" tabIndex={0} onClick={() => navigate('/entities')} onKeyDown={(e) => e.key === 'Enter' && navigate('/entities')}>
          <div className="stat-number">{totalEntities}</div>
          <div className="stat-label">Entities</div>
          <div className="stat-formula">
            <code>{data.warm_up.users.warm}/{data.warm_up.users.total} users · {data.warm_up.hosts.warm}/{data.warm_up.hosts.total} hosts · {data.warm_up.ips.warm}/{data.warm_up.ips.total} ips warm</code>
          </div>
        </div>
        <div className="stat-card" role="button" tabIndex={0} onClick={() => navigate(`/pipeline?run=${lastRun ? lastRun.run_id.slice(0, 8) : ''}`)} onKeyDown={(e) => e.key === 'Enter' && navigate(`/pipeline?run=${lastRun ? lastRun.run_id.slice(0, 8) : ''}`)}>
          <div className="stat-number">{lastRun ? lastRun.anomaly_count : '—'}</div>
          <div className="stat-label">Anomalies (last run)</div>
          <div className="stat-formula"><code>{lastRun ? `${lastRun.findings_count} findings · ${lastRun.duration_ms ? Math.round(lastRun.duration_ms / 1000) + 's' : '—'}` : 'no runs yet'}</code></div>
        </div>
        <div className="stat-card" role="button" tabIndex={0} onClick={() => navigate('/entities?sort=risk')} onKeyDown={(e) => e.key === 'Enter' && navigate('/entities?sort=risk')}>
          <div className="stat-number">{peakRisk > 0 ? peakRisk.toFixed(0) : '—'}</div>
          <div className="stat-label">Peak Risk</div>
          <div className="stat-formula"><code>max ∇R(x) ∀ x ∈ E</code></div>
        </div>
      </div>

      {/* Severity strip */}
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: '1.5rem' }}>
        {['critical', 'high', 'medium', 'low'].map((sev) => (
          <div
            className="stat-card"
            key={sev}
            role="button"
            tabIndex={0}
            onClick={() => navigate(`/incidents?severity=${sev}`)}
            onKeyDown={(e) => e.key === 'Enter' && navigate(`/incidents?severity=${sev}`)}
          >
            <div className="stat-number" style={{ color: `var(--${sev === 'critical' ? 'danger' : sev === 'high' ? 'warning' : sev === 'medium' ? 'purple' : 'success'})` }}>
              {data.incident_stats.by_severity[sev] || 0}
            </div>
            <div className="stat-label">{sev}</div>
          </div>
        ))}
      </div>

      {/* Riskiest entities */}
      {data.top_risky && data.top_risky.length > 0 && (
        <div className="section">
          <div className="section-title" data-symbol="∇">RISKIEST ENTITIES</div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Entity</th>
                  <th>Type</th>
                  <th>Risk Score</th>
                  <th>Peak</th>
                  <th>Trend</th>
                  <th>Top Category</th>
                </tr>
              </thead>
              <tbody>
                {data.top_risky.map((re, i) => {
                  const topCat = Object.entries(re.categories)
                    .filter(([_, v]) => v > 0)
                    .sort(([_, a], [__, b]) => b - a)[0];
                  return (
                    <tr key={i} style={{ cursor: 'pointer' }} onClick={() => navigate(`/entities?entity=${encodeURIComponent(re.entity_id)}`)}>
                      <td style={{ color: 'var(--accent)' }}>{re.entity_id}</td>
                      <td><span className="tag">{re.entity_type}</span></td>
                      <td>
                        <span className={`badge ${re.overall >= 50 ? 'badge-critical' : re.overall >= 20 ? 'badge-high' : 'badge-medium'}`}>
                          {re.overall.toFixed(0)}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-display)', fontSize: 12 }}>{re.peak.toFixed(0)}</td>
                      <td style={{ fontFamily: 'var(--font-display)', fontSize: 12 }}>{re.trend_label}</td>
                      <td>{topCat ? `${topCat[0].replace('_', ' ')} (${topCat[1].toFixed(0)})` : '—'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Recent runs */}
      <div className="section">
        <div className="section-title" data-symbol="∂">RECENT PIPELINE RUNS</div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Run ID</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Anomalies</th>
                <th>Findings</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_runs.length === 0 ? (
                <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-tertiary)' }}>No runs yet</td></tr>
              ) : (
                data.recent_runs.map((run, i) => (
                  <tr key={i}>
                    <td style={{ color: 'var(--accent)' }}>{run.run_id.slice(0, 8)}</td>
                    <td>{run.started_at ? new Date(run.started_at).toLocaleString() : '—'}</td>
                    <td>{run.duration_ms ? `${Math.round(run.duration_ms / 1000)}s` : '—'}</td>
                    <td>{run.anomaly_count}</td>
                    <td>{run.findings_count}</td>
                    <td>
                      <span className={`badge ${run.success ? 'badge-resolved' : 'badge-critical'}`}>
                        {run.success ? 'OK' : 'FAIL'}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent incidents */}
      <div className="section">
        <div className="section-title" data-symbol="∇">RECENT INCIDENTS</div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Entity</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_incidents.length === 0 ? (
                <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-tertiary)' }}>No incidents</td></tr>
              ) : (
                data.recent_incidents.map((inc, i) => (
                  <tr key={i} style={{ cursor: 'pointer' }} onClick={() => navigate(`/incidents?incident=${inc.incident_id.slice(0, 8)}`)}>
                    <td style={{ color: 'var(--accent)' }}>{inc.incident_id.slice(0, 8)}</td>
                    <td>{inc.entity}</td>
                    <td>{inc.finding_type}</td>
                    <td><span className={`badge badge-${inc.severity}`}>{inc.severity}</span></td>
                    <td><span className={`badge badge-${inc.status}`}>{inc.status}</span></td>
                    <td>{inc.updated_at ? new Date(inc.updated_at).toLocaleString() : '—'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
