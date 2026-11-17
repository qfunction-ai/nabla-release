import { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { apiFetch } from '../lib/api';

interface RunRecord {
  run_id: string;
  started_at: string;
  finished_at: string | null;
  log_types: string | string[];
  anomaly_count: number;
  findings_count: number;
  success: boolean;
  error: string | null;
  step_durations: Record<string, number> | null;
  duration_ms: number | null;
}

interface PipelineStatus {
  running: boolean;
  run_id: string | null;
  started_at: string | null;
  current_step: string | null;
  last_run: RunRecord | null;
}

interface RunFinding {
  entity: string;
  entity_type: string;
  type: string;
  severity: string;
  confidence: number;
  mitre_attack: string[];
}

interface RunDetail {
  run_id: string;
  started_at: string;
  finished_at: string | null;
  success: boolean;
  anomaly_count: number | null;
  findings_count: number | null;
  step_durations: Record<string, number> | null;
  anomalies?: { entity: string; severity: string; detection_method: string; timestamp: string; details: string }[];
  findings?: RunFinding[];
  supervisor_narrative?: string | null;
}

export default function Pipeline() {
  const [status, setStatus] = useState<PipelineStatus | null>(null);
  const [history, setHistory] = useState<RunRecord[]>([]);
  const [streaming, setStreaming] = useState(false);
  const [streamLog, setStreamLog] = useState<string[]>([]);
  const [logType, setLogType] = useState('all');
  const [logCount, setLogCount] = useState(50);
  const [source, setSource] = useState('auto');
  const abortRef = useRef<AbortController | null>(null);
  const [expandedRun, setExpandedRun] = useState<string | null>(null);
  const [searchParams] = useSearchParams();

  // Pre-expand a run from the ?run= param (Dashboard card retarget, UI-4)
  useEffect(() => {
    const runParam = searchParams.get('run');
    if (runParam && history.some((r) => r.run_id.startsWith(runParam))) {
      toggleRun(history.find((r) => r.run_id.startsWith(runParam))!.run_id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [history.length]);
  const [runDetail, setRunDetail] = useState<RunDetail | null>(null);

  const toggleRun = (runId: string) => {
    if (expandedRun === runId) {
      setExpandedRun(null);
      setRunDetail(null);
      return;
    }
    setExpandedRun(runId);
    setRunDetail(null);
    apiFetch<RunDetail>(`/api/pipeline/runs/${runId.slice(0, 8)}`)
      .then(setRunDetail)
      .catch(() => {});
  };

  const fetchStatus = () => {
    apiFetch<PipelineStatus>('/api/pipeline/status')
      .then(setStatus)
      .catch(() => {});
  };

  const fetchHistory = () => {
    apiFetch<{ runs: RunRecord[] }>('/api/pipeline/history?limit=20')
      .then((data) => setHistory(data.runs))
      .catch(() => {});
  };

  useEffect(() => { fetchStatus(); fetchHistory(); }, []);

  const startPipeline = async () => {
    setStreaming(true);
    setStreamLog([]);
    abortRef.current = new AbortController();

    try {
      // Trigger the run
      const run = await apiFetch<{ run_id: string }>('/api/pipeline/run', {
        method: 'POST',
        body: JSON.stringify({ log_type: logType, log_count: logCount, source }),
      });

      setStreamLog((prev) => [...prev, `▶ Pipeline started — run ${run.run_id.slice(0, 8)}`]);

      // Connect to SSE stream
      const res = await fetch('/api/pipeline/stream', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ run_id: run.run_id }),
        signal: abortRef.current.signal,
      });

      if (!res.ok) {
        setStreamLog((prev) => [...prev, `✗ Stream error: HTTP ${res.status}`]);
        setStreaming(false);
        return;
      }

      const reader = res.body?.getReader();
      if (!reader) return;

      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const event = JSON.parse(line.slice(6));
              if (event.type === 'progress') {
                setStreamLog((prev) => [...prev, `  ${event.step}...`]);
              } else if (event.type === 'completed') {
                setStreamLog((prev) => [...prev, `✓ Pipeline completed`]);
              } else if (event.type === 'error') {
                setStreamLog((prev) => [...prev, `✗ ${event.error}`]);
              }
            } catch {}
          }
        }
      }
    } catch (e) {
      if ((e as Error).name !== 'AbortError') {
        setStreamLog((prev) => [...prev, `✗ Error: ${String(e)}`]);
      }
    } finally {
      setStreaming(false);
      fetchStatus();
      fetchHistory();
    }
  };

  const stopStream = () => {
    abortRef.current?.abort();
    setStreaming(false);
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">PIPELINE</h1>
        <p className="page-subtitle"><span className="math">∇ × H</span> = detection curl — execute and monitor</p>
      </div>

      {/* Controls */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="section-title" data-symbol="∂">PIPELINE CONFIGURATION</div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label>Source</label>
            <select value={source} onChange={(e) => setSource(e.target.value)} style={{ width: 120 }}>
              <option value="auto">Auto</option>
              <option value="synthetic">Synthetic</option>
              <option value="splunk">Splunk</option>
              <option value="sumologic">SumoLogic</option>
              <option value="file">File</option>
            </select>
          </div>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label>Log Type</label>
            <select value={logType} onChange={(e) => setLogType(e.target.value)} style={{ width: 120 }}>
              <option value="all">All</option>
              <option value="auth">Auth</option>
              <option value="network">Network</option>
              <option value="dns">DNS</option>
              <option value="endpoint">Endpoint</option>
            </select>
          </div>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label>Count</label>
            <input
              type="number"
              value={logCount}
              onChange={(e) => setLogCount(Number(e.target.value))}
              style={{ width: 80 }}
            />
          </div>
          <button
            className="btn btn-primary"
            onClick={streaming ? stopStream : startPipeline}
            disabled={status?.running && !streaming}
          >
            {streaming ? '■ Stop' : '▶ Run Pipeline'}
          </button>
        </div>
      </div>

      {/* Current status */}
      {status && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="section-title" data-symbol="∇">CURRENT STATUS</div>
          {status.running ? (
            <div>
              <span className="badge badge-investigating">Running</span>
              <span style={{ marginLeft: 12, fontFamily: 'var(--font-display)', fontSize: 12, color: 'var(--text-tertiary)' }}>
                Step: {status.current_step || '—'} · Started: {status.started_at ? new Date(status.started_at).toLocaleTimeString() : '—'}
              </span>
            </div>
          ) : (
            <div>
              <span className="badge badge-resolved">Idle</span>
              {status.last_run && (
                <span style={{ marginLeft: 12, fontFamily: 'var(--font-display)', fontSize: 12, color: 'var(--text-tertiary)' }}>
                  Last run: {status.last_run.success ? '✓' : '✗'} ·
                  {status.last_run.duration_ms ? ` ${Math.round(status.last_run.duration_ms / 1000)}s` : ''} ·
                  {status.last_run.anomaly_count} anomalies · {status.last_run.findings_count} findings
                </span>
              )}
            </div>
          )}
        </div>
      )}

      {/* Stream log */}
      {streamLog.length > 0 && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="section-title" data-symbol="∂">RUN OUTPUT</div>
          <pre style={{ fontFamily: 'var(--font-display)', fontSize: 12, color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', maxHeight: 300, overflowY: 'auto' }}>
            {streamLog.join('\n')}
          </pre>
        </div>
      )}

      {/* Run history */}
      <div className="section">
        <div className="section-title" data-symbol="∇">RUN HISTORY</div>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', marginBottom: 8 }}>
          anomaly = single detector hit · finding = correlated threat group reviewed by the supervisor · confirmed findings become incidents · click a run for detail
        </div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Run ID</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Source</th>
                <th>Anomalies</th>
                <th>Findings</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {history.length === 0 ? (
                <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-tertiary)' }}>No runs yet</td></tr>
              ) : (
                history.map((run) => (
                  <>
                    <tr
                      key={run.run_id}
                      style={{ cursor: 'pointer' }}
                      onClick={() => toggleRun(run.run_id)}
                    >
                      <td style={{ color: 'var(--accent)' }}>
                        {expandedRun === run.run_id ? '▾' : '▸'} {run.run_id.slice(0, 8)}
                      </td>
                      <td>{run.started_at ? new Date(run.started_at).toLocaleString() : '—'}</td>
                      <td>{run.duration_ms ? `${Math.round(run.duration_ms / 1000)}s` : '—'}</td>
                      <td>{Array.isArray(run.log_types) ? run.log_types.join(', ') : run.log_types}</td>
                      <td>{run.anomaly_count}</td>
                      <td
                        title="Findings: correlated threat groups reviewed by the supervisor — confirmed findings become incidents"
                      >{run.findings_count}</td>
                      <td>
                        <span className={`badge ${run.success ? 'badge-resolved' : 'badge-critical'}`}>
                          {run.success ? 'OK' : 'FAIL'}
                        </span>
                      </td>
                    </tr>
                    {expandedRun === run.run_id && (
                      <tr key={`${run.run_id}-detail`}>
                        <td colSpan={7} style={{ background: 'var(--bg-secondary)', padding: '12px 16px' }}>
                          <RunDetailPanel detail={runDetail} />
                        </td>
                      </tr>
                    )}
                  </>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

/**
 * Inline run-detail expansion (UI-4): step timeline, findings summary,
 * supervisor narrative, anomaly sample, created incidents. Old runs
 * (pre-UI-2/UI-4 data) degrade gracefully with explicit labels.
 */
function RunDetailPanel({ detail }: { detail: RunDetail | null }) {
  if (!detail) return <div className="loading">Loading run detail…</div>;

  const hasDetailedData = detail.findings !== undefined || detail.anomalies !== undefined;
  const steps = detail.step_durations
    ? Object.entries(detail.step_durations).sort(([, a], [, b]) => b - a)
    : [];

  return (
    <div>
      {/* Step durations mini timeline */}
      {steps.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div className="method-label" style={{ marginTop: 0 }}>Step durations</div>
          {steps.map(([name, secs]) => {
            const max = steps[0][1] || 1;
            return (
              <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                <span style={{ fontFamily: 'var(--font-display)', fontSize: 11, width: 110, color: 'var(--text-secondary)' }}>{name}</span>
                <div className="progress-bar" style={{ flex: 1, maxWidth: 300 }}>
                  <div className="progress-bar-fill" style={{ width: `${(secs / max) * 100}%` }} />
                </div>
                <span style={{ fontFamily: 'var(--font-display)', fontSize: 11, color: 'var(--text-tertiary)' }}>{secs.toFixed(1)}s</span>
              </div>
            );
          })}
        </div>
      )}

      {!hasDetailedData && (
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 11, color: 'var(--text-tertiary)', fontStyle: 'italic' }}>
          Detailed data not captured for this run (predates run-detail persistence)
        </div>
      )}

      {/* Findings summary */}
      {detail.findings && detail.findings.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div className="method-label">Findings ({detail.findings.length}) — correlated threat groups the supervisor reviewed</div>
          {detail.findings.map((f, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '3px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
              <span className={`badge badge-${f.severity}`} style={{ fontSize: 10 }}>{f.severity}</span>
              <span style={{ fontFamily: 'var(--font-display)', fontSize: 11 }}>{f.entity}</span>
              {f.entity_type === 'process' && <span className="tag" style={{ fontSize: 10 }}>proc</span>}
              <span style={{ color: 'var(--text-secondary)' }}>{f.type.replace(/_/g, ' ')}</span>
              {f.mitre_attack.slice(0, 3).map((t) => (
                <span key={t} className="tag" style={{ fontSize: 10, borderColor: 'var(--danger-border)', color: 'var(--danger)' }}>{t}</span>
              ))}
              <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)' }}>
                {(f.confidence * 100).toFixed(0)}%
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Supervisor narrative */}
      {detail.supervisor_narrative && (
        <div style={{ marginBottom: 12 }}>
          <div className="method-label">Supervisor report</div>
          <div style={{ fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.55, whiteSpace: 'pre-wrap', maxHeight: 240, overflowY: 'auto', background: 'var(--bg-tertiary)', padding: 8, border: '1px solid var(--border)' }}>
            {detail.supervisor_narrative}
          </div>
        </div>
      )}

      {/* Anomaly sample */}
      {detail.anomalies && detail.anomalies.length > 0 && (
        <div>
          <div className="method-label">Anomaly sample ({detail.anomalies.length} — detectors fired before correlation)</div>
          {detail.anomalies.slice(0, 8).map((a, i) => (
            <div key={i} style={{ display: 'flex', gap: 8, padding: '2px 0', fontSize: 11 }}>
              <span className={`badge badge-${a.severity}`} style={{ fontSize: 9 }}>{a.severity}</span>
              <span style={{ fontFamily: 'var(--font-display)', color: 'var(--accent)' }}>{a.detection_method}</span>
              <span style={{ color: 'var(--text-secondary)' }}>{a.entity}</span>
              <span style={{ color: 'var(--text-tertiary)', marginLeft: 'auto' }}>
                {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : ''}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
