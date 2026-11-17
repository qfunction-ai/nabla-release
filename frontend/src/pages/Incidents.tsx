import { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { apiFetch } from '../lib/api';

interface Incident {
  incident_id: string;
  entity: string;
  entity_type?: string;
  run_id?: string;
  finding_type: string;
  severity: string;
  status: string;
  confidence: number;
  mitre_techniques: string[];
  description: string;
  evidence: string;
  created_at: string;
  updated_at: string;
  notes: string[];
}

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [entityFilter, setEntityFilter] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<Incident | null>(null);
  const [noteInput, setNoteInput] = useState('');
  const [offset, setOffset] = useState(0);
  const LIMIT = 50;
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  // Consume navigation query params once on mount (UI-1): severity/status
  // filters pre-applied from Dashboard click-throughs. After mount, local
  // state owns the filters.
  useEffect(() => {
    const sev = searchParams.get('severity');
    const st = searchParams.get('status');
    if (sev && ['critical', 'high', 'medium', 'low'].includes(sev)) setSeverityFilter(sev);
    if (st && ['new', 'investigating', 'resolved', 'false_positive'].includes(st)) setStatusFilter(st);
    const entity = searchParams.get('entity');
    if (entity) setEntityFilter(entity);
    const incidentParam = searchParams.get('incident');
    if (incidentParam) {
      setSelected(incidentParam);
      apiFetch<Incident>(`/api/incidents/${incidentParam}`)
        .then(setDetail)
        .catch(() => {});
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchIncidents = () => {
    setLoading(true);
    const params = new URLSearchParams();
    if (statusFilter) params.set('status', statusFilter);
    if (severityFilter) params.set('severity', severityFilter);
    if (entityFilter) params.set('entity', entityFilter);
    params.set('limit', String(LIMIT));
    params.set('offset', String(offset));
    apiFetch<{ incidents: Incident[]; total: number }>(`/api/incidents?${params}`)
      .then((data) => {
        setIncidents(data.incidents);
        setTotal(data.total);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchIncidents(); }, [offset, statusFilter, severityFilter, entityFilter]);

  const selectIncident = (id: string) => {
    setSelected(id);
    setDetail(null);
    apiFetch<Incident>(`/api/incidents/${id}`)
      .then(setDetail)
      .catch(() => {});
  };

  const updateStatus = (newStatus: string) => {
    if (!selected) return;
    apiFetch<Incident>(`/api/incidents/${selected}`, {
      method: 'PUT',
      body: JSON.stringify({ status: newStatus }),
    })
      .then((updated) => {
        setDetail(updated);
        fetchIncidents();
      })
      .catch(() => {});
  };

  const addNote = () => {
    if (!selected || !noteInput.trim()) return;
    apiFetch<Incident>(`/api/incidents/${selected}`, {
      method: 'PUT',
      body: JSON.stringify({ notes: noteInput.trim() }),
    })
      .then((updated) => {
        setDetail(updated);
        setNoteInput('');
      })
      .catch(() => {});
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">INCIDENTS</h1>
        <p className="page-subtitle"><span className="math">∇·F</span> = threat surface divergence · {total} incidents</p>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
        <select
          className="input"
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setOffset(0); }}
          style={{ width: 140 }}
        >
          <option value="">All statuses</option>
          <option value="new">New</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
        <select
          className="input"
          value={severityFilter}
          onChange={(e) => { setSeverityFilter(e.target.value); setOffset(0); }}
          style={{ width: 140 }}
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <div className="two-column">
        {/* Incident list */}
        <div>
          {loading ? (
            <div className="loading">Loading</div>
          ) : incidents.length === 0 ? (
            <div className="empty-state">No incidents match filters</div>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Entity</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((inc) => (
                    <tr
                      key={inc.incident_id}
                      onClick={() => selectIncident(inc.incident_id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td style={{ color: selected === inc.incident_id ? 'var(--accent)' : 'inherit' }}>
                        {inc.incident_id.slice(0, 8)}
                      </td>
                      <td>
                        {inc.entity}
                        {inc.entity_type === 'process' && (
                          <span className="tag" style={{ marginLeft: 6, fontSize: 10 }} title="Process, not a profiled entity">proc</span>
                        )}
                      </td>
                      <td>{inc.finding_type.replace(/_/g, ' ')}</td>
                      <td><span className={`badge badge-${inc.severity}`}>{inc.severity}</span></td>
                      <td><span className={`badge badge-${inc.status}`}>{inc.status}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="pagination">
            <button className="btn" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - LIMIT))}>
              ← Prev
            </button>
            <span>Showing {offset + 1}–{Math.min(offset + LIMIT, total)} of {total}</span>
            <button className="btn" disabled={offset + LIMIT >= total} onClick={() => setOffset(offset + LIMIT)}>
              Next →
            </button>
          </div>
        </div>

        {/* Detail panel */}
        <div>
          {selected && detail ? (
            <div>
              <div className="section-title" data-symbol="∇">INCIDENT DETAIL</div>
              {/* Supervisor narrative — the WHY, front and center (UI-3) */}
              {detail.description && (
                <div className="card" style={{ marginBottom: 16, borderTop: `2px solid var(--${detail.severity === 'critical' ? 'danger' : detail.severity === 'high' ? 'warning' : detail.severity === 'medium' ? 'purple' : 'success'})` }}>
                  <div className="section-title" data-symbol="∇">WHY THIS IS {detail.severity.toUpperCase()}</div>
                  <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
                    {detail.description}
                  </div>
                </div>
              )}

              {/* Metadata strip (compacted, UI-3) */}
              <div className="card" style={{ marginBottom: 16 }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px 24px', alignItems: 'center' }}>
                  <div>
                    <div className="field-label">ID</div>
                    <div className="field-value" style={{ fontFamily: 'var(--font-display)' }}>{detail.incident_id.slice(0, 8)}</div>
                  </div>
                  <div>
                    <div className="field-label">{detail.entity_type === 'process' ? 'Process' : 'Entity'}</div>
                    <div className="field-value" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span
                        style={{ cursor: 'pointer' }}
                        title={detail.entity_type === 'process'
                          ? 'Show all incidents for this process'
                          : 'Show all incidents for this entity'}
                        onClick={() => navigate(`/incidents?entity=${encodeURIComponent(detail.entity)}`)}
                      >
                        {detail.entity}
                      </span>
                      {detail.entity_type && (
                        <span className="tag" title={detail.entity_type === 'process' ? 'A process, not a profiled entity (user/host/ip)' : `Entity type: ${detail.entity_type}`}>
                          {detail.entity_type}
                        </span>
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="field-label">Type</div>
                    <div className="field-value">{detail.finding_type.replace(/_/g, ' ')}</div>
                  </div>
                  <div>
                    <div className="field-label">Severity</div>
                    <div className="field-value"><span className={`badge badge-${detail.severity}`}>{detail.severity}</span></div>
                  </div>
                  <div>
                    <div className="field-label">Status</div>
                    <div className="field-value"><span className={`badge badge-${detail.status}`}>{detail.status.replace('_', ' ')}</span></div>
                  </div>
                  <div>
                    <div className="field-label" title="How strongly the correlation chain supports this finding">Confidence</div>
                    <div className="field-value">{(detail.confidence * 100).toFixed(0)}%</div>
                  </div>
                  {detail.created_at && (
                    <div>
                      <div className="field-label">Created</div>
                      <div className="field-value">{new Date(detail.created_at).toLocaleString()}</div>
                    </div>
                  )}
                </div>
                {detail.mitre_techniques && detail.mitre_techniques.length > 0 && (
                  <div className="entity-field" style={{ marginBottom: 0 }}>
                    <div className="field-label">MITRE ATT&CK</div>
                    <div className="tag-list">
                      {detail.mitre_techniques.map((t) => (
                        <span className="tag" key={t} style={{ borderColor: 'var(--danger-border)', color: 'var(--danger)' }}>{t}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Evidence — expandable, human-readable layer + raw JSON (UI-3) */}
              {detail.evidence && <EvidenceCard evidence={detail.evidence} />}

              {/* Status actions */}
              <div className="card" style={{ marginBottom: 16 }}>
                <div className="section-title" data-symbol="∂">UPDATE STATUS</div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {['new', 'investigating', 'resolved', 'false_positive'].map((s) => (
                    <button
                      key={s}
                      className={`btn ${detail.status === s ? 'btn-primary' : ''}`}
                      onClick={() => updateStatus(s)}
                      disabled={detail.status === s}
                    >
                      {s.replace('_', ' ')}
                    </button>
                  ))}
                </div>
              </div>

              {/* Notes */}
              <div className="card">
                <div className="section-title" data-symbol="∇">NOTES</div>
                {detail.notes && detail.notes.length > 0 && (
                  <ul className="inline-list" style={{ marginBottom: 12 }}>
                    {detail.notes.map((note, i) => (
                      <li key={i}>{note}</li>
                    ))}
                  </ul>
                )}
                <div style={{ display: 'flex', gap: 8 }}>
                  <input
                    className="input"
                    value={noteInput}
                    onChange={(e) => setNoteInput(e.target.value)}
                    placeholder="Add a note..."
                    onKeyDown={(e) => e.key === 'Enter' && addNote()}
                  />
                  <button className="btn" onClick={addNote} disabled={!noteInput.trim()}>
                    Add
                  </button>
                </div>
              </div>
            </div>
          ) : selected ? (
            <div className="loading">Loading detail</div>
          ) : (
            <div className="empty-state">Select an incident to view details</div>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Evidence display (UI-3): collapsed by default; human-readable layer
 * above the raw JSON; counterfactuals phrased in plain language.
 */
function EvidenceCard({ evidence }: { evidence: string }) {
  const [expanded, setExpanded] = useState(false);
  const [showRaw, setShowRaw] = useState(false);

  // Evidence is JSON-ish text from the correlation stage; parse defensively
  let parsed: Record<string, unknown> | null = null;
  try {
    const obj = JSON.parse(evidence);
    if (obj && typeof obj === 'object') parsed = obj as Record<string, unknown>;
  } catch {
    parsed = null;
  }

  const renderHumanLayer = () => {
    if (!parsed) return null;
    const rows: React.ReactNode[] = [];

    // Anomaly chain — UI2a enriched shape: objects with method/severity/details
    const chainObjs = parsed.anomalies as { method?: string; severity?: string; timestamp?: string; details?: string; mitre?: string[] }[] | undefined;
    if (Array.isArray(chainObjs) && chainObjs.length > 0 && typeof chainObjs[0] === 'object') {
      rows.push(
        <div key="chain">
          <div className="method-label">What fired ({chainObjs.length}) — the detector hits behind this finding</div>
          {chainObjs.map((a, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '4px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
              <span className={`badge badge-${a.severity || 'medium'}`} style={{ fontSize: 10, flexShrink: 0 }}>{a.severity || 'med'}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <span style={{ fontFamily: 'var(--font-display)', fontSize: 11, color: 'var(--accent)' }}>{(a.method || 'unknown').replace(/_/g, ' ')}</span>
                {a.details && <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: 11, marginTop: 1 }}>{a.details}</span>}
                {a.mitre && a.mitre.length > 0 && (
                  <span style={{ display: 'flex', gap: 4, marginTop: 2 }}>
                    {a.mitre.slice(0, 3).map((t) => (
                      <span key={t} className="tag" style={{ fontSize: 9, borderColor: 'var(--danger-border)', color: 'var(--danger)' }}>{t}</span>
                    ))}
                  </span>
                )}
              </div>
              <span style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', flexShrink: 0 }}>
                {a.timestamp ? new Date(a.timestamp).toLocaleString() : ''}
              </span>
            </div>
          ))}
        </div>
      );
    } else {
      const chain = (parsed.anomaly_ids ?? parsed.anomalies) as string[] | undefined;
      if (Array.isArray(chain) && chain.length > 0) {
        rows.push(
          <div key="chain">
            <div className="method-label">Anomaly chain ({chain.length})</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {chain.map((id, i) => (
                <span key={i} className="tag" style={{ fontFamily: 'var(--font-display)' }}>{id}</span>
              ))}
            </div>
          </div>
        );
      }
    }

    // Detection methods
    const methods = parsed.detection_methods as string[] | undefined;
    if (Array.isArray(methods) && methods.length > 0) {
      rows.push(
        <div key="methods">
          <div className="method-label">Detection methods</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {methods.map((m, i) => (
              <span key={i} className="method-chip">{m}</span>
            ))}
          </div>
        </div>
      );
    }

    // Attack chain steps
    const steps = parsed.attack_chain as { step?: string; timestamp?: string; [k: string]: unknown }[] | undefined;
    if (Array.isArray(steps) && steps.length > 0) {
      rows.push(
        <div key="steps">
          <div className="method-label">Attack sequence</div>
          {steps.map((st, i) => (
            <div key={i} style={{ fontFamily: 'var(--font-display)', fontSize: 11, color: 'var(--text-secondary)', padding: '2px 0' }}>
              {st.timestamp ? `${new Date(st.timestamp).toLocaleTimeString()} — ` : ''}{String(st.step ?? 'step')}
            </div>
          ))}
        </div>
      );
    }

    // Counterfactuals → plain language
    const cf = parsed.counterfactuals as string[] | { description?: string; [k: string]: unknown }[] | undefined;
    if (Array.isArray(cf) && cf.length > 0) {
      rows.push(
        <div key="cf">
          <div className="method-label" title="Minimal changes that would alter this finding — sensitivity of the conclusion">
            What would change this finding
          </div>
          {cf.map((c, i) => (
            <div key={i} style={{ fontSize: 12, color: 'var(--text-secondary)', padding: '2px 0' }}>
              {typeof c === 'string' ? c : String(c.description ?? JSON.stringify(c))}
            </div>
          ))}
        </div>
      );
    }

    // Correlation score
    const score = parsed.correlation_score;
    if (typeof score === 'number') {
      rows.push(
        <div key="score">
          <div className="method-label">Correlation strength</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div className="progress-bar" style={{ width: 120 }}>
              <div className="progress-bar-fill" style={{ width: `${score * 100}%` }} />
            </div>
            <span style={{ fontFamily: 'var(--font-display)', fontSize: 11, color: 'var(--accent)' }}>{(score * 100).toFixed(0)}%</span>
          </div>
        </div>
      );
    }

    return rows.length > 0 ? <>{rows}</> : null;
  };

  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div className="section-title" data-symbol="∇">EVIDENCE</div>
      {!expanded ? (
        <button className="btn btn-secondary btn-sm" onClick={() => setExpanded(true)}>
          Show evidence {parsed ? '(full detail)' : ''}
        </button>
      ) : (
        <>
          {renderHumanLayer()}
          <div style={{ marginTop: 8 }}>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => setShowRaw(!showRaw)}
            >
              {showRaw ? 'Hide raw JSON' : 'Show raw JSON'}
            </button>
          </div>
          {showRaw && (
            <pre className="code-block" style={{ marginTop: 8 }}>
              {evidence}
            </pre>
          )}
        </>
      )}
    </div>
  );
}
