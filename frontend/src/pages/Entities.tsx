import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { apiFetch } from '../lib/api';
import Timeline from '../components/Timeline';

interface Entity {
  id: string;
  type: string;
  observation_count: number;
  first_seen: string | null;
  last_seen: string | null;
  warm: boolean;
  account_created_at?: string | null;
  risk_score: number;
}

interface EntityDetail {
  type: string;
  warm: boolean;
  observation_count?: number;
  first_seen?: string | null;
  last_seen?: string | null;
  environment_facts: string[];
  ewma?: Record<string, number>;
  typical_ips?: string[];
  peer_group?: { group_id: string; label: string; members: string[]; centroid?: unknown } | null;
  risk_score?: {
    overall: number;
    categories: Record<string, number>;
    peak: number;
    trend: number;
    trend_label: string;
  };
}

interface Attribution {
  entity_id: string;
  anomalies: {
    run_id: string;
    timestamp: string;
    detection_method: string;
    severity: string;
    details: string;
    categories: string[];
    mitre_attack: { id: string; name: string }[];
  }[];
  incidents: {
    incident_id: string;
    finding_type: string;
    severity: string;
    status: string;
    updated_at: string;
  }[];
  risk: {
    overall: number;
    peak: number;
    trend: number;
    trend_label: string;
    categories: Record<string, number>;
  } | null;
  runs_scanned: number;
}

export default function Entities() {
  const [entities, setEntities] = useState<Entity[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [sortBy, setSortBy] = useState<string>('id');
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<EntityDetail | null>(null);
  const [offset, setOffset] = useState(0);
  const LIMIT = 50;
  const [searchParams] = useSearchParams();

  // Consume navigation query params once on mount (UI-1): entity selection
  // and sort from Dashboard click-throughs. After mount, local state owns
  // everything.
  useEffect(() => {
    const sortParam = searchParams.get('sort');
    if (sortParam === 'risk' || sortParam === 'last_seen' || sortParam === 'id') setSortBy(sortParam);
    const entityParam = searchParams.get('entity');
    if (entityParam) {
      setSearch(entityParam);
      setSelected(entityParam);
      apiFetch<EntityDetail>(`/api/entities/${encodeURIComponent(entityParam)}`)
        .then(setDetail)
        .catch(() => {});
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchEntities = () => {
    setLoading(true);
    const params = new URLSearchParams();
    if (search) params.set('search', search);
    if (typeFilter) params.set('type', typeFilter);
    params.set('limit', String(LIMIT));
    params.set('offset', String(offset));
    apiFetch<{ entities: Entity[]; total: number }>(`/api/entities?${params}`)
      .then((data) => {
        let sorted = [...data.entities];
        if (sortBy === 'risk') {
          sorted.sort((a, b) => b.risk_score - a.risk_score);
        } else if (sortBy === 'last_seen') {
          sorted.sort((a, b) => (b.last_seen || '').localeCompare(a.last_seen || ''));
        }
        setEntities(sorted);
        setTotal(data.total);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchEntities(); }, [offset, typeFilter, sortBy]);

  useEffect(() => {
    const t = setTimeout(fetchEntities, 300);
    return () => clearTimeout(t);
  }, [search]);

  const [attribution, setAttribution] = useState<Attribution | null>(null);

  const selectEntity = (id: string) => {
    setSelected(id);
    setDetail(null);
    setAttribution(null);
    apiFetch<EntityDetail>(`/api/entities/${encodeURIComponent(id)}`)
      .then(setDetail)
      .catch(() => {});
    apiFetch<Attribution>(`/api/entities/${encodeURIComponent(id)}/attribution`)
      .then(setAttribution)
      .catch(() => {});
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">ENTITIES</h1>
        <p className="page-subtitle"><span className="math">∂P/∂t</span> — behavioral profiles · {total} known entities</p>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
        <input
          className="input"
          placeholder="Search entities..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
          style={{ maxWidth: 300 }}
        />
        <select
          className="input"
          value={typeFilter}
          onChange={(e) => { setTypeFilter(e.target.value); setOffset(0); }}
          style={{ width: 120 }}
        >
          <option value="">All types</option>
          <option value="user">User</option>
          <option value="host">Host</option>
          <option value="ip">IP</option>
        </select>
        <select
          className="input"
          value={sortBy}
          onChange={(e) => { setSortBy(e.target.value); setOffset(0); }}
          style={{ width: 140 }}
        >
          <option value="id">Sort: Name</option>
          <option value="risk">Sort: Risk Score</option>
          <option value="last_seen">Sort: Last Seen</option>
        </select>
      </div>

      <div className="two-column">
        {/* Entity list */}
        <div>
          {loading ? (
            <div className="loading">Loading</div>
          ) : entities.length === 0 ? (
            <div className="empty-state">No entities found</div>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Risk</th>
                    <th>Obs</th>
                    <th>Status</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {entities.map((e) => (
                    <tr
                      key={e.id}
                      onClick={() => selectEntity(e.id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td style={{ color: selected === e.id ? 'var(--accent)' : 'inherit' }}>
                        {e.id}
                      </td>
                      <td><span className="tag">{e.type}</span></td>
                      <td>
                        <span className={`badge ${e.risk_score >= 50 ? 'badge-critical' : e.risk_score >= 20 ? 'badge-high' : e.risk_score > 0 ? 'badge-medium' : 'badge-resolved'}`}>
                          {e.risk_score.toFixed(0)}
                        </span>
                      </td>
                      <td>{e.observation_count}</td>
                      <td>
                        <span className={`badge ${e.warm ? 'badge-resolved' : 'badge-new'}`}>
                          {e.warm ? 'warm' : 'cold'}
                        </span>
                      </td>
                      <td>{e.last_seen ? new Date(e.last_seen).toLocaleDateString() : '—'}</td>
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
          {selected ? (
            detail ? (
              <div>
                <div className="section-title" data-symbol="∇">ENTITY DETAIL</div>
                <div className="card" style={{ marginBottom: 16 }}>
                  <div className="entity-field">
                    <div className="field-label">ID</div>
                    <div className="field-value">{selected}</div>
                  </div>
                  <div className="entity-field">
                    <div className="field-label">Type</div>
                    <div className="field-value">{String(detail.type)}</div>
                  </div>
                  <div className="entity-field">
                    <div className="field-label">Status</div>
                    <div className="field-value">
                      <span className={`badge ${detail.warm ? 'badge-resolved' : 'badge-new'}`}>
                        {detail.warm ? 'warm' : 'cold'}
                      </span>
                    </div>
                  </div>
                  {detail.observation_count !== undefined && (
                    <div className="entity-field">
                      <div className="field-label">Observations</div>
                      <div className="field-value">{detail.observation_count}</div>
                    </div>
                  )}
                  {detail.first_seen && (
                    <div className="entity-field">
                      <div className="field-label">First Seen</div>
                      <div className="field-value">{new Date(detail.first_seen).toLocaleString()}</div>
                    </div>
                  )}
                  {detail.last_seen && (
                    <div className="entity-field">
                      <div className="field-label">Last Seen</div>
                      <div className="field-value">{new Date(detail.last_seen).toLocaleString()}</div>
                    </div>
                  )}
                </div>

                {/* Why this score — attribution (UI-2) */}
                {attribution && (attribution.anomalies.length > 0 || attribution.incidents.length > 0) && (
                  <div className="card" style={{ marginBottom: 16 }}>
                    <div className="section-title" data-symbol="∂">WHY THIS SCORE</div>
                    {attribution.risk && Object.keys(attribution.risk.categories).length > 0 && (
                      <div style={{ marginBottom: 12 }}>
                        {Object.entries(attribution.risk.categories)
                          .sort(([_, a], [__, b]) => b - a)
                          .map(([k, v]) => (
                            <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                              <span style={{ fontFamily: 'var(--font-display)', fontSize: 11, width: 160, color: 'var(--text-secondary)' }}>
                                {k.replace(/_/g, ' ')}
                              </span>
                              <div className="progress-bar" style={{ flex: 1 }}>
                                <div className="progress-bar-fill" style={{ width: `${Math.min(100, v)}%` }} />
                              </div>
                              <span style={{ fontFamily: 'var(--font-display)', fontSize: 11, color: 'var(--accent)' }}>{v.toFixed(0)}</span>
                            </div>
                          ))}
                      </div>
                    )}
                    {attribution.anomalies.length > 0 && (
                      <div>
                        <div className="method-label" style={{ marginTop: 0 }}>Contributing anomalies ({attribution.anomalies.length}, newest first — from last {attribution.runs_scanned} runs)</div>
                        {attribution.anomalies.slice(0, 10).map((a, i) => (
                          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                            <span className={`badge badge-${a.severity}`} style={{ fontSize: 10 }}>{a.severity}</span>
                            <span style={{ fontFamily: 'var(--font-display)', fontSize: 11, color: 'var(--accent)' }}>
                              {a.detection_method}
                            </span>
                            <span style={{ color: 'var(--text-tertiary)', fontSize: 11, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {a.details || '—'}
                            </span>
                            <span style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)' }}>
                              {a.timestamp ? new Date(a.timestamp).toLocaleDateString() : ''}
                            </span>
                          </div>
                        ))}
                        {attribution.anomalies.length > 10 && (
                          <div style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', marginTop: 4 }}>
                            + {attribution.anomalies.length - 10} more — see timeline below
                          </div>
                        )}
                      </div>
                    )}
                    {attribution.incidents.length > 0 && (
                      <div style={{ marginTop: 10 }}>
                        <div className="method-label">Open & recent incidents ({attribution.incidents.length})</div>
                        {attribution.incidents.slice(0, 5).map((inc) => (
                          <div key={inc.incident_id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', fontSize: 12 }}>
                            <span className={`badge badge-${inc.severity}`} style={{ fontSize: 10 }}>{inc.severity}</span>
                            <span style={{ fontFamily: 'var(--font-display)', fontSize: 11 }}>{inc.finding_type.replace(/_/g, ' ')}</span>
                            <span className={`badge badge-${inc.status}`} style={{ fontSize: 10, marginLeft: 'auto' }}>{inc.status.replace('_', ' ')}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Peer group — clip 5 demo surface (course plan 2026-11-17) */}
                {detail.peer_group && detail.peer_group.members && detail.peer_group.members.length > 0 && (
                  <div className="card" style={{ marginBottom: 16 }}>
                    <div className="section-title" data-symbol="∇">PEER GROUP</div>
                    <div style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', marginBottom: 8 }}>
                      Entities with similar behavior — anomaly meaning is relative to this group
                    </div>
                    <div className="tag-list">
                      {detail.peer_group.members.slice(0, 10).map((m) => (
                        <span
                          className="tag"
                          key={m}
                          style={m === selected ? { borderColor: 'var(--accent-border)', color: 'var(--accent)' } : undefined}
                        >
                          {m}
                        </span>
                      ))}
                      {detail.peer_group.members.length > 10 && (
                        <span className="tag">+{detail.peer_group.members.length - 10} more</span>
                      )}
                    </div>
                  </div>
                )}
                {detail.peer_group === null && (
                  <div className="card" style={{ marginBottom: 16 }}>
                    <div className="section-title" data-symbol="∇">PEER GROUP</div>
                    <div style={{ fontFamily: 'var(--font-display)', fontSize: 11, color: 'var(--text-tertiary)' }}>
                      No peer group yet — forms at the next re-cluster (about hourly)
                    </div>
                  </div>
                )}

                {/* Risk score */}
                {detail.risk_score && detail.risk_score.overall > 0 && (
                  <div className="card" style={{ marginBottom: 16 }}>
                    <div className="section-title" data-symbol="∂">RISK SCORE</div>
                    <div className="entity-field">
                      <div className="field-label">Overall</div>
                      <div className="field-value">
                        <span className={`badge ${detail.risk_score.overall >= 50 ? 'badge-critical' : detail.risk_score.overall >= 20 ? 'badge-high' : 'badge-medium'}`}>
                          {detail.risk_score.overall.toFixed(1)}
                        </span>
                        <span style={{ marginLeft: 8, fontFamily: 'var(--font-display)', fontSize: 11, color: 'var(--text-tertiary)' }}>
                          peak {detail.risk_score.peak.toFixed(1)} · {detail.risk_score.trend_label}
                        </span>
                      </div>
                    </div>
                    {Object.entries(detail.risk_score.categories).filter(([_, v]) => v > 0).length > 0 && (
                      <div className="entity-field">
                        <div className="field-label">Categories</div>
                        <div className="tag-list">
                          {Object.entries(detail.risk_score.categories)
                            .filter(([_, v]) => v > 0)
                            .sort(([_, a], [__, b]) => b - a)
                            .map(([k, v]) => (
                              <span className="tag" key={k}>{k.replace('_', ' ')}: {v.toFixed(0)}</span>
                            ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* EWMA values */}
                {detail.ewma && typeof detail.ewma === 'object' && (
                  <div className="card" style={{ marginBottom: 16 }}>
                    <div className="section-title" data-symbol="∂">EWMA VALUES</div>
                    <div style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', marginBottom: 8 }}>
                      Exponentially-weighted recent-activity baselines the entity detectors compare against
                    </div>
                    <pre style={{ fontFamily: 'var(--font-display)', fontSize: 12, color: 'var(--text-secondary)', whiteSpace: 'pre-wrap' }}>
                      {JSON.stringify(detail.ewma, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Typical behavior */}
                {detail.typical_ips && (
                  <div className="card" style={{ marginBottom: 16 }}>
                    <div className="section-title" data-symbol="∇">TYPICAL SOURCE IPS</div>
                    <div style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', marginBottom: 8 }}>
                      Addresses this account has historically connected from — new addresses feed the entity_new_ip detector
                    </div>
                    <div className="tag-list">
                      {(detail.typical_ips as string[]).map((ip: string) => (
                        <span className="tag" key={ip}>{ip}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* ENVIRONMENT CONTEXT card removed (UI2a item 2b): the detail endpoint's
                    environment_facts field reads the entities dict — it duplicated ENTITY CONTEXT.
                    Entity facts live in the editable card below; env-wide facts in Config → Environment. */}

                {/* Entity context editor (UI-2) — facts scoped to THIS entity */}
                <EntityContextEditor entityId={selected} />
              </div>
            ) : (
              <div className="loading">Loading detail</div>
            )
          ) : null}

          {/* Timeline */}
          {selected && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="section-title" data-symbol="∇">TIMELINE</div>
              <Timeline entityId={selected} entityType={detail?.type} />
            </div>
          )}

          {!selected && (
            <div className="empty-state">Select an entity to view details</div>
          )}
        </div>
      </div>
    </div>
  );
}

/** Per-entity context facts editor (UI-2) — the supervisor treats these
 * as ground truth about what this entity is supposed to do. */
function EntityContextEditor({ entityId }: { entityId: string }) {
  const [facts, setFacts] = useState<string[] | null>(null);
  const [newFact, setNewFact] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  // Load current facts from the environment document's entities dict
  useEffect(() => {
    setFacts(null);
    setError('');
    apiFetch<{ entities: Record<string, string[]> }>('/api/config/environment')
      .then((env) => setFacts(env.entities[entityId] || []))
      .catch(() => setFacts([]));
  }, [entityId]);

  const save = (updated: string[]) => {
    setSaving(true);
    setError('');
    apiFetch(`/api/entities/${encodeURIComponent(entityId)}/context`, {
      method: 'PUT',
      body: JSON.stringify({ facts: updated }),
    })
      .then(() => setFacts(updated))
      .catch((e) => setError(`Save failed: ${String(e)}`))
      .finally(() => setSaving(false));
  };

  if (facts === null) return null;

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div className="section-title" data-symbol="∇">ENTITY CONTEXT</div>
      <div style={{ fontFamily: 'var(--font-display)', fontSize: 10, color: 'var(--text-tertiary)', marginBottom: 8 }}>
        What is this entity supposed to do? The supervisor treats these facts as ground truth when reviewing findings
      </div>
      {error && <div className="error" style={{ marginBottom: 8 }}>{error}</div>}
      <ul className="inline-list">
        {facts.map((fact, i) => (
          <li key={i}>
            {fact}
            <button className="remove-btn" disabled={saving} onClick={() => save(facts.filter((_, j) => j !== i))}>×</button>
          </li>
        ))}
        {facts.length === 0 && (
          <li style={{ color: 'var(--text-tertiary)', fontStyle: 'italic' }}>No entity context declared</li>
        )}
      </ul>
      <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
        <input
          className="input"
          value={newFact}
          onChange={(e) => setNewFact(e.target.value)}
          placeholder={`e.g. Service account — only runs backups`}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && newFact.trim()) {
              save([...facts, newFact.trim()]);
              setNewFact('');
            }
          }}
        />
        <button
          className="btn btn-secondary btn-sm"
          disabled={saving || !newFact.trim()}
          onClick={() => {
            save([...facts, newFact.trim()]);
            setNewFact('');
          }}
        >
          Add
        </button>
      </div>
    </div>
  );
}
