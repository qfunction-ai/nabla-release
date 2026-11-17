import { useState, useEffect, useMemo, useCallback } from 'react';
import { apiFetch } from '../lib/api';

interface TimelineEvent {
  timestamp: string;
  event_type: string;
  severity: string;
  entity: string;
  entity_type: string;
  title: string;
  details: string;
  detection_method: string;
  categories: string[];
  risk_score: number;
  source: string;
  mitre_attack: { id: string; name: string }[];
}

interface TimelineProps {
  entityId: string;
  entityType?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff4444',
  high: '#ff8800',
  medium: '#ffcc00',
  low: '#44aaff',
};

/**
 * Interactive horizontal timeline showing security events for an entity.
 * Color-coded by severity, with hover tooltips and zoom controls.
 */
export default function Timeline({ entityId, entityType }: TimelineProps) {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);
  const [filterType, setFilterType] = useState<string>('all');

  useEffect(() => {
    if (!entityId) return;
    setLoading(true);
    const params = new URLSearchParams({ limit: '200' });
    if (entityType) params.set('entity_type', entityType);
    apiFetch<{ events: TimelineEvent[]; total: number }>(
      `/api/timeline/${encodeURIComponent(entityId)}?${params.toString()}`
    )
      .then((data) => setEvents(data.events))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [entityId, entityType]);

  const filtered = useMemo(() => {
    if (filterType === 'all') return events;
    return events.filter((e) => e.event_type === filterType);
  }, [events, filterType]);

  const sorted = useMemo(() => {
    return [...filtered].sort(
      (a, b) => a.timestamp.localeCompare(b.timestamp)
    );
  }, [filtered]);

  // Compute time range for horizontal positioning
  const timeRange = useMemo(() => {
    if (sorted.length === 0) return { min: 0, max: 1 };
    const timestamps = sorted.map((e) => new Date(e.timestamp).getTime());
    return { min: Math.min(...timestamps), max: Math.max(...timestamps) };
  }, [sorted]);

  const getPosition = useCallback(
    (timestamp: string) => {
      const t = new Date(timestamp).getTime();
      const range = timeRange.max - timeRange.min || 1;
      return ((t - timeRange.min) / range) * 100;
    },
    [timeRange]
  );

  const formatTime = (ts: string) => {
    try {
      const d = new Date(ts);
      return d.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return ts;
    }
  };

  if (!entityId) {
    return <div className="timeline-empty">Select an entity to view timeline</div>;
  }

  if (loading) {
    return <div className="timeline-loading">Loading timeline...</div>;
  }

  if (sorted.length === 0) {
    return <div className="timeline-empty">No events found for {entityId}</div>;
  }

  return (
    <div className="timeline-container">
      <div className="timeline-controls">
        <select value={filterType} onChange={(e) => setFilterType(e.target.value)}>
          <option value="all">All events</option>
          <option value="anomaly">Anomalies</option>
          <option value="incident">Incidents</option>
          <option value="risk_change">Risk changes</option>
        </select>
        <span style={{ marginLeft: 16, fontFamily: 'var(--font-display)', fontSize: 11, color: 'var(--text-secondary)' }}>
          {sorted.length} events · {formatTime(sorted[0].timestamp)} — {formatTime(sorted[sorted.length - 1].timestamp)}
        </span>
        <button
          className="btn-small"
          onClick={() => setZoom(Math.max(0.5, zoom - 0.25))}
          style={{ marginLeft: 'auto' }}
        >
          −
        </button>
        <span style={{ fontFamily: 'var(--font-display)', fontSize: 11, padding: '0 4px' }}>
          {Math.round(zoom * 100)}%
        </span>
        <button
          className="btn-small"
          onClick={() => setZoom(Math.min(4, zoom + 0.25))}
        >
          +
        </button>
      </div>

      {/* Horizontal timeline track */}
      <div
        className="timeline-track"
        style={{
          position: 'relative',
          height: 60,
          overflowX: 'auto',
          overflowY: 'hidden',
          minWidth: '100%',
        }}
      >
        <div
          style={{
            position: 'relative',
            width: `${100 * zoom}%`,
            height: '100%',
            minWidth: '100%',
          }}
        >
          {/* Center line */}
          <div
            style={{
              position: 'absolute',
              top: 28,
              left: 0,
              right: 0,
              height: 2,
              background: 'var(--border)',
            }}
          />

          {/* Event markers */}
          {sorted.map((event, i) => {
            const pos = getPosition(event.timestamp) * zoom;
            const color = SEVERITY_COLORS[event.severity] || '#888';
            return (
              <div
                key={i}
                onMouseEnter={() => setHoveredIdx(i)}
                onMouseLeave={() => setHoveredIdx(null)}
                style={{
                  position: 'absolute',
                  left: `${pos}%`,
                  top: 18,
                  transform: 'translateX(-50%)',
                  cursor: 'pointer',
                }}
              >
                <div
                  style={{
                    width: 14,
                    height: 14,
                    borderRadius: '50%',
                    background: color,
                    border: `2px solid ${hoveredIdx === i ? '#fff' : 'transparent'}`,
                    boxShadow: hoveredIdx === i ? `0 0 8px ${color}` : 'none',
                    transition: 'border 0.15s, box-shadow 0.15s',
                  }}
                />
              </div>
            );
          })}
        </div>
      </div>

      {/* Tooltip */}
      {hoveredIdx !== null && sorted[hoveredIdx] && (
        <div className="timeline-tooltip" style={{
          background: 'var(--bg-tertiary)',
          border: '1px solid var(--border)',
          borderRadius: 6,
          padding: '8px 12px',
          fontSize: 12,
          maxWidth: 320,
          marginTop: 4,
        }}>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>
            <span style={{
              display: 'inline-block',
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: SEVERITY_COLORS[sorted[hoveredIdx].severity] || '#888',
              marginRight: 6,
            }} />
            {sorted[hoveredIdx].title}
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: 11 }}>
            {formatTime(sorted[hoveredIdx].timestamp)}
          </div>
          {sorted[hoveredIdx].details && (
            <div style={{ marginTop: 4, fontSize: 11 }}>
              {sorted[hoveredIdx].details}
            </div>
          )}
          {sorted[hoveredIdx].detection_method && (
            <div style={{ marginTop: 4, fontSize: 11, fontFamily: 'var(--font-display)' }}>
              method: {sorted[hoveredIdx].detection_method}
            </div>
          )}
          {sorted[hoveredIdx].risk_score > 0 && (
            <div style={{ marginTop: 4, fontSize: 11, fontFamily: 'var(--font-display)' }}>
              risk: {sorted[hoveredIdx].risk_score.toFixed(0)}
            </div>
          )}
        </div>
      )}

      {/* Event list */}
      <div className="timeline-list" style={{ marginTop: 12, maxHeight: 300, overflowY: 'auto' }}>
        {sorted.map((event, i) => (
          <div
            key={i}
            className="timeline-row"
            onClick={() => setHoveredIdx(i)}
            style={{
              display: 'flex',
              alignItems: 'center',
              padding: '6px 8px',
              borderRadius: 4,
              background: hoveredIdx === i ? 'var(--bg-hover)' : 'transparent',
              cursor: 'pointer',
              fontSize: 12,
            }}
          >
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: SEVERITY_COLORS[event.severity] || '#888',
                marginRight: 8,
                flexShrink: 0,
              }}
            />
            <span style={{ fontFamily: 'var(--font-display)', fontSize: 11, color: 'var(--text-secondary)', width: 120, flexShrink: 0 }}>
              {formatTime(event.timestamp)}
            </span>
            <span style={{ fontWeight: 500, flex: 1 }}>{event.title}</span>
            <span className={`badge badge-${event.severity}`} style={{ fontSize: 10 }}>
              {event.severity}
            </span>
            {event.risk_score > 0 && (
              <span style={{ marginLeft: 8, fontFamily: 'var(--font-display)', fontSize: 11, color: 'var(--text-secondary)' }}>
                {event.risk_score.toFixed(0)}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
