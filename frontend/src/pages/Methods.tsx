import { useState, useMemo, useEffect } from 'react';
import { useDocPage, DocSectionMeta } from '../hooks/useDocPage';
import { apiFetch } from '../lib/api';
import {
  DETECTION_METHODS,
  SUPPLEMENTARY,
  CATEGORY_LABELS,
  MethodCategory,
} from '../lib/detectionMethods';
import type { components } from '../types/api';

const CATEGORY_ORDER: MethodCategory[] = ['statistical', 'endpoint', 'advanced', 'entity'];

type MethodRef = components['schemas']['MethodReference'];

function proseFor(m: MethodRef) {
  // Join by emitted type string or method key — the authored prose
  // keyed its entries by typeLabel
  return DETECTION_METHODS.find(
    (p) => p.typeLabel === m.method || m.types.includes(p.typeLabel)
  );
}

function MethodCard({ m }: { m: MethodRef }) {
  const prose = proseFor(m);
  return (
    <div className="method-card" id={`method-${m.method}`}>
      <div className="method-card-header">
        <span className="method-name">{prose?.name ?? m.method}</span>
        <span className="tag" title="the detection_method key">{m.method}</span>
        {m.types.map((t) => (
          <span key={t} className="tag" title="the anomaly type string incidents display">{t}</span>
        ))}
        {prose && <span className="tag">{prose.logs.join(', ')}</span>}
        <span
          className={`badge ${m.state === 'static' ? 'badge-resolved' : 'badge-false_positive'}`}
          title={m.state === 'static' ? 'Signature method — runs during baseline' : 'Needs entity/statistical history — suppressed during baseline'}
        >
          {m.state === 'static' ? 'signature' : 'suppressed in baseline'}
        </span>
      </div>
      <div className="method-body">
        {prose ? (
          <>
            <p>{prose.catches}</p>
            {prose.how.map((h, i) => (
              <p key={i}>{h}</p>
            ))}
          </>
        ) : (
          <p style={{ color: 'var(--warning)' }}>
            No authored reference entry for this method yet — the list above is
            generated from the backend's own tables (every emitted method
            appears here even when prose is missing).
          </p>
        )}
        <div className="method-label">RL-tunable</div>
        {m.threshold === null ? (
          <span className="method-chip method-chip-static">static</span>
        ) : (
          <span className="method-chip">
            {m.threshold} = {m.default}
          </span>
        )}
        {prose && (
          <>
            <div className="method-label">False positives</div>
            <p>{prose.fp}</p>
            <div className="method-label">Code</div>
            <p>
              <code>{prose.fn}</code>
            </p>
          </>
        )}
      </div>
    </div>
  );
}

export default function Methods() {
  const [category, setCategory] = useState('');
  const [logType, setLogType] = useState('');
  const [baselineOnly, setBaselineOnly] = useState('');
  const [query, setQuery] = useState('');
  const [methods, setMethods] = useState<MethodRef[] | null>(null);

  // L11: the method list comes from the backend's own tables — this
  // page renders the ground truth and joins authored prose by key.
  useEffect(() => {
    apiFetch<components['schemas']['MethodsResponse']>('/api/system/methods')
      .then((d) => setMethods(d.methods))
      .catch(() => setMethods([]));
  }, []);

  const filtered = useMemo(() => {
    if (!methods) return [];
    const q = query.trim().toLowerCase();
    return methods.filter((m) => {
      const prose = proseFor(m);
      if (category && prose?.category !== category) return false;
      if (logType && !(prose?.logs.some((l) => l === logType || l === 'all' || l === 'any'))) return false;
      if (baselineOnly === 'active' && m.state === 'static') return false;
      if (baselineOnly === 'suppressed' && m.state !== 'static') return false;
      if (
        q &&
        ![m.method, ...m.types, prose?.name ?? '', prose?.fn ?? '', prose?.catches ?? '', ...(prose?.how ?? [])]
          .join(' ')
          .toLowerCase()
          .includes(q)
      )
        return false;
      return true;
    });
  }, [methods, category, logType, baselineOnly, query]);

  // Authored prose entries the backend no longer emits — surfaced, not
  // silently rendered as if current (the L11 slash-triple lands here)
  const staleProse = useMemo(() => {
    if (!methods) return [];
    const served = new Set<string>();
    for (const m of methods) {
      served.add(m.method);
      m.types.forEach((t) => served.add(t));
    }
    return DETECTION_METHODS.filter((p) => !served.has(p.typeLabel));
  }, [methods]);

  const sections: DocSectionMeta[] = useMemo(
    () => [
      { id: 'overview', title: 'Overview', icon: '∇' },
      ...CATEGORY_ORDER.filter((c) => filtered.some((m) => proseFor(m)?.category === c)).map((c) => ({
        id: `cat-${c}`,
        title: CATEGORY_LABELS[c],
        icon: '∂',
      })),
      { id: 'supplementary', title: 'Supplementary Layers', icon: '∇' },
    ],
    [filtered]
  );

  const { activeSection, goToSection } = useDocPage('/methods', sections);

  const visible = (c: MethodCategory) =>
    filtered.some((m) => proseFor(m)?.category === c);
  const inCategory = (c: MethodCategory) =>
    filtered.filter((m) => proseFor(m)?.category === c);
  const uncatalogued = filtered.filter((m) => !proseFor(m));

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h1 className="page-title">
          <span className="accent">?</span> METHODS
        </h1>
        <p className="page-subtitle">
          <span className="math">∂f/∂x</span> — every emitted detector + supplementary layers
        </p>
      </div>

      <div className="method-filter-bar">
        <select className="input" value={category} onChange={(e) => setCategory(e.target.value)} style={{ maxWidth: 220 }}>
          <option value="">All categories</option>
          {CATEGORY_ORDER.map((c) => (
            <option key={c} value={c}>
              {CATEGORY_LABELS[c]}
            </option>
          ))}
        </select>
        <select className="input" value={logType} onChange={(e) => setLogType(e.target.value)} style={{ maxWidth: 140 }}>
          <option value="">All log types</option>
          <option value="auth">auth</option>
          <option value="network">network</option>
          <option value="dns">dns</option>
          <option value="endpoint">endpoint</option>
        </select>
        <select className="input" value={baselineOnly} onChange={(e) => setBaselineOnly(e.target.value)} style={{ maxWidth: 200 }}>
          <option value="">Baseline: any</option>
          <option value="active">Runs in baseline</option>
          <option value="suppressed">Suppressed in baseline</option>
        </select>
        <input
          className="input"
          placeholder="Search methods…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ maxWidth: 260 }}
        />
        <span style={{ fontFamily: 'var(--font-display)', fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
          {filtered.length} / {methods?.length ?? 0}
        </span>
      </div>

      <div className="doc-layout">
        <nav className="doc-toc">
          {sections.map((s) => (
            <button
              key={s.id}
              className={`doc-toc-link${activeSection === s.id ? ' doc-toc-active' : ''}`}
              onClick={() => goToSection(s.id)}
            >
              <span className="doc-toc-icon">{s.icon}</span>
              {s.title}
            </button>
          ))}
        </nav>

        <div className="doc-content">
          <div className="doc-section" id="doc-section-overview">
            <div className="doc-section-title">
              <span className="accent">∇</span> Overview
            </div>
            <div className="doc-section-body">
              <p>
                Every pipeline run executes the detectors below over the full batch, then layers the
                supplementary analyses (graph, temporal, exfiltration) on top. Thresholds marked with chips are
                RL-tunable — the system self-adjusts them run over run (see Config → Calibration for live values).
              </p>
              <p>{methods?.length ?? '—'} emitted methods. Names shown first are the README canon; the <code>detection_method</code> tag is the method key and the next tag is the type string incidents and the timeline display.</p>
              <p>
                The list is generated from the backend's own tables (bandit arms + emitted
                methods + the R7 classification) — it cannot drift from the code the way a
                hand-copied table can.
              </p>
              <div className="doc-tip">
                During BASELINE phase, detectors needing statistical or entity history are suppressed — see each
                card's baseline badge. The RL system makes no threshold updates during baseline.
              </div>
            </div>
          </div>

          {CATEGORY_ORDER.filter(visible).map((c) => (
            <div className="doc-section" key={c} id={`doc-section-cat-${c}`}>
              <div className="doc-section-title">
                <span className="accent">∂</span> {CATEGORY_LABELS[c]}
              </div>
              {inCategory(c).map((m) => (
                <MethodCard key={m.method} m={m} />
              ))}
            </div>
          ))}

          {uncatalogued.length > 0 && (
            <div className="doc-section" id="doc-section-uncatalogued">
              <div className="doc-section-title">
                <span className="accent">∂</span> Emitted — No Reference Entry
              </div>
              <div className="doc-section-body">
                <p>
                  These methods are emitted by the pipeline and tracked by the calibration
                  system, but have no authored reference entry yet. They are listed because
                  the method list is generated — hiding emitted methods is how a stale
                  copy stays stale.
                </p>
              </div>
              {uncatalogued.map((m) => (
                <MethodCard key={m.method} m={m} />
              ))}
            </div>
          )}

          {staleProse.length > 0 && (
            <div className="doc-section" id="doc-section-stale">
              <div className="doc-section-title">
                <span className="accent">∂</span> Stale Reference Entries
              </div>
              <div className="doc-section-body">
                <p>
                  Authored entries that match no emitted method under any name — kept
                  visible rather than silently rendered as current:
                </p>
                {staleProse.map((p) => (
                  <p key={p.typeLabel} style={{ color: 'var(--warning)' }}>
                    <code>{p.typeLabel}</code> — {p.name}
                  </p>
                ))}
              </div>
            </div>
          )}

          <div className="doc-section" id="doc-section-supplementary">
            <div className="doc-section-title">
              <span className="accent">∇</span> Supplementary Layers
            </div>
            <div className="doc-section-body">
              <p>
                Seven additional analysis layers that are not part of the 29 numbered methods. The four exfiltration
                sub-detectors exist in code only (not in the README table); all four emit type{' '}
                <code>data_exfiltration</code>.
              </p>
            </div>
            {SUPPLEMENTARY.map((s) => (
              <div className="method-card" key={s.name}>
                <div className="method-card-header">
                  <span className="method-name">{s.name}</span>
                  {s.attck?.map((a) => (
                    <span key={a} className="tag" style={{ borderColor: 'var(--danger-border)', color: 'var(--danger)' }}>
                      {a}
                    </span>
                  ))}
                </div>
                <div className="method-body">
                  <p>{s.summary}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
