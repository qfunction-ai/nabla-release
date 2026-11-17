import { useState, useMemo } from 'react';
import { useDocPage, DocSectionMeta } from '../hooks/useDocPage';
import {
  DETECTION_METHODS,
  SUPPLEMENTARY,
  CATEGORY_LABELS,
  MethodCategory,
} from '../lib/detectionMethods';

const CATEGORY_ORDER: MethodCategory[] = ['statistical', 'endpoint', 'advanced', 'entity'];

function MethodCard({ m }: { m: (typeof DETECTION_METHODS)[number] }) {
  return (
    <div className="method-card" id={`method-${m.number}`}>
      <div className="method-card-header">
        <span className="method-number">#{m.number}</span>
        <span className="method-name">{m.name}</span>
        <span className="tag">{m.typeLabel}</span>
        <span className="tag">{m.logs.join(', ')}</span>
        <span
          className={`badge ${m.baseline ? 'badge-resolved' : 'badge-false_positive'}`}
          title={m.baseline ? 'Signature method — runs during baseline' : 'Needs entity/statistical history — suppressed during baseline'}
        >
          {m.baseline ? 'signature' : 'suppressed in baseline'}
        </span>
      </div>
      <div className="method-body">
        <p>{m.catches}</p>
        {m.how.map((h, i) => (
          <p key={i}>{h}</p>
        ))}
        <div className="method-label">RL-tunable</div>
        {m.tunable.length === 0 ? (
          <span className="method-chip method-chip-static">static</span>
        ) : (
          m.tunable.map((t) => (
            <span key={t.name} className="method-chip">
              {t.name} = {t.default}
            </span>
          ))
        )}
        <div className="method-label">False positives</div>
        <p>{m.fp}</p>
        <div className="method-label">Code</div>
        <p>
          <code>{m.fn}</code>
        </p>
      </div>
    </div>
  );
}

export default function Methods() {
  const [category, setCategory] = useState('');
  const [logType, setLogType] = useState('');
  const [baselineOnly, setBaselineOnly] = useState('');
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return DETECTION_METHODS.filter((m) => {
      if (category && m.category !== category) return false;
      if (logType && !m.logs.some((l) => l === logType || l === 'all' || l === 'any')) return false;
      if (baselineOnly === 'active' && !m.baseline) return false;
      if (baselineOnly === 'suppressed' && m.baseline) return false;
      if (
        q &&
        ![m.name, m.typeLabel, m.fn, m.catches, ...m.how, ...m.tunable.map((t) => t.name)]
          .join(' ')
          .toLowerCase()
          .includes(q)
      )
        return false;
      return true;
    });
  }, [category, logType, baselineOnly, query]);

  const sections: DocSectionMeta[] = useMemo(
    () => [
      { id: 'overview', title: 'Overview', icon: '∇' },
      ...CATEGORY_ORDER.filter((c) => filtered.some((m) => m.category === c)).map((c) => ({
        id: `cat-${c}`,
        title: CATEGORY_LABELS[c],
        icon: '∂',
      })),
      { id: 'supplementary', title: 'Supplementary Layers', icon: '∇' },
    ],
    [filtered]
  );

  const { activeSection, goToSection } = useDocPage('/methods', sections);

  const visible = (c: MethodCategory) => filtered.some((m) => m.category === c);

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h1 className="page-title">
          <span className="accent">?</span> METHODS
        </h1>
        <p className="page-subtitle">
          <span className="math">∂f/∂x</span> — the 29 numbered detectors + supplementary layers
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
          {filtered.length} / {DETECTION_METHODS.length}
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
                Every pipeline run executes the numbered detectors below over the full batch, then layers the
                supplementary analyses (graph, temporal, exfiltration) on top. Thresholds marked with chips are
                RL-tunable — the system self-adjusts them run over run (see Config → RL State for live values).
                The RL bandit tracks 27 method arms.
              </p>
              <p>{DETECTION_METHODS.length} numbered methods in four categories. Names shown first are the README canon; the <code>type_label</code> tag is the string incidents and the timeline display.</p>
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
              {filtered
                .filter((m) => m.category === c)
                .map((m) => (
                  <MethodCard key={m.number} m={m} />
                ))}
            </div>
          ))}

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
