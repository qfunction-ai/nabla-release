import { useDocPage, DocSectionMeta } from '../hooks/useDocPage';
import { Link } from 'react-router-dom';

const SECTIONS: DocSectionMeta[] = [
  { id: 'getting-started', title: 'Getting Started', icon: '∇' },
  { id: 'how-it-works', title: 'How It Works', icon: '∂' },
  { id: 'dashboard', title: 'Dashboard', icon: '▪' },
  { id: 'entities', title: 'Entities', icon: '∂' },
  { id: 'incidents', title: 'Incidents', icon: '∇' },
  { id: 'pipeline', title: 'Pipeline', icon: '∂' },
  { id: 'chat', title: 'Chat', icon: '∇' },
  { id: 'config', title: 'Config', icon: '∂' },
  { id: 'detection-methods', title: 'Detection Methods', icon: '∇' },
  { id: 'faq', title: 'FAQ', icon: '?' },
];

export default function Help() {
  const { activeSection, goToSection } = useDocPage('/help', SECTIONS);

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h1 className="page-title">
          <span className="accent">?</span> HELP
        </h1>
        <p className="page-subtitle">
          <span className="math">∇·docs</span> — divergence-free understanding
        </p>
      </div>

      <div className="doc-layout">
        <nav className="doc-toc">
          {SECTIONS.map((s) => (
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
          {/* ── Getting Started ─────────────────────────────── */}
          <div className="doc-section" id="doc-section-getting-started">
            <div className="doc-section-title">
              <span className="accent">∇</span> Getting Started
            </div>
            <div className="doc-section-body">
              <p>
                Nabla is a self-hosted User Entity Behavior Analytics system: it ingests SIEM logs, detects
                anomalies deterministically, correlates them into incidents, applies one focused LLM review pass,
                scores entity risk, and self-tunes its thresholds — all on local inference, no cloud dependency.
              </p>
              <h4>Prerequisites</h4>
              <ul>
                <li>Docker and Docker Compose</li>
                <li>Ollama with the <code>gemma4</code> and <code>embeddinggemma</code> models pulled</li>
                <li>The stack running: <code>docker compose up -d</code> (UI on port 3000, API on 8002)</li>
              </ul>
              <h4>First run</h4>
              <ol>
                <li>Open <code>http://localhost:3000</code> — the login screen appears.</li>
                <li>
                  On a fresh system the registration form shows: create the admin account. If{' '}
                  <code>NABLA_SETUP_TOKEN</code> is configured, the registration form requires it.
                </li>
                <li>Bootstrap runs automatically at deploy; the Dashboard shows system health and phase.</li>
                <li>
                  Run your first pipeline: Pipeline page → source <code>synthetic</code> (or connect Splunk /
                  SumoLogic in Config → Connectors) → Run Pipeline. Watch the live output stream.
                </li>
                <li>Review what was found: Incidents for confirmed threats, Entities for behavioral profiles.</li>
              </ol>
              <div className="doc-tip">
                The system starts in BASELINE phase — expect fewer findings at first (21 days of ingested
                history activates everything; backfill or force-transition to skip the wait). See{' '}
                <button className="view-all" onClick={() => goToSection('how-it-works')} style={{ background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', padding: 0, font: 'inherit' }}>
                  How It Works
                </button>{' '}
                for why.
              </div>
            </div>
          </div>

          {/* ── How It Works ────────────────────────────────── */}
          <div className="doc-section" id="doc-section-how-it-works">
            <div className="doc-section-title">
              <span className="accent">∂</span> How It Works
            </div>
            <div className="doc-section-body">
              <p>Every pipeline run executes six steps:</p>
              <ol>
                <li><strong>Ingestion</strong> — fetch logs from Splunk/SumoLogic, generate synthetic data, or parse uploaded files.</li>
                <li><strong>Anomaly detection</strong> — 29 numbered methods plus supplementary graph/temporal/exfiltration layers. Deterministic Python, no LLM.</li>
                <li><strong>Threat correlation</strong> — anomalies grouped by IP/user/process, severity-scored, enriched with MITRE ATT&amp;CK.</li>
                <li><strong>Supervisor review</strong> — the only LLM step: reads the pre-correlated findings, filters false positives, writes attack narratives. Skipped entirely when there are no findings.</li>
                <li><strong>Risk + peer groups</strong> — per-entity 0–100 risk scores, re-clustered peer groups.</li>
                <li><strong>RL update</strong> — Q-learning and a Thompson-Sampling bandit adjust 30 thresholds from the supervisor's verdicts.</li>
              </ol>
              <h4>The two-phase lifecycle</h4>
              <p>
                <strong>BASELINE</strong> (first 21 days <em>of ingested history</em>): the system learns what
                normal looks like. Detectors that need statistical or entity history are suppressed;
                signature-based methods (LOLBIN, attack scripts, renamed tools, …) run from day one. The GCN-LOF,
                provenance, temporal, and exfiltration layers also run during baseline.
              </p>
              <p>
                <strong>DETECTION</strong>: everything activates once the system has ingested 21+ days of real
                SIEM history (data span, not wall-clock — backfilling 30 days of history qualifies immediately)
                AND at least 3 warm user profiles. Operators can also force the transition explicitly
                (<code>nabla phase force-detection --confirm</code>) — an audit-logged dev/demo tool. Entity-aware versions of detectors replace their batch-level counterparts as
                profiles warm up — off-hours becomes <em>this user's</em> off-hours, spikes become <em>this user's</em> spikes.
              </p>
              <h4>The supervisor</h4>
              <p>
                One LLM agent with no tools. It reads nine shared memory blocks (findings, thresholds, ATT&amp;CK
                mapping, environment context, …) directly in its context window. Its job is interpretation, not
                detection — everything upstream is deterministic and fast.
              </p>
            </div>
          </div>

          {/* ── Dashboard ───────────────────────────────────── */}
          <div className="doc-section" id="doc-section-dashboard">
            <div className="doc-section-title">
              <span className="accent">▪</span> Dashboard
            </div>
            <div className="doc-section-body">
              <p>The landing page: system state at a glance.</p>
              <ul>
                <li><strong>System health</strong> — Letta (agent runtime), Ollama (inference), and the current phase with days remaining to detection.</li>
                <li><strong>Detection surface</strong> — incident counts, entity totals with warm-up ratios, last-run anomalies, peak risk.</li>
                <li><strong>Severity strip</strong> — incidents by critical/high/medium/low.</li>
                <li><strong>Riskiest entities</strong> — top risk scores with trend and top category.</li>
                <li><strong>Recent runs and incidents</strong> — the last five of each.</li>
              </ul>
            </div>
          </div>

          {/* ── Entities ────────────────────────────────────── */}
          <div className="doc-section" id="doc-section-entities">
            <div className="doc-section-title">
              <span className="accent">∂</span> Entities
            </div>
            <div className="doc-section-body">
              <p>
                Behavioral profiles for every user, host, and IP the system has seen. <strong>Warm</strong> entities
                (≥3 observations) have statistical baselines and get the entity-aware detectors;{' '}
                <strong>cold</strong> entities only match signature rules.
              </p>
              <ul>
                <li><strong>Risk score</strong> — 0–100, category-partitioned, time-decayed, peer-adjusted. The badge color band matches the investigation cutoff.</li>
                <li><strong>Detail panel</strong> — risk categories (which detection families contributed), EWMA baselines, typical IPs, environment context.</li>
                <li><strong>Timeline</strong> — interactive: severity-coded markers, zoom, hover tooltips, filter by event type.</li>
              </ul>
              <div className="doc-tip">
                Sort by risk score to triage; click any row for the detail panel and timeline.
              </div>
            </div>
          </div>

          {/* ── Incidents ───────────────────────────────────── */}
          <div className="doc-section" id="doc-section-incidents">
            <div className="doc-section-title">
              <span className="accent">∇</span> Incidents
            </div>
            <div className="doc-section-body">
              <p>Confirmed threats after correlation and supervisor review. The triage workflow:</p>
              <ol>
                <li>Filter by status/severity; new incidents surface first.</li>
                <li>Open the detail panel: description (supervisor's narrative), evidence JSON (the raw anomaly chain), MITRE ATT&amp;CK tags, confidence.</li>
                <li>Transition status as you work: new → investigating → resolved (or false positive). Status changes feed back into the RL system — resolved findings reinforce current thresholds; false positives push them looser.</li>
                <li>Notes append the investigation record to the incident.</li>
              </ol>
            </div>
          </div>

          {/* ── Pipeline ────────────────────────────────────── */}
          <div className="doc-section" id="doc-section-pipeline">
            <div className="doc-section-title">
              <span className="accent">∂</span> Pipeline
            </div>
            <div className="doc-section-body">
              <p>Run and monitor detection executions.</p>
              <ul>
                <li><strong>Source</strong> — synthetic (built-in generator), Splunk, SumoLogic, or file (upload handled here too).</li>
                <li><strong>Run output</strong> — live SSE stream of each step as it executes, with counts per stage.</li>
                <li><strong>History</strong> — every run with duration, anomaly/finding counts, and pass/fail. Click any run for its detail: step durations, the findings the supervisor reviewed, the run's report, and the anomalies that fed it.</li>
              <li><strong>Vocabulary</strong> — an <em>anomaly</em> is a single detector hit; a <em>finding</em> is a correlated threat group (anomalies grouped by entity, scored, ATT&amp;CK-enriched) that goes to the supervisor; findings the supervisor confirms become <em>incidents</em>. Runs with zero findings skip the LLM entirely.</li>
                <li><strong>Scheduler</strong> — interval-driven runs (Config → Schedule); off by default.</li>
              </ul>
              <div className="doc-tip">
                Uploaded files never contaminate the baseline — they are processed in-memory for ad-hoc analysis only.
              </div>
            </div>
          </div>

          {/* ── Chat ────────────────────────────────────────── */}
          <div className="doc-section" id="doc-section-chat">
            <div className="doc-section-title">
              <span className="accent">∇</span> Chat
            </div>
            <div className="doc-section-body">
              <p>
                Streamed conversation with the supervisor agent. Ask about current threats, why an incident was
                flagged, or system state — it reads the same shared blocks the pipeline writes.
              </p>
              <ul>
                <li>Reasoning is separated: the model's thinking (when it thinks) is shown apart from its answer.</li>
                <li>Responses arrive as complete chunks rather than token-by-token — current fork runtime behavior, cosmetic only.</li>
              </ul>
            </div>
          </div>

          {/* ── Config ──────────────────────────────────────── */}
          <div className="doc-section" id="doc-section-config">
            <div className="doc-section-title">
              <span className="accent">∂</span> Config
            </div>
            <div className="doc-section-body">
              <h4>Schedule</h4>
              <p>
                Interval-driven pipeline runs — identical to manual runs, including supervisor review, risk
                updates, and threshold tuning. Interval, log types, and per-run log count are editable inline;
                changes apply to the next scheduled run.
              </p>
              <h4>Connectors</h4>
              <p>
                Splunk and SumoLogic connection state and last ingestion times. Credentials are configured via
                environment variables at deployment — read-only in the UI by design (secrets never enter the
                browser-transactable config surface). Set <code>NABLA_SPLUNK_HOST/TOKEN</code> or{' '}
                <code>NABLA_SUMOLOGIC_HOST/ACCESS_ID/ACCESS_KEY</code> (plus query vars) in your{' '}
                <code>.env</code>, then redeploy with <code>docker compose up -d --build</code>.
              </p>
              <h4>Environment</h4>
              <p>
                Environment-wide truths that suppress false positives: structural facts, network ranges
                (no "impossible travel" between internal ranges), new/service/admin account lists, and benign
                patterns — each section explains what it suppresses. Per-entity context ("this service account
                only runs backups") is edited on the <strong>Entities</strong> page detail panel, where you
                meet the entity.
              </p>
              <h4>RL State</h4>
              <p>
                The 30 self-tuning thresholds with current vs default values (changed ones highlighted), and
                per-method effectiveness bars from the bandit. The system skips updates during baseline and when a
                run produces zero anomalies.
              </p>
              <h4>System</h4>
              <p>Runtime health (Letta, Ollama, data directory) plus bootstrap/teardown actions.</p>
              <h4>Export / Import</h4>
              <p>Full learned state (profiles, thresholds, model, incidents, history) as JSON. Merge combines with existing state; overwrite replaces it.</p>
            </div>
          </div>

          {/* ── Detection Methods ───────────────────────────── */}
          <div className="doc-section" id="doc-section-detection-methods">
            <div className="doc-section-title">
              <span className="accent">∇</span> Detection Methods
            </div>
            <div className="doc-section-body">
              <p>
                Nabla runs 29 numbered detection methods in four families — statistical &amp; rule-based (1–6),
                endpoint behavior (7–11), advanced endpoint (12–20), and entity-specific (21–29) — plus
                supplementary layers: four exfiltration sub-detectors, provenance-graph community detection,
                temporal attack chains, and cross-type correlation.
              </p>
              <p>
                During BASELINE phase, 17 baseline-dependent detectors are suppressed (16 methods, with EWMA/CUSUM
                counting as two); 13 signature methods run from day one, and the supplementary layers are not
                phase-gated. Entity-aware variants replace batch-level checks as profiles warm up.
              </p>
              <p>
                Every threshold is RL-tunable: the system adapts them from the supervisor's verdicts. Current live
                values are in Config → RL State.
              </p>
              <div className="doc-tip">
                <Link to="/methods" style={{ color: 'var(--accent)' }}>
                  Open the full Methods reference →
                </Link>{' '}
                — every method in depth: what it catches, how it decides, its false-positive profile, and its
                tuning knobs. Filterable by category, log type, and baseline availability.
              </div>
            </div>
          </div>

          {/* ── FAQ ─────────────────────────────────────────── */}
          <div className="doc-section" id="doc-section-faq">
            <div className="doc-section-title">
              <span className="accent">?</span> FAQ
            </div>
            <div className="doc-section-body">
              <h4>Why am I not seeing statistical findings (off-hours, z-scores, spikes)?</h4>
              <p>
                The system is in BASELINE phase — statistical detectors are intentionally held back until
                baselines exist (21+ days of ingested real-SIEM history AND ≥3 warm users). Signature methods
                and the graph layers still run. The Dashboard shows days of history collected. Ingesting
                historical data from your SIEM advances the clock by the span of that data; the phase can
                also be force-transitioned for dev/demo (<code>nabla phase force-detection --confirm</code>).
              </p>
              <h4>An entity shows "cold" — what does that mean?</h4>
              <p>
                Fewer than 3 observations so far. Cold entities only match signature rules; they get statistical
                baselines (and the entity-aware detectors) once warm.
              </p>
              <h4>I ran docker compose up -d and nothing changed after pulling new code.</h4>
              <p>
                <code>up -d</code> reuses existing images. Rebuild explicitly:{' '}
                <code>docker compose up -d --build</code> — the classic stale-image gotcha.
              </p>
              <h4>How do I read an incident's evidence?</h4>
              <p>
                Evidence is the correlation chain behind a finding: the anomaly IDs that fed it, the detection
                methods that fired, the attack sequence timestamps, and the correlation strength. "What would
                change this finding" lists the minimal changes that would alter the conclusion — findings that
                depend on a single anomaly are more fragile and warrant extra scrutiny. Expand evidence for full
                detail; raw JSON is available for power users.
              </p>
              <h4>Where did my incidents / history / profiles go after a Docker cleanup?</h4>
              <p>
                All learned state lives in Docker volumes (nabla_data, postgres_data). <code>docker compose down -v</code>{' '}
                or a volume prune deletes them permanently — that data is not in the git repo. Export state
                (Config → Export) before destructive Docker operations.
              </p>
              <h4>Chat responses arrive all at once instead of streaming</h4>
              <p>
                Observed behavior on the current runtime: responses arrive as one complete chunk. Content is
                intact; this is a streaming-granularity quirk of the agent runtime (fork-side, under
                investigation), not a data loss.
              </p>
              <h4>What is the difference between the setup token and my login?</h4>
              <p>
                The setup token (<code>NABLA_SETUP_TOKEN</code>, if configured) gates first-user registration
                only. Your username/password is the day-to-day login; sessions are 7-day secure cookies.
              </p>
              <h4>Why did the supervisor skip the LLM review on my run?</h4>
              <p>
                By design: when correlated findings are zero, the supervisor step is skipped entirely — the
                narrative would have nothing to review. The run record shows this in its step output.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
