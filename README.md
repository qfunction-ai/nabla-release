# Nabla

User Entity Behavior Analytics (UEBA) system built on the [Letta](https://github.com/letta-ai/letta) API. Self-hosted, local inference via Ollama.

## Architecture

A single LLM supervisor agent plus deterministic pipeline stages, coordinated through shared memory blocks:

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Ingestion   │────▶│ Anomaly Detection │────▶│    Correlation   │
│  (function)  │     │   (function)      │     │   (function)    │
└─────────────┘     └──────────────────┘     └─────────────────┘
                                                      │
                                                      ▼
                                              ┌──────────────┐
                                              │  Supervisor   │
                                              │  (LLM review) │
                                              └──────────────┘
                                                      │
                                                      ▼
                                              ┌──────────────┐
                                              │ Risk + RL     │
                                              │  (function)   │
                                              └──────────────┘
```

- **Ingestion** — deterministic Python function, no LLM. Fetches from SIEM (Splunk or SumoLogic) or parses uploaded files
- **Anomaly Detection** — deterministic Python function (`detection.py`), 29 methods (20 base + 9 entity-specific), no context window limit
- **Threat Correlation** — deterministic Python function (`correlation.py`), replaces LLM threat agent. 9.4x faster than the previous agent-based approach
- **Supervisor** — the only agent: single LLM inference step. Reads blocks directly, no tools needed
- **Risk + Calibration** — deterministic entity risk scoring, peer-group re-clustering, and label-driven threshold calibration (the retired Q-learning adapter is documented history; see `nabla/rl/calibration.py`)

The deterministic stages write, and the supervisor reads, **nine shared memory blocks**: `ingestion_status`, `anomaly_queue`, `threat_findings`, `rl_thresholds`, `graph_context`, `attack_mapping`, `lolbin_db`, `environment_context`, `system_phase`.

## Pipeline Steps

The pipeline runs 8 steps per execution:

| Step | Stage | Description |
|------|-------|-------------|
| 1 | Ingestion | Fetch logs from SIEM or parse uploaded files |
| 2 | Detection | Run 29 anomaly detection methods on full dataset |
| 2b | GCN-LOF | Graph Convolutional Network + Local Outlier Factor (method 12) |
| 2c | Provenance | Build provenance graph, Louvain community detection, flag anomalous communities |
| 2d | Temporal | Detect temporal attack chains (recon→exploit→persist→exfil) |
| 3 | Correlation | Deterministic cross-type correlation, severity assessment, timeline construction |
| 4 | Supervisor | Single LLM inference to review findings and generate narrative |
| 5 | RL Update | Update Q-learning thresholds and Thompson Sampling bandit from supervisor review |

> **Note:** the GCN-LOF step (2b) requires scipy/scikit-learn. If those imports fail, the step is **silently skipped** — the pipeline runs with one fewer detector and no error. Verify with:
> `python -c "import scipy.sparse; from sklearn.neighbors import LocalOutlierFactor"`

## Detection Methods

Twenty-nine methods run on each pipeline execution — 20 base + 9 entity-specific — plus supplementary graph, temporal, and exfiltration (4 sub-detectors) modules; the RL bandit tracks 27 method arms:

### Statistical & Rule-Based (1–6)

| # | Method | What it catches | Log type |
|---|---|---|---|
| 1 | Pre-flagged | Events explicitly marked as anomalous in source data | All |
| 2 | Z-score spike | Metrics > 2σ from baseline | All |
| 3 | Brute force | > 50% failed login attempts | Auth |
| 4 | Off-hours activity | Events between 22:00–06:00 UTC | Auth |
| 5 | Impossible travel | 3+ unique source IPs for the same user | Auth |
| 6 | Activity spike | > 3x mean event volume | All |

### Endpoint Behavior (7–11)

| # | Method | What it catches | Log type |
|---|---|---|---|
| 7 | LOLBIN abuse | Known-abusable binaries with suspicious command patterns | Endpoint |
| 8 | Suspicious parent-child | Office apps spawning shells/LOLBINs (e.g., winword→cmd) | Endpoint |
| 9 | Critical host escalation | sudo/runas/UAC bypass on domain controllers or critical servers | Endpoint |
| 10 | Unusual process per host | Processes on a host not seen in historical baseline | Endpoint |
| 11 | Rapid action sequence | Create→execute→delete on same user/host within a short window | Endpoint |

### Advanced Endpoint (12–20)

| # | Method | What it catches | Log type |
|---|---|---|---|
| 12 | GCN-LOF | Graph Convolutional Network + Local Outlier Factor hybrid | All |
| 13 | Known attack script | STIX-derived tool/malware name matching (1100+ names) | Endpoint |
| 14 | Renamed attack tool | Legitimate binary renamed to match known attack tool | Endpoint |
| 15 | Suspicious file path | Processes running from unusual locations (PerfLogs, Public, Temp) | Endpoint |
| 16 | Enumeration behavior | Process spawning many children, accessing sensitive paths, or running enum commands | Endpoint |
| 17 | Integrity anomaly | High-integrity process spawned by non-system parent | Endpoint |
| 18 | Registry abuse | Suspicious registry modifications (autorun, persistence, credential access) | Endpoint |
| 19 | Network anomaly | Unusual outbound connections, C2 framework indicators | Endpoint |
| 20 | EWMA/CUSUM drift | Exponential weighted moving average and cumulative sum control charts | All |

### Entity-Specific (21–29)

| # | Method | What it catches | Log type |
|---|---|---|---|
| 21 | Entity z-score | Per-entity metrics > 2σ from entity baseline | All |
| 22 | Entity auth failure | Per-entity auth failure ratio > entity baseline | Auth |
| 23 | Entity off-hours | Per-entity off-hours count > entity baseline | Auth |
| 24 | Entity new IP | IP not in entity's typical set | Auth |
| 25 | Entity activity spike | Per-entity event volume > 3x entity baseline | All |
| 26 | Entity new process | Process not in entity's historical set | Endpoint |
| 27 | Entity unusual process | Per-entity process anomaly score > threshold | Endpoint |
| 28 | Entity behavior composite | Combined anomaly score across entity dimensions | All |
| 29 | Entity host composite | Combined anomaly score across host dimensions | All |

### Graph & Relational (supplementary)

| Method | What it catches | Log type |
|---|---|---|
| Provenance community | Louvain community detection flags high-density anomalous clusters | Endpoint |
| Temporal chain | Multi-phase attack sequences (recon→exploit→persist→exfil) | All |
| Cross-type correlation | Events linked by IP, user, and 30-minute windows across log types | All |

The LOLBIN database is populated from [LOLBAS](https://lolbas-project.github.io/) (Windows) and [GTFOBins](https://gtfobins.org/) (Unix) APIs at bootstrap, providing real MITRE ATT&CK technique IDs and detection rule references.

STIX-derived tool detection (`attack.py`) downloads the MITRE ATT&CK STIX bundle, extracts 1100+ tool/malware names, and uses word-boundary regex matching to detect known attack tools in process names and command lines.

Endpoint detection methods use SIEM-resilient field fallback — they check canonical field names first, then fall back to Sysmon (`Image`, `CommandLine`, `ParentImage`, `Computer`) and auditd equivalents.

## Entity Baselines

Per-entity behavioral profiles (`baselines.py`) track typical activity patterns across pipeline runs:

- **UserProfile** — typical IPs, typical hours, auth failure ratio, typical processes
- **HostProfile** — typical processes, typical users, typical integrity levels
- **IPProfile** — typical users, typical hosts

New entities go through a warm-up period (default 3 observations) before their baselines influence detection. During warm-up, detection falls back to batch-level statistics. Profiles persist to `/data/entity_profiles.json`.

## Baseline Learning Mode

Nabla operates in two phases (`system_state.py`):

- **Baseline** — signature-based detection only. 17 baseline-dependent methods (z-score, off-hours, activity spike, etc.) are suppressed to avoid false positives from incomplete baselines. Supervisor LLM is skipped when no findings exist.
- **Detection** — all methods active. Supervisor reviews findings and generates incident reports.

Transition from baseline → detection requires:
1. First SIEM ingestion ≥ 21 days ago
2. ≥ 3 users with warm-up complete

Once in detection phase, the system never returns to baseline.

## Explainability

Three-layer explainability for each finding:

1. **Evidence traces** — structured evidence extracted from anomaly fields (rule, threshold, actual value, margin)
2. **Rule counterfactuals** — removes one anomaly type at a time, re-runs severity assessment, reports impact
3. **Graph counterfactuals** — removes one edge at a time from provenance communities, re-runs Louvain, checks if community splits or density drops

Evidence is appended to the `threat_findings` block before supervisor review.

## Provenance Graph

The provenance analyzer (`provenance.py`) builds a directed graph from endpoint events:

- **Node types**: process, file, ip, user, host, registry, domain
- **Edge types**: parent_of, executed_on, created, read, wrote, connected_to, logged_in_as, queried
- **Benign pruning**: removes system processes (explorer, svchost, etc.) unless they have anomalous neighbors
- **Louvain community detection**: pure Python implementation, flags communities with anomaly density > 0.3 or type diversity ≥ 3 with density > 0.1

## Adaptive Thresholds (RL)

Thirty thresholds self-tune via reinforcement learning:

| Threshold | Range | Default | Controls |
|---|---|---|---|
| `z_score_sigma` | 2.0–4.0 | 2.0 | Standard deviations for spike detection |
| `brute_force_ratio` | 0.3–0.8 | 0.5 | Failed login ratio threshold |
| `off_hours_count` | 2–8 | 3 | Minimum events during off-hours |
| `multi_ip_count` | 2–6 | 3 | Minimum unique IPs for impossible travel |
| `spike_multiplier` | 2.0–6.0 | 3.0 | Multiplier over mean for activity spikes |
| `lolbin_sensitivity` | 0.3–1.0 | 0.7 | LOLBIN detection strictness |
| `parent_child_sensitivity` | 0.3–1.0 | 0.7 | Parent-child strictness |
| `critical_host_sensitivity` | 0.3–1.0 | 0.7 | Escalation detection strictness |
| `unusual_process_sensitivity` | 0.3–1.0 | 0.5 | Unusual process strictness |
| `action_sequence_window_minutes` | 5–120 | 30 | Time window for rapid create→execute→delete sequences |
| `gcn_lof_alpha` | 0.3–0.7 | 0.5 | LOF weight in GCN-LOF combined score |
| `gcn_lof_threshold` | 0.5–0.95 | 0.75 | Cutoff for GCN-LOF anomaly flagging |
| `provenance_anomaly_density` | 0.1–0.5 | 0.3 | Community density threshold for flagging |
| `provenance_min_community_size` | 2–10 | 3 | Minimum nodes for a flagged community |
| `temporal_chain_window_minutes` | 5–120 | 30 | Time window for temporal chain detection |
| `temporal_min_chain_length` | 2–6 | 3 | Minimum phases in a temporal chain |
| `suspicious_path_sensitivity` | 0.3–1.0 | 0.7 | Suspicious file path strictness |
| `integrity_anomaly_sensitivity` | 0.3–1.0 | 0.7 | Integrity anomaly strictness |
| `registry_abuse_sensitivity` | 0.3–1.0 | 0.7 | Registry abuse strictness |
| `network_anomaly_sensitivity` | 0.3–1.0 | 0.7 | Network anomaly strictness |
| `ewma_sensitivity` | 0.3–1.0 | 0.7 | EWMA drift strictness |
| `cusum_sensitivity` | 0.3–1.0 | 0.7 | CUSUM shift strictness |
| `enumeration_sensitivity` | 0.3–1.0 | 0.7 | Enumeration behavior strictness |
| `entity_event_count_sigma` | 1.0–4.0 | 2.0 | Entity z-score threshold |
| `entity_new_ip_threshold` | 1–5 | 2 | New IPs per entity before flagging |
| `entity_auth_failure_sigma` | 1.0–4.0 | 2.0 | Entity auth failure z-score |
| `entity_new_process_threshold` | 1–10 | 3 | New processes per entity before flagging |
| `entity_new_user_threshold` | 1–5 | 1 | New users per entity before flagging |
| `entity_behavior_composite_threshold` | 0.1–1.0 | 0.6 | Entity behavior composite score cutoff |
| `entity_host_composite_threshold` | 0.1–1.0 | 0.6 | Entity host composite score cutoff |

- **Q-learning agent** — Tabular Q-learning over discretized state (threshold bin, precision bucket, volume bucket). Epsilon-greedy (ε=0.1), α=0.1, γ=0.3. Adjusts all 30 thresholds per cycle.
- **Thompson Sampling bandit** — Beta(α,β) posterior per detection method (27 methods). Tracks which methods produce confirmed vs. dismissed findings.
- **Reward signal** — Confirmed findings: +10. Dismissed: -2. Volume penalty: -0.1/alert. Precision = confirmed / total.

Updated thresholds are written to the `rl_thresholds` shared block, which the detection function reads at detection time.

## SIEM Connectors

### Splunk

Uses httpx directly (not splunk-sdk) to avoid heavy dependencies. Auth: bearer token (preferred) or username/password (session key). Supports SPL search strings per log type with optional `{watchlist_clause}` injection.

### SumoLogic

Uses the v2 Search Job API (available on all account tiers; v1 requires Enterprise). Auth: accessId + accessKey (HTTP Basic Auth). Flow:

1. `POST /v2/search/jobs` → get job ID
2. Poll `GET /v2/search/jobs/{id}` → wait for DONE GATHERING RESULTS
3. `GET /v2/search/jobs/{id}/messages` → page results
4. `DELETE /v2/search/jobs/{id}` → clean up

Includes Windows Security Event normalizer (maps 19 event IDs to canonical actions) and Linux Sysmon XML normalizer.

## File Upload

Upload log files for ad-hoc analysis without a SIEM:

```bash
# CSV with auto-detected columns
nabla run --source file --file logs.csv --log-type auth --format csv

# JSON with column mapping
nabla run --source file --file events.json --log-type endpoint --format json \
  --map user=UserName host=HostName process=ProcessName

# Sysmon XML
nabla run --source file --file sysmon.xml --log-type endpoint --format xml
```

Supported formats: CSV, JSON, JSONL, XML/Sysmon, syslog text. Column names are auto-detected with optional `--map` overrides. File-sourced logs are processed in-memory only — they do not update persistent ingestion state, keeping ad-hoc analysis separate from scheduled SIEM ingestion.

## Incidents

Each finding from a pipeline run becomes an incident with a lifecycle: `new` → `investigating` → `resolved` / `false_positive`. Incidents persist to `/data/incidents.json` and survive across pipeline runs. Deduplication prevents the same (entity, finding_type) from creating duplicate active incidents on repeated runs.

## Export / Import

Bundle all durable state into a single JSON for portability across teardown/bootstrap cycles:

```bash
# Export state
nabla export -o /data/nabla-export.json

# Import (overwrite existing)
nabla import -i /data/nabla-export.json

# Import (merge with existing)
nabla import -i /data/nabla-export.json --merge
```

Eight state files are bundled: entity_profiles, rl_state, gcn_lof_model, environment_context, watchlists, runs, ingestion_state, system_state. Merge mode deep-merges dicts, deduplicates runs by run_id, and keeps latest ingestion timestamps.

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- [Ollama](https://ollama.ai) running locally with models pulled:
  ```bash
  ollama pull gemma4:26b
  ollama pull embeddinggemma
  ```

  **Embedding model.** `embeddinggemma:latest` is the only published tag;
  `latest` is stable here — at pin time (2026-11-19) local and registry
  digests matched (`85462619ee72...`). Re-verify after pulling:

  ```bash
  ollama show embeddinggemma   # digest should start with 85462619ee72
  ```

  **Model pin.** The shipped default LLM is `gemma4:26b` (MoE, 25.2B total /
  3.8B active per token). Ollama tags are mutable — at pin time (2026-11-19)
  the registry manifest for `26b` was
  `001e5dafc3c77684c2307ebc6ab8e336e10c9b18eca52acf547d72fc83c3ca8c`.
  This tag requires **Ollama 0.34.1+** (renderer packaging): the pull is
  per-tensor sharded and the client picks a quantization per platform —
  macOS observed `48eb98ec778c` (nvfp4 renderer build). Verify after pulling:

  ```bash
  ollama show gemma4:26b    # architecture gemma4, parameters 26.2B
  ```

  The client-side ID varies by platform (the renderer selects the tensor
  build), so verify the architecture/parameter lines above; the registry
  manifest digest is the stable cross-platform identity. Hardware: 16 GB+
  VRAM recommended; on 8-12 GB cards Ollama (0.30+) automatically keeps the
  MoE expert weights in system RAM (leave `num_gpu` unset — any explicit value
  disables the expert-aware placement) at reduced generation speed, so 32 GB+
  system RAM is recommended in that case. On Ampere cards (RTX 30xx) expect
  the GGUF Q4_K_M path rather than nvfp4 (Blackwell-only format).

### Setup

```bash
# Clone
git clone git@github.com:qfunction-ai/delta.git
cd nabla

# Configure environment
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD and NABLA_LETTA_API_KEY (generate with):
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
openssl rand -base64 32   # NABLA_LETTA_API_KEY (LettaLocal server password)

# Start services
docker compose up -d

# Wait for Letta to be healthy
docker compose logs -f letta  # until "Uvicorn running"
```

### Bootstrap

```bash
# Create the supervisor agent and shared blocks
docker compose exec nabla nabla bootstrap

# Verify
docker compose exec nabla nabla status
```

### Run a Pipeline

```bash
# Single run with all log types
docker compose exec nabla nabla run

# Specific log type and count
docker compose exec nabla nabla run --log-type auth --log-count 100

# Upload a log file
docker compose exec nabla nabla run --source file --file logs.csv --log-type auth --format csv

# Schedule recurring runs (every 5 minutes)
docker compose exec nabla nabla schedule --interval 5 --log-type all --log-count 50
```

### Chat with the Supervisor

```bash
docker compose exec nabla nabla chat
```

### Teardown

```bash
docker compose exec nabla nabla teardown
```

## CLI Reference

| Command | Description |
|---|---|
| `nabla bootstrap` | Create the supervisor agent and shared blocks |
| `nabla run` | Execute the full UEBA pipeline |
| `nabla status` | Check agent health, system state, and baseline phase |
| `nabla history` | Show pipeline run history |
| `nabla chat` | Interactive chat with the Supervisor agent |
| `nabla schedule` | Start or stop scheduled pipeline runs |
| `nabla teardown` | Delete the supervisor agent and shared blocks |
| `nabla check-ollama` | Check Ollama connectivity and recommend config |
| `nabla rl-status` | Show RL threshold state and method effectiveness |
| `nabla risk` | List top-risk entities against the investigation cutoff |
| `nabla eval` | Run supervisor evaluation scenarios |
| `nabla watchlist` | Manage watchlists for targeted SIEM ingestion |
| `nabla export` | Export all state to a single JSON file |
| `nabla import` | Import state from a JSON file (overwrite or merge) |
| `nabla incidents` | Manage incidents (list, show, update, stats) |
| `nabla web` | Start the web server (or set `NABLA_WEB_ENABLED=1`) |

### Run options

```
nabla run --log-type [auth|network|dns|endpoint|all] --log-count N
nabla run --source file --file PATH --format [csv|json|jsonl|xml|text] --log-type TYPE --map canonical=raw_col
nabla schedule --interval MINUTES --log-type TYPE --log-count N --stop
```

### Watchlist commands

```
nabla watchlist list                    # Show all watchlist groups
nabla watchlist add GROUP ENTITY        # Add entity to a group
nabla watchlist remove GROUP ENTITY     # Remove entity from a group
```

### Incident commands

```
nabla incidents list [--status new]      # List incidents (optionally filtered)
nabla incidents show ID                  # Show incident details
nabla incidents update ID [--status STATUS] [--notes NOTES]  # Update incident
nabla incidents stats                    # Show incident statistics
```

## Configuration

All settings use the `NABLA_` env prefix. Key variables:

| Variable | Default | Description |
|---|---|---|
| `NABLA_LETTA_BASE_URL` | `http://localhost:8284` | Letta server URL |
| `NABLA_LLM_MODEL` | `ollama/gemma4:26b` | LLM model handle |
| `NABLA_EMBEDDING_MODEL` | `embeddinggemma:latest` | Embedding model (no `ollama/` prefix) |
| `NABLA_EMBEDDING_ENDPOINT` | `http://host.docker.internal:11434/v1` | Embedding endpoint (from Letta container) |
| `NABLA_TOOL_LETTA_URL` | _(empty)_ | Override URL for tools inside Letta |
| `NABLA_DATA_DIR` | `/data` | Persistent state directory |
| `NABLA_SCHEDULE_ENABLED` | `0` | Enable scheduler on container start |
| `NABLA_SCHEDULE_INTERVAL_MINUTES` | `5` | Minutes between scheduled runs |
| `NABLA_SCHEDULE_LOG_TYPES` | `all` | Log types for scheduled runs |
| `NABLA_SCHEDULE_LOG_COUNT` | `50` | Log count for scheduled runs |
| `NABLA_MAX_FILE_ENTRIES` | `100000` | Maximum entries when parsing uploaded files |
| `NABLA_BASELINE_DAYS` | `21` | Days before baseline→detection transition |
| `NABLA_NEW_ACCOUNT_GRACE_DAYS` | `30` | Days new accounts are exempt from certain detection |
| `NABLA_LOLBAS_SHA256` | _(empty)_ | Pinned SHA-256 for LOLBAS download (empty = warn only) |
| `NABLA_GTFOBINS_SHA256` | _(empty)_ | Pinned SHA-256 for GTFOBins download (empty = warn only) |
| `NABLA_SETUP_TOKEN` | _(empty)_ | API auth token (empty = open access, dev mode) |
| `NABLA_WEB_ENABLED` | `0` | Enable web server on container start |
| `NABLA_WEB_HOST` | `0.0.0.0` | Web server bind host |
| `NABLA_WEB_PORT` | `8000` | Web server bind port |
| `POSTGRES_PASSWORD` | _(required)_ | PostgreSQL password |
| `NABLA_LETTA_API_KEY` | _(required)_ | LettaLocal API key — must equal the Letta server password (`openssl rand -base64 32`) |

### vLLM upgrade path

For production-scale deployments, Nabla can run its LLM through vLLM instead of
Ollama — a config change only, on existing settings: set `NABLA_LLM_MODEL` to a
`vllm/...` provider-prefixed handle and point `NABLA_EMBEDDING_ENDPOINT` at the
vLLM OpenAI-compatible endpoint. Bootstrap strips the `ollama/` prefix only
when present, so no Ollama-specific assumptions break. This path is exercised
by configuration only — it is not part of the course-tested surface.

### Splunk connector

| Variable | Default | Description |
|---|---|---|
| `NABLA_SPLUNK_HOST` | _(empty)_ | Splunk URL (e.g. `https://splunk.example.com:8089`) |
| `NABLA_SPLUNK_TOKEN` | _(empty)_ | Bearer token (preferred auth) |
| `NABLA_SPLUNK_USERNAME` | _(empty)_ | Username/password fallback |
| `NABLA_SPLUNK_PASSWORD` | _(empty)_ | Password for username auth |
| `NABLA_SPLUNK_VALIDATE_URL` | `true` | SSRF validation on host URL |
| `NABLA_SPLUNK_VERIFY_SSL` | `true` | TLS verification |

### SumoLogic connector

| Variable | Default | Description |
|---|---|---|
| `NABLA_SUMOLOGIC_HOST` | _(empty)_ | SumoLogic API URL (e.g. `https://api.sumologic.com/api`) |
| `NABLA_SUMOLOGIC_ACCESS_ID` | _(empty)_ | Access ID for Basic Auth |
| `NABLA_SUMOLOGIC_ACCESS_KEY` | _(empty)_ | Access Key for Basic Auth |
| `NABLA_SUMOLOGIC_VALIDATE_URL` | `true` | SSRF validation on host URL |
| `NABLA_SUMOLOGIC_VERIFY_SSL` | `true` | TLS verification |
| `NABLA_SUMOLOGIC_MAX_RESULTS` | `10000` | Max results per search |
| `NABLA_SUMOLOGIC_POLL_INTERVAL` | `5.0` | Seconds between status polls |
| `NABLA_SUMOLOGIC_POLL_TIMEOUT` | `300.0` | Max seconds to wait for job completion |

## Web UI

React 19 + TypeScript + Vite frontend served by nginx. Dark navy theme (`#0a0e17`) with monospace accents, IBM Plex Sans + JetBrains Mono fonts. Color as signal: red (critical), amber (high), green (resolved).

### Pages

| Page | Description |
|---|---|
| **Dashboard** | System health, entity counts, incident summary, recent pipeline runs |
| **Entities** | Entity list + detail view with EWMA charts, IPs, environment facts |
| **Pipeline** | Trigger runs, real-time SSE streaming, run history |
| **Incidents** | Incident list + detail, status updates, notes |
| **Chat** | SSE streaming conversation with the supervisor agent |
| **Environment** | Three-section inline editor (facts, entity context, mutable state) |
| **Config** | Five tabs: schedule, connectors, RL thresholds, system, export/import |

### Authentication

Token-based via `NABLA_SETUP_TOKEN`. If set, all API endpoints require `Authorization: Bearer <token>`. If empty, the API is open (dev mode). The frontend shows a setup token field on first access. Token comparison uses `hmac.compare_digest()` for timing safety.

## Docker Services

| Service | Image | Port | Purpose |
|---|---|---|---|
| `letta` | `ghcr.io/qfunction-ai/letta-local:0.16.38` | `127.0.0.1:8284` | Agent runtime (QFunction fork — Ollama reasoning-model detection, local-model hardening; canary disabled locally via `LETTA_CANARY_ENABLED=false`) |
| `postgres` | `pgvector/pgvector:pg16` | `127.0.0.1:5433` | Agent memory + metadata |
| `nabla` | Built from `Dockerfile` | `127.0.0.1:8002` | CLI + scheduler + API server |
| `frontend` | Built from `frontend/Dockerfile` | `127.0.0.1:3000` | Web UI (nginx reverse proxy) |

All ports bound to localhost only. Named volumes for `postgres_data`, `letta_data`, and `nabla_data`.

## Testing

```bash
# Unit tests (1254 tests)
python -m pytest tests/ -v -k "not integration" --ignore=tests/test_gcn_lof.py

# Integration tests (requires running Letta + Postgres, 22 tests)
NABLA_INTEGRATION=1 python -m pytest tests/ -v -k "integration" --ignore=tests/test_gcn_lof.py

# API tests (138 tests)
python -m pytest tests/test_api_*.py tests/test_api_security.py -v

# Security tests
python -m pytest tests/test_security_hardening.py tests/test_ssrf.py -v
```

Test coverage: attack mapping, baselines, blocks, config, connectors, correlation, detection (all 29 methods + entity-specific), endpoint detection, explainability, export/import, GCN-LOF, graph context, history, incidents, ingestion, ingestion state, logging, lolbin database, parsers (5 formats), persistence, pipeline, provenance, RL (thresholds, reward, state, bandit), scheduler, security (XXE, SSRF, path traversal, watchlist, log redaction, file permissions, CLI locks, DNS rebinding, redirect validation, checksum pinning), splunk connector, sumologic connector, system state, temporal, and tool validation. API tests cover auth, dashboard, entities, incidents, pipeline, config, system, upload, chat, and security hardening.

## Project Structure

```
nabla/
├── agents/           # Agent creation and lifecycle
│   ├── bootstrap.py   # Bootstrap/teardown orchestration
│   ├── env.py         # Environment variables + compaction model
│   ├── registry.py    # Agent discovery by name prefix
│   └── supervisor.py  # Supervisor agent definition (no tools)
├── api/              # FastAPI web server routes
│   ├── auth.py        # Setup token verification
│   ├── chat.py        # SSE streaming chat with supervisor
│   ├── config.py      # Schedule, connectors, RL, environment, watchlists
│   ├── dashboard.py   # System health, stats, recent runs
│   ├── entities.py    # Entity profiles and baselines
│   ├── incidents.py   # Incident CRUD + status updates
│   ├── pipeline.py    # Pipeline trigger + SSE streaming
│   ├── system.py      # Bootstrap, teardown, export, import
│   └── upload.py      # Log file upload (chunked, size-limited)
├── connectors/       # SIEM connectors for real log ingestion
│   ├── base.py        # Shared SSRF utilities, canonical schema, credential loading
│   ├── splunk.py     # Splunk SPL connector (auth, network, DNS, endpoint)
│   └── sumologic.py  # SumoLogic v2 Search Job API connector
├── parsers/          # Log file parsers for ad-hoc upload
│   ├── __init__.py    # parse_file() dispatcher + normalize_entries()
│   ├── csv_parser.py  # CSV format parser
│   ├── field_map.py   # Auto-detect column names + --map overrides
│   ├── json_parser.py # JSON/JSONL format parser
│   ├── text_parser.py  # Syslog text format parser
│   └── xml_parser.py  # XML/Sysmon format parser (defusedxml)
├── rl/               # Reinforcement learning
│   ├── bandit.py      # Thompson Sampling bandit (28 methods)
│   ├── reward.py      # Reward computation from findings
│   ├── state.py       # State extraction from shared blocks
│   └── thresholds.py  # Q-learning threshold agent (30 thresholds)
├── tools/            # Letta tool definitions
│   └── register.py    # Tool registration + idempotent lookup
├── attack.py         # MITRE ATT&CK mapping (STIX bundle → tool index + block text)
├── auth.py           # API authentication (setup token, timing-safe comparison)
├── baselines.py      # Per-entity behavioral profiles (UserProfile, HostProfile, IPProfile)
├── blocks.py         # Shared memory block management (9 blocks)
├── cli.py            # Typer CLI (14 commands + subcommands)
├── client.py         # Letta client factory
├── config.py         # Pydantic settings (NABLA_ prefix)
├── correlation.py    # Deterministic threat correlation (replaces LLM threat agent)
├── detection.py     # Deterministic anomaly detection (29 numbered methods + graph/temporal/exfil modules, replaces LLM anomaly agent)
├── explain.py       # Three-layer explainability (evidence, counterfactuals, graph counterfactuals)
├── export.py        # State export/import (8 state files, merge mode, path validation)
├── gcn_lof.py       # GCN-LOF hybrid detector (method 12)
├── history.py        # Pipeline run history persistence
├── incidents.py     # Incident lifecycle management (new→investigating→resolved/false_positive)
├── ingest.py         # Synthetic log generation + SIEM ingestion
├── log.py            # Structured logging + credential redaction filter
├── lolbin_db.py      # LOLBIN database (LOLBAS + GTFOBins APIs → block text, SHA-256 pinning)
├── persistence.py    # Atomic JSON file writes (0600 permissions)
├── pipeline.py       # Pipeline orchestration (8 steps)
├── provenance.py     # Provenance graph + Louvain community detection
├── rate_limit.py     # SlowAPI rate limiter configuration
├── safe_error.py     # Error message sanitization for API responses
├── scheduler.py      # APScheduler with PostgreSQL job store
├── server.py         # FastAPI application (CORS, security headers, rate limiting)
├── ssrf.py           # SSRF URL validation (peer IP + redirect + DNS rebinding checks)
├── system_state.py   # Baseline/detection phase tracking + transition logic
├── temporal.py       # Temporal attack chain detection
├── utils.py          # Shared utilities (is_routable_ip, is_off_hours)
└── watchlist.py      # Watchlist management for targeted SIEM ingestion
frontend/
├── src/
│   ├── pages/         # React pages (Dashboard, Entities, Pipeline, Incidents, Chat, Environment, Config, Setup)
│   ├── hooks/         # useAuth() hook
│   ├── lib/           # apiFetch(), API_URL, apiHeaders()
│   └── components/    # Layout.tsx
├── nginx.conf         # Reverse proxy (/api/ → nabla:8000, SSE support)
├── Dockerfile         # Multi-stage build (node:20-alpine → nginx:alpine)
└── tsconfig.json      # TypeScript config
```

## Security Notes

- Containers run as non-root (`appuser` uid 1000 for backend, `nginx` for frontend)
- PostgreSQL bound to `127.0.0.1` only
- Letta API bound to `127.0.0.1` only (no authentication — use a firewall)
- No hardcoded credentials — all secrets via `.env`
- Atomic file writes with 0600 permissions prevent corrupted state on crash
- `.env` excluded from git via `.gitignore`
- Network isolation: nabla container can reach letta but not postgres directly
- XXE protection: `defusedxml.ElementTree` replaces `xml.etree.ElementTree`
- SSRF protection: peer IP validation + redirect URL validation per hop + DNS rebinding double-check
- Path traversal protection: file parsing, export/import, and upload paths restricted to allowed directories
- Upload path traversal: filename sanitization strips `../`, `\`, absolute paths, special chars
- Watchlist entity validation: blocks SPL metacharacters (`|;`$\\{}[]!#&<>'"`)
- CLI lock file prevents concurrent pipeline runs
- Credential redaction in logs: Bearer tokens, passwords in URLs, API keys (48+ hex, 64+ base64 thresholds)
- STIX bundle integrity: redirect domain pinning (github.com only), SHA-256 hash verification
- LOLBIN download integrity: SHA-256 checksum pinning via env vars (`NABLA_LOLBAS_SHA256`, `NABLA_GTFOBINS_SHA256`)
- Splunk credential loading: TOCTOU-safe via `os.open()` + `os.fstat()`
- Environment variable credential warning: alerts when Splunk creds set via env vars (visible in /proc)
- Docker entrypoint: skips symlinks during chown (`! -type l`)
- AST-based code sanitizer for tool source code
- PBKDF2-HMAC-SHA256 encryption key derivation with transparent migration
- Timing-safe token comparison (`hmac.compare_digest`) for setup token and service tokens
- `pg_advisory_xact_lock` serializes first-user registration
- JWT `ver` claim enables token revocation (logout-everywhere)
- SumoLogic connector: `follow_redirects=False` with per-hop SSRF validation
- Splunk connector: `follow_redirects=False` with per-hop SSRF validation
- Private IP filtering: RFC 1918 addresses excluded from impossible-travel and multi-IP detection
- New account grace period: recently created accounts exempt from z-score and activity spike detection
- Environment context block: user-declared network ranges, service accounts, and benign patterns reduce false positives
- Rate limiting: per-route limits via slowapi (pipeline 2/min, chat 10/min, upload 5/min, bootstrap 1/min, default 30/min)
- Error message sanitization: internal errors logged server-side, generic messages returned to clients
- Security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`
- CORS restricted to `GET`, `POST`, `PUT`, `DELETE` methods and `Authorization`, `Content-Type` headers
- Frontend container runs as `USER nginx` (non-root)
- CSP headers via nginx for frontend assets
- Upload size limit: 10MB per file, 1MB per uncompressed entry, 10MB total uncompressed
- Pipeline input validation: source, log_type, log_count validated via Pydantic field validators
- Schedule interval validation: 1–1440 minutes, log_count 1–100,000
- Incident status/severity: `Literal` type constraints on query params and update body
- Chat SSE stream: thread-safe queue-based iteration (no event loop blocking)
- Dashboard health checks: async with `asyncio.gather()` (no sequential blocking)
- Upload: chunked file reading (1MB chunks) instead of full memory load

## Known Letta Workarounds

- `GLOBAL_MAX_CONTEXT_WINDOW_LIMIT=32768` — prevents Letta from capping context below model capability ([bug #3279](https://github.com/letta-ai/letta/issues/3279))
- Compaction model override via REST API — `PATCH /v1/agents/{id}` for `compaction_settings.model` ([bug #3270](https://github.com/letta-ai/letta/issues/3270))
- `embedding_model` must NOT have `ollama/` prefix — Ollama expects bare model name
- `pgvector` extension required — use `pgvector/pgvector:pg16`, not plain `postgres:16`
- `archival_memory_search` must be explicitly attached to v2 agents
- `tool_exec_environment_variables` must be set via raw REST API — SDK silently fails
- Tool schema generator requires docstrings, type annotations, and `Args:` descriptions on **every** function in the source code — including nested helpers. Missing any of these causes `BadRequestError: Failed to derive json schema`
- Letta AST parser picks the LAST function definition — all helpers must be defined BEFORE the main tool function

## License

Proprietary. All rights reserved.
