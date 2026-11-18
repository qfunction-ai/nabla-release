# Nabla

Self-hosted User and Entity Behavior Analytics (UEBA) on Letta. Nabla
ingests authentication and endpoint telemetry, builds behavioral baselines
per entity, correlates anomalies into findings, and uses an LLM supervisor
to produce analyst-readable incident narratives.

## Quickstart

Requirements: Docker + compose plugin, an Ollama host reachable from the
containers, ~8 GB RAM.

```bash
git clone https://github.com/qfunction-ai/nabla-release.git
cd nabla-release
cp .env.example .env          # set POSTGRES_PASSWORD; models default to Gemma
ollama pull gemma4:latest && ollama pull embeddinggemma:latest   # on your Ollama host
docker compose up -d          # first boot pulls images + models (minutes)
curl http://localhost:8002/health
```

On first boot, register the operator: open the UI at `http://localhost:3000`
(the nginx frontend; `:8002` is the backend API) and create the first
account — the first registered user becomes the operator.
Registration is rate-limited to 3/minute. If you set `NABLA_SETUP_TOKEN`
in `.env`, API access requires that token instead.

Verify the pipeline end-to-end with synthetic data (no SIEM needed):

```bash
docker compose exec nabla nabla bootstrap
docker compose exec nabla nabla run --source synthetic --log-count 50
```

You should see ingestion, detection, correlation, and a supervisor
narrative in the run output, and entities with baselines forming in the UI.

## Using Nabla with the "AI and UEBA" course (PluralSight)

The course's sample dataset is distributed with the course materials —
it is intentionally NOT in this repository. Download the sample log from
the course materials page, then:

```bash
docker compose exec nabla nabla ingest <path-to-download>/sample-log/ --siem-data
```

Ingest day-by-day (one file per session) to watch peer groups re-cluster
between sessions. Note: a fresh instance stays in baseline phase while
learning from a small sample — entity detectors activate after the
configured baseline window (`NABLA_BASELINE_DAYS`, default 21 days of
ingested history). The course videos show the instructor's
detection-phase instance for the anomaly and attack demos.

## What's here

- `nabla/` — the backend: ingestion, 29 detection methods, correlation,
  LLM supervisor, risk scoring, peer groups, REST API
- `frontend/` — the operator UI (entities, incidents, methods reference)
- `tests/` — unit + frontend test tiers (see below)
- `docs/detection-methods.md` — the detector reference documentation

## CI and what it does NOT verify

CI runs the unit tier (`pytest -k "not integration"`) and the frontend
suite (msw-mocked, no live stack). It does NOT verify: the live Letta +
Postgres + Ollama integration paths, model behavior, or SIEM connectors.
To exercise those locally: `docker compose up -d` and run the integration
tier with `NABLA_INTEGRATION=1`.

## SIEM ingestion (optional)

Nabla runs fully on file and synthetic sources. To connect your own
SumoLogic or Splunk, see the connector section in `.env.example` and the
in-app Help documentation.

## License

Apache 2.0 — see LICENSE. Contributions per CLA.md.

## Troubleshooting: data-volume ownership

Named volumes take their initial ownership from the image. If a volume was
created by an older image with a different UID and the backend cannot write
`/data`, run the one-off repair:

```bash
docker compose run --rm --user root nabla chown -R appuser:appgroup /data
```
