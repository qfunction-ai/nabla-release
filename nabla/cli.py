"""Nabla CLI — command-line interface for the UEBA multi-agent system."""

import os
import time

import typer

from nabla.client import get_client
from nabla.config import get_settings
from nabla.log import get_logger

logger = get_logger("cli")

# Lock file to prevent concurrent pipeline runs
_LOCK_FILE = "/tmp/nabla-pipeline.lock"

app = typer.Typer(help="Nabla — UEBA multi-agent system on Letta API")


@app.command()
def bootstrap():
    """Create all Nabla agents, shared blocks, and tools."""
    typer.echo("Bootstrapping Nabla system...")
    from nabla.agents.bootstrap import bootstrap as _bootstrap

    client = get_client()
    logger.info("Starting bootstrap")
    agents = _bootstrap(client)

    typer.echo("Created agents:")
    for role, agent_id in agents.items():
        typer.echo(f"  {role}: {agent_id}")
    typer.echo("Nabla system ready.")
    logger.info("Bootstrap complete: %d agents created", len(agents))


@app.command()
def run(
    log_type: str = typer.Option("all", help="Type of logs: auth, network, dns, endpoint, or all"),
    log_count: int = typer.Option(20, help="Number of log entries per type (synthetic only)"),
    source: str = typer.Option("auto", help="Ingestion source: auto, synthetic, splunk, sumologic, file"),
    watchlist_group: list[str] = typer.Option([], help="Watchlist groups to target (can be repeated)"),
    reset_ingestion: bool = typer.Option(False, "--reset", help="Reset ingestion state for full re-pull"),
    force: bool = typer.Option(False, "--force", help="Clear a stale pipeline lock and proceed"),
    gcn_lof: bool = typer.Option(False, "--gcn-lof", help="Enable GCN-LOF (experimental; disabled by default per R3 — 13-18% flag rate under the current anchoring)"),
    file: str = typer.Option(None, "--file", help="Path to log file (required when source=file)"),
    format: str = typer.Option(
        None, "--format",
        help="File format: csv, json, jsonl, xml, text (auto-detected if omitted)",
    ),
    map: str = typer.Option(None, "--map", help="Column mapping: canonical=raw_col,canonical2=raw_col2"),
):
    """Execute the full UEBA pipeline (ingest → detect → correlate → supervisor)."""
    from nabla.pipeline import run_pipeline
    from nabla.parsers.field_map import parse_column_map_string

    # Prevent concurrent pipeline runs. Stale locks (age > 15 min, e.g. a
    # timeout-killed run) are removed with an audit line; --force clears
    # any lock explicitly. (silent-swallow sweep: lock expiry)
    lock_acquired = False
    while not lock_acquired:
        try:
            lock_fd = os.open(_LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.write(lock_fd, f"{os.getpid()}\n".encode())
            lock_acquired = True
        except FileExistsError:
            age_s = time.time() - os.path.getmtime(_LOCK_FILE)
            if force or age_s > 900:  # 15 minutes
                how = "--force" if force else f"stale ({int(age_s)}s old)"
                logger.warning("Removing pipeline lock (%s)", how)
                typer.echo(f"  Removing pipeline lock ({how}).", err=True)
                try:
                    os.unlink(_LOCK_FILE)
                except FileNotFoundError:
                    pass  # silent by design: raced another remover (2026-09 sweep)
                continue
            typer.echo(
                "Error: Another pipeline run is already in progress. "
                "If this is stale, remove /tmp/nabla-pipeline.lock or use --force.",
                err=True,
            )
            raise typer.Exit(1)

    try:
        # Parse column mapping
        column_map = None
        if map:
            try:
                column_map = parse_column_map_string(map)
            except ValueError as e:
                typer.echo(f"Error: {e}", err=True)
                raise typer.Exit(1)

        # Validate file source
        if source == "file" and not file:
            typer.echo("Error: --file is required when --source=file", err=True)
            raise typer.Exit(1)

        client = get_client()
        logger.info("Running pipeline: log_type=%s, log_count=%d, source=%s", log_type, log_count, source)
        results = run_pipeline(
            client,
            log_types=log_type,
            log_count=log_count,
            source=source,
            watchlist_groups=watchlist_group or None,
            reset_ingestion=reset_ingestion,
            file_path=file,
            file_format=format,
            column_map=column_map,
            gcn_lof_enabled=gcn_lof,
        )

        typer.echo("\n=== Pipeline Results ===")
        for step, response in results.items():
            typer.echo(f"\n--- {step.upper()} ---")
            typer.echo(response)

        # Per-layer counts INCLUDING zeros (silent-swallow sweep): a dead
        # layer prints "0" here; a TypeError never reached the count.
        from nabla.history import list_runs
        typer.echo("\n=== Layer Counts ===")
        runs = list_runs(limit=1)
        if runs:
            layer_counts = runs[0].get("layer_counts")
            if layer_counts:
                for layer, n in layer_counts.items():
                    typer.echo(f"  {layer}: {n}")
            else:
                typer.echo("  (run predates layer counts)")
    finally:
        os.close(lock_fd)
        os.unlink(_LOCK_FILE)


@app.command()
def status():
    """Check agent health and system state."""
    from nabla.pipeline import get_status

    client = get_client()
    info = get_status(client)

    if "error" in info:
        logger.warning("Status check failed: %s", info["error"])
        typer.echo(info["error"], err=True)
        raise typer.Exit(1)

    typer.echo("=== Nabla Agents ===")
    for a in info.get("agents", []):
        typer.echo(f"  {a['role']}: {a['name']} ({a['id']})")

    # Detector self-test (silent-swallow sweep): smoke-call each optional
    # layer so a dead detector is visible HERE, not in run-log archaeology.
    typer.echo("\n=== Detector Self-Test ===")
    for name, result in _detector_self_test():
        mark = "✓" if result else "✗ FAILED"
        typer.echo(f"  {mark} {name}")


def _detector_self_test() -> list[tuple[str, bool]]:
    """Smoke-call optional detection layers with a two-entry payload.

    A signature mismatch (the class of bug that silently killed GCN-LOF
    and temporal) raises here instead of being swallowed per-run.
    """
    entries = [
        {"user": "selftest", "action": "login", "timestamp": "2026-01-01T10:00:00Z",
         "source_ip": "10.0.0.1", "log_type": "auth", "process": "sshd"},
        {"user": "selftest", "action": "network_connect", "timestamp": "2026-01-01T10:01:00Z",
         "source_ip": "10.0.0.2", "log_type": "network", "process": "curl"},
    ]
    anomalies = [{"entity": "selftest", "type": "z_score_spike", "severity": "low",
                  "timestamp": "2026-01-01T10:00:00Z", "detection_method": "z_score"}]
    results: list[tuple[str, bool]] = []

    def _check(name, fn):
        try:
            fn()
            results.append((name, True))
        except Exception as e:
            logger.warning("Detector self-test FAILED for %s: %s", name, e, exc_info=True)
            results.append((name, False))

    def _gcn():
        from nabla.gcn_lof import GCNLOFDetector
        d = GCNLOFDetector.__new__(GCNLOFDetector)
        GCNLOFDetector.detect(d, entries, baselines=None, threshold=0.75,
                              _existing_anomalies=anomalies)

    def _provenance():
        from nabla.provenance import detect_provenance_anomalies_with_context
        detect_provenance_anomalies_with_context(entries, anomalies, None)

    def _temporal():
        from nabla.temporal import detect_temporal_chains_with_context
        detect_temporal_chains_with_context(entries, anomalies, None)

    def _exfil():
        from nabla.exfiltration import detect_exfiltration
        import inspect
        sig = inspect.signature(detect_exfiltration)
        detect_exfiltration(entries, {}) if len(sig.parameters) >= 2 else detect_exfiltration(entries)

    _check("gcn_lof", _gcn)
    _check("provenance", _provenance)
    _check("temporal", _temporal)
    _check("exfiltration", _exfil)
    return results

    # Show system phase
    blocks = info.get("blocks", {})
    blocks.pop("system_phase", "detection")
    blocks.pop("first_ingestion_at", None)
    blocks.pop("baseline_days_remaining", None)
    warm_up = blocks.pop("warm_up", None)

    from nabla.system_state import load_system_state, format_phase_summary
    settings = get_settings()
    sys_state = load_system_state(settings.system_state_file)
    typer.echo(f"\n{format_phase_summary(sys_state, warm_up)}")

    typer.echo("\n=== Shared Blocks ===")
    for label, value in info.get("blocks", {}).items():
        typer.echo(f"\n--- {label} ---")
        typer.echo(value)


@app.command()
def history(
    limit: int = typer.Option(20, help="Number of recent runs to show"),
):
    """Show pipeline run history."""
    from nabla.history import list_runs

    runs = list_runs(limit=limit)
    if not runs:
        typer.echo("No pipeline runs recorded yet.")
        return

    typer.echo(f"=== Recent Pipeline Runs (showing {len(runs)}) ===\n")
    for r in runs:
        status_icon = "✓" if r["success"] else "✗"
        duration_str = ""
        if r.get("step_durations"):
            total = sum(r["step_durations"].values())
            duration_str = f"  duration={total:.1f}s"
        typer.echo(
            f"  {status_icon} {r['run_id'][:8]}  "
            f"{r['started_at'][:19]}  "
            f"source={r.get('source', 'synthetic')}  "
            f"types={','.join(r.get('log_types', []))}  "
            f"anomalies={r.get('anomaly_count', '?')}  "
            f"findings={r.get('findings_count', '?')}"
            f"{duration_str}"
        )


@app.command()
def chat():
    """Interactive chat with the Supervisor agent."""
    from nabla.agents.registry import find_agent

    client = get_client()
    supervisor = find_agent(client, "supervisor")

    if supervisor is None:
        logger.warning("Supervisor agent not found")
        typer.echo("Supervisor agent not found. Run `nabla bootstrap` first.", err=True)
        raise typer.Exit(1)

    agent_id = supervisor.id
    typer.echo(f"Chatting with Supervisor ({agent_id}). Type 'quit' to exit.\n")

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            typer.echo("\nGoodbye.")
            break

        if user_input.lower() in ("quit", "exit", "q"):
            typer.echo("Goodbye.")
            break

        if not user_input:
            continue

        response = client.agents.messages.create(
            agent_id=agent_id,
            messages=[{"role": "user", "content": user_input}],
        )

        # Extract assistant message
        for msg in response.messages:
            if msg.message_type == "assistant_message":
                typer.echo(f"\nSupervisor: {msg.content}\n")
                break


@app.command()
def schedule(
    interval: int = typer.Option(5, help="Run interval in minutes"),
    log_type: str = typer.Option("all", help="Log types: auth, network, dns, endpoint, or all"),
    log_count: int = typer.Option(50, help="Number of log entries per type (synthetic only)"),
    source: str = typer.Option("auto", help="Ingestion source: auto, synthetic, splunk"),
    watchlist_group: list[str] = typer.Option([], help="Watchlist groups to target (can be repeated)"),
    stop: bool = typer.Option(False, "--stop", help="Stop the scheduler"),
):
    """Start or stop scheduled pipeline runs."""
    if stop:
        from nabla.scheduler import stop_scheduler
        stop_scheduler()
        return

    from nabla.pipeline import _resolve_log_types
    from nabla.scheduler import run_scheduler_loop

    types = _resolve_log_types(log_type)
    typer.echo(f"Starting scheduler: every {interval} min, types={types}, count={log_count}, source={source}")
    run_scheduler_loop(
        interval_minutes=interval,
        log_types=types,
        log_count=log_count,
        source=source,
        watchlist_groups=watchlist_group or None,
    )


@app.command()
def teardown(
    force: bool = typer.Option(
        False, "--force",
        help="Skip confirmation prompt (required in non-interactive mode)",
    ),
):
    """Delete all Nabla agents and shared blocks."""
    if not force:
        typer.confirm("This will delete all Nabla agents and blocks. Continue?", abort=True)

    from nabla.agents.bootstrap import teardown as _teardown

    client = get_client()
    logger.info("Starting teardown")
    deleted = _teardown(client)
    typer.echo(f"Deleted {deleted} resources.")
    logger.info("Teardown complete: %d resources deleted", deleted)


@app.command(name="check-ollama")
def check_ollama():
    """Check Ollama connectivity and recommend configuration."""
    import httpx

    settings = get_settings()

    # Derive Ollama base URL from embedding endpoint (strip /v1)
    ollama_url = settings.embedding_endpoint
    if ollama_url.endswith("/v1"):
        ollama_url = ollama_url.removesuffix("/v1")
    ollama_url = ollama_url.rstrip("/")
    if not ollama_url.startswith("http"):
        ollama_url = f"http://{ollama_url}"

    typer.echo("=== Ollama Health Check ===\n")
    typer.echo(f"Ollama URL: {ollama_url}")

    # 1. Connectivity
    try:
        resp = httpx.get(f"{ollama_url}/api/tags", timeout=5)
        resp.raise_for_status()
        typer.echo("Status: reachable")
    except Exception as e:
        typer.echo(f"Status: UNREACHABLE — {e}", err=True)
        raise typer.Exit(1)

    # 2. Model availability
    models = resp.json().get("models", [])
    model_names = [m.get("name", "") for m in models]
    typer.echo(f"\nAvailable models: {len(models)}")

    llm_name = settings.llm_model.replace("ollama/", "")
    emb_name = settings.embedding_model

    llm_found = any(m.startswith(llm_name.split(":")[0]) for m in model_names)
    emb_found = any(m.startswith(emb_name.split(":")[0]) for m in model_names)

    typer.echo(f"  LLM ({llm_name}): {'found' if llm_found else 'MISSING'}")
    typer.echo(f"  Embedding ({emb_name}): {'found' if emb_found else 'MISSING'}")

    # 3. Recommended settings
    typer.echo("\n=== Recommended Ollama Settings ===\n")
    typer.echo("Set these environment variables before starting Ollama:")
    typer.echo(f"  OLLAMA_KEEP_ALIVE={settings.ollama_keep_alive}")
    typer.echo(f"  OLLAMA_CONTEXT_LENGTH={settings.ollama_context_length}")
    typer.echo(f"  OLLAMA_FLASH_ATTENTION={'1' if settings.ollama_flash_attention else '0'}")
    typer.echo(f"  OLLAMA_MAX_LOADED_MODELS={settings.ollama_max_loaded_models}")
    typer.echo("")
    typer.echo("Why these values:")
    typer.echo("  KEEP_ALIVE=24h — prevents model reloading between pipeline steps (saves 10-30s per step)")
    typer.echo("  CONTEXT_LENGTH=32768 — agents need more context than default 2048 for tool schemas + memory")
    typer.echo("  FLASH_ATTENTION=1 — reduces memory and improves speed for long contexts")
    typer.echo("  MAX_LOADED_MODELS=2 — keeps LLM + embedding model loaded simultaneously")

    # 4. Letta workarounds
    typer.echo("\n=== Letta Workarounds ===\n")
    typer.echo(f"GLOBAL_MAX_CONTEXT_WINDOW_LIMIT={settings.letta_max_context_window}")
    typer.echo("  Prevents Letta from capping context below model capability (bug #3279)")
    if settings.letta_compaction_model:
        typer.echo(f"compaction_settings.model={settings.letta_compaction_model}")
        typer.echo("  Fixes tokenizer mismatch during compaction (bug #3270)")
    else:
        typer.echo(f"compaction_settings.model={settings.llm_model} (recommended)")
        typer.echo("  Fixes tokenizer mismatch during compaction (bug #3270)")
        typer.echo("  Set NABLA_LETTA_COMPACTION_MODEL to enable this workaround")


@app.command(name="calibration-status")
def calibration_status():
    """Show threshold calibration state (Phase 3: label-driven)."""
    from nabla.rl.calibration import load_calibration, THRESHOLDS, current_labels
    from nabla.rl.bandit import DetectionMethodBandit

    settings = get_settings()
    store = load_calibration()
    bandit = DetectionMethodBandit.load(settings.rl_state_file)

    typer.echo("=== Threshold Calibration (label-driven) ===\n")
    typer.echo("Threshold values (current vs default):")
    for name in THRESHOLDS:
        entry = store.get(name, {})
        current = entry.get("current")
        default = entry.get("default")
        pinned = " [PINNED]" if entry.get("pinned") else ""
        changed = " (changed)" if current != default else ""
        typer.echo(f"  {name}: {current} (default {default}){changed}{pinned}")

    labels = current_labels()
    typer.echo(f"\nFeedback labels: {len(labels)} (current, non-superseded)")

    typer.echo("\n=== Detection Method Effectiveness (bandit) ===\n")
    means = bandit.get_means()
    for method in sorted(means, key=means.get, reverse=True):
        alpha = bandit.alpha[method]
        beta = bandit.beta[method]
        bar = "█" * int(means[method] * 20)
        typer.echo(f"  {method:20s} {means[method]:.2f} {bar}  (α={alpha:.0f} β={beta:.0f})")

    typer.echo(f"\nCalibration store: {settings.data_dir}/feedback/calibration.json")


@app.command(name="calibrate")
def calibrate_cmd():
    """Run threshold calibration from current analyst dispositions."""
    from nabla.rl.calibration import run_calibration

    report = run_calibration()
    typer.echo("=== Calibration Report ===")
    for name, r in sorted(report.items()):
        status = r.get("status", "?")
        if status == "moved":
            typer.echo(f"  {name}: {r['from']} → {r['to']}  ({r.get('reason', '')})")
        elif status == "pinned_by_operator":
            typer.echo(f"  {name}: pinned by operator at {r.get('current')}")
        else:
            typer.echo(f"  {name}: {status} (current {r.get('current')}) — {r.get('reason', '')}")


# --- Watchlist subcommands ---

watchlist_app = typer.Typer(help="Manage watchlists for targeted SIEM ingestion")
app.add_typer(watchlist_app, name="watchlist")


@watchlist_app.command("list")
def watchlist_list():
    """List all watchlist groups and their entities."""
    from nabla.watchlist import list_groups

    settings = get_settings()
    groups = list_groups(settings.effective_watchlist_path)

    if not any(groups.values()):
        typer.echo("Watchlist is empty. Add entities with: nabla watchlist add <group> <entity>")
        return

    for group, entities in groups.items():
        if entities:
            typer.echo(f"\n  {group}:")
            for entity in entities:
                typer.echo(f"    - {entity}")
        else:
            typer.echo(f"\n  {group}: (empty)")

    from nabla.watchlist import get_all_entities
    all_entities = get_all_entities(settings.effective_watchlist_path)
    typer.echo(
        f"\n  Summary: {len(all_entities['users'])} users, "
        f"{len(all_entities['hosts'])} hosts, {len(all_entities['ips'])} IPs"
    )


@watchlist_app.command("add")
def watchlist_add(
    group: str = typer.Argument(
        help="Group name (e.g., high_value_users, critical_systems, watched_ips, or a custom group name)"
    ),
    entity: str = typer.Argument(help="Entity to add (username, hostname, or IP address)"),
):
    """Add an entity to a watchlist group."""
    from nabla.watchlist import add_entity

    settings = get_settings()
    add_entity(settings.effective_watchlist_path, group, entity)
    typer.echo(f"Added '{entity}' to '{group}'")


@watchlist_app.command("remove")
def watchlist_remove(
    group: str = typer.Argument(help="Group name"),
    entity: str = typer.Argument(help="Entity to remove"),
):
    """Remove an entity from a watchlist group."""
    from nabla.watchlist import remove_entity

    settings = get_settings()
    remove_entity(settings.effective_watchlist_path, group, entity)
    typer.echo(f"Removed '{entity}' from '{group}'")


@app.command(name="export")
def export_cmd(
    output: str = typer.Option(
        "nabla-export.json", "--output", "-o",
        help="Output file path for the export JSON",
    ),
):
    """Export all learned state to a single JSON file.

    Bundles entity profiles, RL thresholds, GCN-LOF model, environment
    context, watchlists, run history, and ingestion state into one
    portable file. Use before teardown to preserve learned knowledge.
    """
    from nabla.export import export_state as _export

    settings = get_settings()
    summary = _export(settings.data_dir, output)

    typer.echo(f"Exported {len(summary['exported'])}/{len(summary['exported']) + len(summary['skipped'])} state files to {output}")
    if summary["skipped"]:
        typer.echo(f"Skipped (not found): {', '.join(summary['skipped'])}")


@app.command(name="import")
def import_cmd(
    input: str = typer.Option(
        "nabla-export.json", "--input", "-i",
        help="Input export JSON file path",
    ),
    merge: bool = typer.Option(
        False, "--merge",
        help="Merge with existing state instead of overwriting",
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Skip confirmation prompt",
    ),
):
    """Import learned state from an export JSON file.

    Restores entity profiles, RL thresholds, GCN-LOF model, environment
    context, watchlists, run history, and ingestion state. Existing files
    are backed up with .bak suffix before overwriting.

    Use --merge to combine imported state with existing state instead of
    replacing it.
    """
    if not force:
        typer.confirm(
            "This will overwrite existing state files (backups created). Continue?",
            abort=True,
        )

    from nabla.export import import_state as _import

    settings = get_settings()
    try:
        summary = _import(input, settings.data_dir, merge=merge)
    except FileNotFoundError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    typer.echo(f"Imported {len(summary['imported'])}/{len(summary['imported']) + len(summary['skipped'])} state files")
    if summary["skipped"]:
        typer.echo(f"Skipped: {', '.join(summary['skipped'])}")
    if summary["backups"]:
        typer.echo(f"Backups: {len(summary['backups'])} files (.bak)")


# --- Incident subcommands ---

incidents_app = typer.Typer(help="Manage threat incidents from pipeline runs")
app.add_typer(incidents_app, name="incidents")


@incidents_app.command("list")
def incidents_list(
    status: str = typer.Option(None, "--status", help="Filter by status: new, investigating, resolved, false_positive"),
    severity: str = typer.Option(None, "--severity", help="Filter by severity: critical, high, medium, low"),
    limit: int = typer.Option(50, "--limit", help="Maximum incidents to show"),
):
    """List threat incidents from pipeline runs."""
    from nabla.incidents import list_incidents

    incidents = list_incidents(status=status, severity=severity, limit=limit)
    if not incidents:
        typer.echo("No incidents found.")
        return

    typer.echo(f"=== Incidents (showing {len(incidents)}) ===\n")
    for inc in incidents:
        sev = inc.get("severity", "medium").upper()
        stat = inc.get("status", "new")
        entity = inc.get("entity", "unknown")
        ftype = inc.get("finding_type", "unknown")
        created = inc.get("created_at", "")[:16]
        typer.echo(f"  {sev:8s}  [{stat:13s}] {entity:20s} {ftype:30s} {created}")


@incidents_app.command("show")
def incidents_show(
    incident_id: str = typer.Argument(help="Incident ID (UUID or first 8 chars)"),
):
    """Show full details of a specific incident."""
    from nabla.incidents import get_incident

    # Support partial ID match (first 8 chars)
    if len(incident_id) < 36:
        from nabla.incidents import list_incidents
        all_incidents = list_incidents(limit=1000)
        matches = [i for i in all_incidents if i["incident_id"].startswith(incident_id)]
        if len(matches) == 1:
            incident_id = matches[0]["incident_id"]
        elif len(matches) > 1:
            typer.echo(f"Ambiguous ID '{incident_id}' matches {len(matches)} incidents. Use more characters.", err=True)
            raise typer.Exit(1)
        else:
            typer.echo(f"Incident '{incident_id}' not found.", err=True)
            raise typer.Exit(1)

    inc = get_incident(incident_id)
    if inc is None:
        typer.echo(f"Incident '{incident_id}' not found.", err=True)
        raise typer.Exit(1)

    typer.echo(f"=== Incident {inc['incident_id'][:8]} ===\n")
    typer.echo(f"  Status:      {inc.get('status', 'new')}")
    typer.echo(f"  Severity:    {inc.get('severity', 'medium')}")
    typer.echo(f"  Entity:      {inc.get('entity', 'unknown')} ({inc.get('entity_type', 'unknown')})")
    typer.echo(f"  Finding:     {inc.get('finding_type', 'unknown')}")
    typer.echo(f"  Cross-type:  {inc.get('cross_type', 'single-type')}")
    typer.echo(f"  Log types:   {', '.join(inc.get('log_types', []))}")
    typer.echo(f"  Confidence:  {inc.get('confidence', 0.5):.1%}")
    typer.echo(f"  Created:     {inc.get('created_at', '')}")
    typer.echo(f"  Updated:     {inc.get('updated_at', '')}")
    typer.echo(f"  Run ID:      {inc.get('run_id', '')[:8]}")

    mitre = inc.get("mitre_attack", [])
    if mitre:
        typer.echo("\n  MITRE ATT&CK:")
        for tech in mitre:
            tid = tech.get("id", "")
            name = tech.get("name", "")
            tactic = tech.get("tactic", "")
            typer.echo(f"    {tid} {name} ({tactic})")

    tools = inc.get("tools_detected")
    if tools:
        typer.echo(f"\n  Tools detected: {', '.join(tools) if isinstance(tools, list) else tools}")

    evidence = inc.get("evidence", "")
    if evidence:
        typer.echo("\n  --- Evidence ---")
        for line in evidence.split("\n"):
            typer.echo(f"    {line}")

    review = inc.get("supervisor_review", "")
    if review:
        typer.echo("\n  --- Supervisor Review ---")
        for line in review.split("\n")[:50]:
            typer.echo(f"    {line}")
        if review.count("\n") > 50:
            typer.echo("    ... (truncated)")

    notes = inc.get("operator_notes", "")
    if notes:
        typer.echo("\n  --- Operator Notes ---")
        for line in notes.split("\n"):
            typer.echo(f"    {line}")


@incidents_app.command("update")
def incidents_update(
    incident_id: str = typer.Argument(help="Incident ID (UUID or first 8 chars)"),
    status: str = typer.Option(None, "--status", help="New status: new, investigating, resolved, false_positive"),
    notes: str = typer.Option(None, "--notes", help="Operator notes to append"),
):
    """Update an incident's status or add operator notes."""
    from nabla.incidents import update_incident, list_incidents

    # Support partial ID match
    if len(incident_id) < 36:
        all_incidents = list_incidents(limit=1000)
        matches = [i for i in all_incidents if i["incident_id"].startswith(incident_id)]
        if len(matches) == 1:
            incident_id = matches[0]["incident_id"]
        elif len(matches) > 1:
            typer.echo(f"Ambiguous ID '{incident_id}' matches {len(matches)} incidents. Use more characters.", err=True)
            raise typer.Exit(1)
        else:
            typer.echo(f"Incident '{incident_id}' not found.", err=True)
            raise typer.Exit(1)

    if not status and notes is None:
        typer.echo("Provide --status and/or --notes to update.", err=True)
        raise typer.Exit(1)

    try:
        result = update_incident(incident_id, status=status, notes=notes)
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    if result is None:
        typer.echo(f"Incident '{incident_id[:8]}' not found.", err=True)
        raise typer.Exit(1)

    typer.echo(f"Incident {result['incident_id'][:8]} updated: status={result['status']}")
    if notes is not None:
        typer.echo("  Notes appended.")


@incidents_app.command("stats")
def incidents_stats():
    """Show incident counts by status and severity."""
    from nabla.incidents import incident_stats

    stats = incident_stats()
    if stats["total"] == 0:
        typer.echo("No incidents recorded yet.")
        return

    typer.echo("=== Incident Statistics ===\n")

    typer.echo("  By status:")
    for s in ["new", "investigating", "resolved", "false_positive"]:
        count = stats["by_status"].get(s, 0)
        if count:
            typer.echo(f"    {s:15s} {count}")

    typer.echo("\n  By severity:")
    for sev in ["critical", "high", "medium", "low"]:
        count = stats["by_severity"].get(sev, 0)
        if count:
            typer.echo(f"    {sev:10s} {count}")

    typer.echo(f"\n  Total: {stats['total']}")


@app.command(name="risk")
def risk(
    limit: int = typer.Option(10, help="Number of top-risk entities to show"),
    cutoff: float = typer.Option(None, help="Only show entities above this score"),
):
    """Show top-risk entities by aggregate risk score."""
    from nabla.risk import EntityRiskStore, get_trend_label

    settings = get_settings()
    try:
        store = EntityRiskStore(settings.entity_risk_scores_file)
    except Exception:
        typer.echo("No risk scores available. Run the pipeline first.")
        return

    cutoff_val = cutoff if cutoff is not None else settings.risk_score_investigation_cutoff
    top = store.top_risky(limit=limit)

    if not top:
        typer.echo("No risk scores computed yet. Run the pipeline first.")
        return

    typer.echo(f"\n  Top {len(top)} Riskiest Entities (cutoff: {cutoff_val:.0f})\n")
    typer.echo(f"  {'Entity':<30s} {'Type':<6s} {'Score':>6s} {'Peak':>6s} {'Trend':>10s}  Categories")
    typer.echo(f"  {'─' * 30} {'─' * 6} {'─' * 6} {'─' * 6} {'─' * 10}  {'─' * 30}")

    for rs in top:
        trend_label = get_trend_label(rs.trend)
        cat_str = " ".join(
            f"{k}={v:.0f}" for k, v in rs.categories.items() if v > 0
        )
        marker = "!" if rs.overall >= cutoff_val else " "
        typer.echo(
            f"  {marker}{rs.entity_id:<29s} {rs.entity_type:<6s} "
            f"{rs.overall:>6.1f} {rs.peak:>6.1f} {trend_label:>10s}  {cat_str}"
        )

    above = sum(1 for rs in store.scores.values() if rs.overall >= cutoff_val)
    typer.echo(f"\n  {above} entities above investigation cutoff ({cutoff_val:.0f})")


@app.command(name="eval")
def eval_cmd(
    scenario: str = typer.Option("supervisor", help="Eval suite to run: supervisor"),
    save: bool = typer.Option(True, "--save/--no-save", help="Save results to JSON"),
):
    """Run evaluation scenarios against Nabla agents."""
    import asyncio

    typer.echo(f"Running {scenario} evaluation suite...\n")

    if scenario == "supervisor":
        from nabla.evals.supervisor_evals import run_evals
        result = asyncio.run(run_evals())
        result.print_report()

        if save:
            from pathlib import Path
            from nabla.config import get_settings
            settings = get_settings()
            results_path = Path(settings.data_dir) / "eval_results.json"
            results_path.write_text(result.to_json())
            typer.echo(f"\nResults saved to {results_path}")

        if not result.passed:
            raise typer.Exit(code=1)
    else:
        typer.echo(f"Unknown eval suite: {scenario}")
        raise typer.Exit(code=1)


@app.command(name="web")
def web():
    """Start the Nabla web server (API + UI)."""
    from nabla.server import main as _main
    typer.echo("Starting Nabla web server...")
    _main()


@app.command(name="phase")
def phase(
    action: str = typer.Argument(..., help="force-detection | set-baseline | show"),
    confirm: bool = typer.Option(False, "--confirm", help="Required for state changes (audit-logged)"),
):
    """Inspect or override the baseline/detection phase (phase-mechanics plan).

    force-detection: operator override — the entity/statistical detectors
    activate without waiting for the baseline clock. Loudly logged.
    set-baseline: revert to baseline phase.
    """
    from nabla.system_state import load_system_state, save_system_state
    from nabla.config import get_settings
    from nabla.log import get_logger
    import datetime as _dt

    settings = get_settings()
    logger = get_logger("cli.phase")
    state = load_system_state(settings.system_state_file)

    if action == "show":
        typer.echo(f"  Phase: {state.get('phase', '?')}")
        typer.echo(f"  first_ingestion_at: {state.get('first_ingestion_at') or 'never'}")
        typer.echo(f"  data span: {state.get('data_oldest_ts', '?')} .. {state.get('data_newest_ts', '?')}")
        return

    if action not in ("force-detection", "set-baseline"):
        typer.echo(f"Unknown phase action: {action} (use force-detection | set-baseline | show)")
        raise typer.Exit(code=1)

    if not confirm:
        typer.echo(f"  Refusing to {action} without --confirm (operator decision, audit-logged).")
        raise typer.Exit(code=1)

    target = "detection" if action == "force-detection" else "baseline"
    state["phase"] = target
    state[f"phase_{target}_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    save_system_state(settings.system_state_file, state)
    logger.warning("PHASE OVERRIDE by operator: -> %s (%s)", target, action)
    typer.echo(f"  Phase set to {target} (audit-logged).")


def _reset_files(scope: str, data_dir) -> list[str]:
    """Resolve the file list per reset scope (absolute paths)."""
    import os
    base = str(data_dir)
    peer_path = os.path.join(base, "entity_peer_groups.json")

    phase_files = [os.path.join(base, f) for f in ("system_state.json", "baseline_snapshots.jsonl")]
    learned_files = phase_files + [
        os.path.join(base, f) for f in (
            "entity_profiles.json", "entity_risk_scores.json",
            "rl_state.json", "gcn_lof_model.json", "siem_logs.jsonl",
            # runs.json included: hash-keyed ingest resumability reads chunk
            # keys from run records — leaving them behind after a learned
            # reset skips re-ingesting identical files into wiped state
            # (dry-run find, 2026-11-17)
            "runs.json",
        )
    ] + [peer_path]
    # Stage-4 rehearsal find #5: the calibration/feedback stores are LEARNED
    # state (Phase 3 created them after the scopes were defined) — resets
    # never cleared them, so thresholds and labels survived every scope
    # (found live: Tuesday's 42 labels + 2.25 threshold outlived three
    # `reset --scope all` runs during the rehearsal)
    fb_dir = os.path.join(base, "feedback")
    if os.path.isdir(fb_dir):
        import glob as _glob
        learned_files += _glob.glob(os.path.join(fb_dir, "*.json*"))
    all_files = learned_files + [
        os.path.join(base, f) for f in (
            "incidents.json", "runs.json", "environment_context.json",
            "watchlists.json",
        )
    ]
    return {"phase-only": phase_files, "learned": learned_files, "all": all_files}[scope]


@app.command(name="reset")
def reset(
    scope: str = typer.Option("learned", help="phase-only | learned | all"),
    yes: bool = typer.Option(False, "--yes", help="Skip confirmation prompt (non-interactive)"),
):
    """Reset Nabla state for course cohorts / fresh baselines (phase-mechanics plan).

    phase-only: phase state + baseline snapshots (profiles survive).
    learned:   + entity profiles, risk, peers, RL, GCN-LOF model, cursors, calibration/feedback
    all:       + incidents, run history, environment context, watchlists
               (auth users and connector credentials always survive).
    """
    from nabla.config import get_settings
    from nabla.log import get_logger
    import os

    if scope not in ("phase-only", "learned", "all"):
        typer.echo(f"Unknown scope: {scope} (phase-only | learned | all)")
        raise typer.Exit(code=1)

    settings = get_settings()
    files = _reset_files(scope, settings.data_dir)
    typer.echo(f"\n  Reset scope '{scope}' will DELETE:")
    for f in files:
        mark = "" if os.path.exists(f) else "  (absent)"
        typer.echo(f"    {os.path.basename(f)}{mark}")
    if scope == "all":
        typer.echo("  Surviving: users.json, jwt_secret, connector credentials (env), logs/")
    typer.echo()

    if not yes:
        confirm = typer.confirm("This cannot be undone. Continue?")
        if not confirm:
            typer.echo("  Aborted.")
            raise typer.Exit()

    logger = get_logger("cli.reset")
    deleted = 0
    for f in files:
        for variant in (f, f + ".lock"):
            try:
                if os.path.exists(variant):
                    os.remove(variant)
                    deleted += 1
            except OSError as e:
                typer.echo(f"    could not remove {os.path.basename(variant)}: {e}")
    logger.warning("RESET by operator: scope=%s, %d files deleted", scope, deleted)
    typer.echo(f"  Deleted {deleted} files. Next ingestion starts a fresh baseline.")



def _chunk_hash(path: str) -> str:
    """Content hash of a chunk file (resumability key — review N2)."""
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()[:16]


def _landed_chunks() -> set[str]:
    """Chunk keys (name:hash) already ingested, from run records."""
    from nabla.history import list_runs
    landed = set()
    for run in list_runs(limit=200):
        for key in (run.get("ingest_chunks") or []):
            landed.add(key)
    return landed


@app.command(name="ingest")
def ingest(
    path: str = typer.Argument(..., help="Dataset directory or single JSONL file"),
    siem_data: bool = typer.Option(False, "--siem-data", help="Treat as real captured SIEM telemetry: advances the data-span phase clock (course datasets)"),
    frozen_baseline: bool = typer.Option(False, "--frozen-baseline", help="Skip baseline/profile updates (attack-phase import: anomalies fire against the frozen baseline)"),
    graph: bool = typer.Option(False, "--graph", help="Enable graph layers (provenance/temporal) — OFF by default for bulk import (Gate 0: OOM above ~20K events/chunk)"),
    gcn_lof: bool = typer.Option(False, "--gcn-lof", help="Enable GCN-LOF (experimental; disabled by default per R3)"),
    chunk_size: int = typer.Option(15000, help="Max events per chunk when splitting large files"),
    verify: str = typer.Option(None, help="scenario.json path: after ingest, compare actual incidents against the answer key"),
):
    """Ingest a course dataset (baseline or attack phase) from JSONL files.

    The course-dataset counterpart to `nabla run` (sumologic-import plan):
    chunked, resumable, provenance-aware. Baseline phase:
      nabla ingest dataset/baseline/ --siem-data
    Attack phase (profiles frozen):
      nabla ingest dataset/attacks/ --siem-data --frozen-baseline --graph
    """
    import glob as _glob
    import hashlib
    import os as _os
    from datetime import datetime, timedelta, timezone as _tz

    from nabla.pipeline import run_pipeline
    from nabla.client import get_client as _get_client

    # Collect chunk files
    if _os.path.isdir(path):
        files = sorted(
            f for f in _glob.glob(_os.path.join(path, "*.jsonl"))
            if ".part" not in _os.path.basename(f)  # stray split temps from killed runs
        )
    elif _os.path.isfile(path):
        files = [path]
    else:
        typer.echo(f"Error: {path} not found", err=True)
        raise typer.Exit(1)
    if not files:
        typer.echo(f"Error: no .jsonl files in {path}", err=True)
        raise typer.Exit(1)

    landed = _landed_chunks()
    client = _get_client()
    total_landed = 0
    all_chunk_timestamps: list[str] = []

    for f in files:
        name = _os.path.basename(f)
        if _os.path.getsize(f) == 0:
            typer.echo(f"  ! {name} is empty (zero bytes) — skipped (stale export chunk?)", err=True)
            continue
        key = f"{name}:{_chunk_hash(f)}"
        if key in landed:
            typer.echo(f"  = {name} (already landed, hash match — skipped)")
            continue

        # Count lines; split oversized files into temp chunks
        n_events = sum(1 for _ in open(f))
        sub_files = [f]
        if n_events > chunk_size:
            sub_files = []
            base_noext = f.rsplit(".", 1)[0]
            with open(f) as src:
                idx = 0
                while True:
                    lines = [src.readline() for _ in range(chunk_size)]
                    lines = [l for l in lines if l]
                    if not lines:
                        break
                    sub = f"{base_noext}.part{idx:03d}.jsonl"
                    with open(sub, "w") as out:
                        out.writelines(lines)
                    sub_files.append(sub)
                    idx += 1
            typer.echo(f"  {name}: {n_events} events → {len(sub_files)} chunks (cap {chunk_size})")

        for sub in sub_files:
            typer.echo(f"  ▶ {name} → {_os.path.basename(sub)} ...", nl=False)
            # Extract timestamps from the chunk for span tracking (siem-data)
            import json as _json
            ts_list = []
            if siem_data:
                with open(sub) as sf:
                    for line in sf:
                        try:
                            ev = _json.loads(line)
                            if ev.get("timestamp"):
                                ts_list.append(str(ev["timestamp"]))
                        except Exception:
                            pass  # silent by design: unparseable line in span scan (2026-09 sweep)

            results = run_pipeline(
                client,
                source="file",
                file_path=sub,
                file_format="jsonl",
                log_count=10**9,  # no truncation
                update_baseline=not frozen_baseline,
                skip_graph=not graph,
                gcn_lof_enabled=gcn_lof,
                ingest_meta={
                    "ingest_chunks": [key],
                    "ingest_siem_data": siem_data,
                    "ingest_frozen_baseline": frozen_baseline,
                },
            )
            if siem_data and ts_list:
                # Advance the data-span clock on real telemetry (file transport)
                from nabla.system_state import load_system_state, record_ingestion, save_system_state
                st_path = get_settings().system_state_file
                state = load_system_state(st_path)
                state = record_ingestion(state, "sumologic", entry_timestamps=ts_list)
                save_system_state(st_path, state)
                all_chunk_timestamps.extend(ts_list)
            total_landed += 1
            typer.echo(" done")

        # Clean up temp sub-chunks
        if sub_files != [f]:
            for sub in sub_files:
                try:
                    _os.remove(sub)
                except OSError:
                    pass  # silent by design: temp cleanup best-effort (2026-09 sweep)

    # Stale-attack-window warning (review N1): attack timestamps vs digest window
    if siem_data and all_chunk_timestamps:
        newest = max(all_chunk_timestamps)
        try:
            newest_dt = datetime.fromisoformat(newest.replace("Z", "+00:00"))
            if newest_dt.tzinfo is None:
                newest_dt = newest_dt.replace(tzinfo=_tz.utc)  # naive -> UTC (real-slice timestamps)
            age_days = (datetime.now(_tz.utc) - newest_dt).days
            if age_days > 7:
                typer.echo(
                    f"\n  ⚠ WARNING: newest ingested event is {age_days} days old — beyond the "
                    f"supervisor's 7-day incident-digest window. Campaign-reference context will "
                    f"be EMPTY for this scenario (anomalies/risk still fire on data time).",
                    err=True,
                )
                logger.warning("Ingest: attack window predates digest window by %dd", age_days)
        except ValueError:
            pass  # silent by design: unparseable newest timestamp (2026-09 sweep)

    typer.echo(f"\n  Ingest complete: {total_landed} chunks landed, {len(files)} file(s).")

    if verify:
        _verify_scenario(verify)


if __name__ == "__main__":
    app()


def _verify_scenario(scenario_path: str):
    """Compare actual incidents against the scenario answer key (--verify)."""
    import json as _json
    from pathlib import Path as _P

    if not _P(scenario_path).exists():
        typer.echo(f"Error: {scenario_path} not found", err=True)
        raise typer.Exit(1)
    scenario = _json.loads(_P(scenario_path).read_text())
    expected = scenario.get("expected_findings", [])

    from nabla.incidents import list_incidents
    actual = list_incidents(limit=500)
    actual_by_entity: dict[str, list] = {}
    for inc in actual:
        actual_by_entity.setdefault(inc.get("entity", "?"), []).append(inc)

    typer.echo("\n=== Scenario Verification ===")
    matched, missed, extra = 0, 0, 0
    for exp in expected:
        entity = exp.get("entity", "?")
        want_types = set(exp.get("expected_detectors", []))
        hits = actual_by_entity.get(entity, [])
        hit_types = {a.get("finding_type", "") for a in hits}
        # Match if any expected detector appears in any incident type for the entity
        entity_types = set()
        for a in hits:
            for t in str(a.get("finding_type", "")).split(","):
                entity_types.add(t.strip())
        if want_types & entity_types:
            matched += 1
            typer.echo(f"  ✓ {entity}: {', '.join(sorted(want_types & entity_types))}")
        else:
            missed += 1
            typer.echo(f"  ✗ {entity}: expected {', '.join(sorted(want_types))} — got {sorted(entity_types) or 'nothing'}")

    expected_entities = {e.get("entity") for e in expected}
    for entity, incs in actual_by_entity.items():
        if entity not in expected_entities and incs:
            extra += len(incs)
            typer.echo(f"  + unexpected: {entity} ({len(incs)} incidents)")

    typer.echo(f"\n  Result: {matched} matched, {missed} missed, {extra} unexpected")
    typer.echo("  (Mismatches are course content — FP/FN discussion — not tool failures.)")
