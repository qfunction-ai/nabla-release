"""Pipeline orchestration — coordinates the full UEBA pipeline across all steps."""

from __future__ import annotations

import time

from letta_client import Letta

from nabla.agents.registry import find_all_agents
from nabla.config import get_settings
from nabla.history import new_run, complete_run, save_run
from nabla.ingest import store_baseline_snapshot
from nabla.log import get_logger
from nabla.pipeline.helpers import (
    _extract_count,
    _extract_host_processes_from_entries,
    _resolve_log_types,
)
from nabla.pipeline.ingestion import run_ingestion
from nabla.pipeline.detection import run_detection
from nabla.pipeline.correlation import run_correlation
from nabla.pipeline.supervisor import run_supervisor
from nabla.pipeline.rl_update import run_rl_update

logger = get_logger("pipeline.orchestration")


# Cap on persisted anomaly summaries per run (UI-2). 500 compact entries
# (~100-200 bytes each) bounds the run record at roughly 100KB.
ANOMALY_SUMMARY_CAP = 500

# Caps for the persisted findings summary and supervisor narrative (UI-4).
FINDINGS_SUMMARY_CAP = 100
NARRATIVE_CAP = 10_000  # characters


# N5 (round 4): the quarantine trigger's method hold list — the families
# whose severity ceiling is MEDIUM ALWAYS (detection.py's severity map,
# extracted in the round-4 plan): they gate attack classes that severity
# cannot express (the 3am insider fires entity_off_hours medium forever;
# under a severity-only gate that batch would absorb into hour_histogram
# and the compromise schedule would go baseline-normal within nights —
# A10 reborn). entity_unusual_process is belt-and-suspenders: it fires
# high (lolbin/attack only) so severity already reaches it.
QUARANTINE_HOLD_METHODS = {
    "off_hours", "entity_off_hours",
    "unusual_process", "entity_unusual_process",
    "pre_flagged",
    "cusum",
}

_QUARANTINE_SEVERITIES = {"high", "critical"}


def _quarantine_flagged_entities(anomalies: list[dict]) -> set[str]:
    """N5: entities worth a baseline hold. severity >= high OR a
    medium-ceiling hold-list method. Medium statistical noise (z at 2.1
    fires medium) no longer freezes a baseline per flag; the hold list
    keeps the attack classes only those detectors can see."""
    flagged: set[str] = set()
    for a in anomalies:
        entity = a.get("entity", a.get("user", ""))
        if not entity:
            continue
        sev = str(a.get("severity", "medium")).lower()
        method = str(a.get("detection_method", a.get("type", "")))
        if sev in _QUARANTINE_SEVERITIES or method in QUARANTINE_HOLD_METHODS:
            flagged.add(entity)
    return flagged


def _summarize_findings_for_run(findings: list) -> list[dict]:
    """Project correlation findings into the compact persisted shape."""
    out: list[dict] = []
    for f in (findings or [])[:FINDINGS_SUMMARY_CAP]:
        out.append({
            "entity": f.get("entity", "unknown"),
            "entity_type": f.get("entity_type", "unknown"),
            "type": f.get("type", "unknown"),
            "severity": f.get("severity", "medium"),
            "confidence": f.get("confidence", 0.5),
            "mitre_attack": [
                t if isinstance(t, str) else t.get("id", "")
                for t in (f.get("mitre_attack") or [])
            ][:6],
        })
    return out


def _compact_anomaly(a: dict) -> dict:
    """Project an anomaly dict to the compact persisted shape.

    Keys match what the timeline API and attribution endpoint read:
    entity/user, entity_type, severity, timestamp, detection_method/type,
    details, categories, mitre_attack.
    """
    return {
        "anomaly_id": a.get("anomaly_id", ""),
        "entity": a.get("entity", a.get("user", "")),
        "entity_type": a.get("entity_type", "user"),
        "severity": a.get("severity", "medium"),
        "timestamp": a.get("timestamp", a.get("detected_at", "")),
        "detection_method": a.get("detection_method", a.get("type", "unknown")),
        "details": str(a.get("details", a.get("description", "")))[:200],
        "categories": a.get("categories", []),
        "mitre_attack": a.get("mitre_attack", []),
        # Phase 3: the label pipeline's per-anomaly record needs the raw
        # score compared against the threshold (gate 8 — calibrate() cannot
        # pick a precision-meeting threshold without it).
        "raw_score": a.get("raw_score"),
    }


def _summarize_anomalies_for_run(detection, anomaly_count: int) -> list[dict]:
    """Build the bounded anomaly list persisted into the run record."""
    if anomaly_count == 0 or detection is None:
        return []
    combined: list[dict] = []
    for bucket in (
        detection.anomalies,
        detection.gcn_lof_anomalies,
        detection.provenance_anomalies,
        detection.temporal_anomalies,
    ):
        combined.extend(bucket or [])
    # Keep the highest-severity entries when capping
    if len(combined) > ANOMALY_SUMMARY_CAP:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        combined.sort(key=lambda a: order.get(a.get("severity", "medium"), 2))
        combined = combined[:ANOMALY_SUMMARY_CAP]
    return [_compact_anomaly(a) for a in combined]


def _run_pipeline_body(
    client: Letta | None = None,
    log_types: list[str] | str = "all",
    log_count: int = 20,
    source: str = "auto",
    watchlist_groups: list[str] | None = None,
    reset_ingestion: bool = False,
    file_path: str | None = None,
    file_format: str | None = None,
    column_map: dict[str, str] | None = None,
    update_baseline: bool = False,
    skip_graph: bool = False,
    gcn_lof_enabled: bool = False,
    ingest_meta: dict | None = None,
) -> dict[str, str]:
    """Execute the full UEBA pipeline.

    Steps: ingest (Python function) → detect (deterministic) → correlate (deterministic) → supervisor

    Args:
        client: Letta client instance. If None, creates one.
        log_types: Log type(s) to generate. "all" for all 4 types.
        log_count: Number of log entries per type (synthetic only).
        source: Ingestion source — "auto", "synthetic", "splunk", or "file".
        watchlist_groups: Watchlist groups to target (None = all groups).
        reset_ingestion: Reset ingestion state for full re-pull.
        file_path: Path to log file (required when source="file").
        file_format: Format hint for file parsing ("csv", "json", "jsonl", "xml", "text").
        column_map: User-provided field mapping (canonical → raw column name).
        update_baseline: Whether file-sourced runs should update baselines.
            Defaults to false — file uploads are ad-hoc analysis and shouldn't
            shift the baseline. Set to true for onboarding a new log source.

    Returns {step: response} for each step.
    """
    if gcn_lof_enabled:
        _gcn_lof_warning()

    if client is None:
        from nabla.client import get_client
        client = get_client()


    agents = find_all_agents(client)
    if len(agents) < 1:
        raise RuntimeError(
            f"Expected 1 Nabla agent, found {len(agents)}. "
            "Run `nabla bootstrap` first."
        )

    settings = get_settings()
    types = _resolve_log_types(log_types)
    results = {}
    run_record = new_run(log_types=types, log_count=log_count, source=source)
    step_durations = {}
    degradations: list[str] = []  # A22: non-fatal failures surfaced in run status

    try:
        # ── Step 1: Log Ingestion ──────────────────────────────
        t0 = time.monotonic()
        ingestion = run_ingestion(
            client=client,
            agents=agents,
            settings=settings,
            log_types=log_types,
            log_count=log_count,
            source=source,
            watchlist_groups=watchlist_groups,
            reset_ingestion=reset_ingestion,
            file_path=file_path,
            file_format=file_format,
            column_map=column_map,
        )
        total_count = ingestion.total_normal + ingestion.total_anomalous
        results["ingestion"] = (
            f"Stored {total_count} logs across {len(types)} types "
            f"({ingestion.total_normal} normal, {ingestion.total_anomalous} anomalous) | "
            + " | ".join(ingestion.type_summaries)
        )
        step_durations["ingestion"] = time.monotonic() - t0

        # ── Step 2: Anomaly Detection ─────────────────────────
        t0 = time.monotonic()
        # Build watchlist for detection (same one used for ingestion)
        from nabla.watchlist import get_all_entities
        from nabla.connectors.base import Watchlist
        from nabla.pipeline.helpers import _filter_watchlist_by_groups
        watchlist_dict = get_all_entities(settings.effective_watchlist_path)
        watchlist = Watchlist.from_dict(watchlist_dict)
        if watchlist_groups:
            watchlist = _filter_watchlist_by_groups(settings.effective_watchlist_path, watchlist_groups)

        # F3: detectors swallow their own exceptions so one bad detector cannot
        # kill a run. That is right, but it meant a detector could fail on
        # every run and the run still reported clean — exfil_volume did
        # exactly that for a whole round. The collector routes those failures
        # into this run's degradations list.
        from nabla.degradations import collect_degradations
        with collect_degradations(degradations):
            detection = run_detection(
                client=client,
                agents=agents,
                settings=settings,
                all_entries=ingestion.entries,
                watchlist=watchlist,
                siem_entries_ingested=ingestion.siem_entries_ingested,
                effective_source=ingestion.effective_source,
                skip_graph=skip_graph,
                gcn_lof_enabled=gcn_lof_enabled,
            )
        results["anomaly"] = (
            f"Detected {len(detection.anomalies)} anomalies "
            f"({len(detection.gcn_lof_anomalies)} via GCN-LOF, "
            f"{len(detection.provenance_anomalies)} via provenance, "
            f"{len(detection.temporal_anomalies)} via temporal)"
        )
        step_durations["anomaly"] = time.monotonic() - t0
        logger.info(
            "Anomaly Detection completed in %.1fs — %d anomalies "
            "(%d via GCN-LOF, %d via provenance, %d via temporal)",
            step_durations["anomaly"], len(detection.anomalies),
            len(detection.gcn_lof_anomalies), len(detection.provenance_anomalies),
            len(detection.temporal_anomalies),
        )

        # File-sourced runs are ad-hoc analysis by default — they should NOT
        # update baselines, entity profiles, or phase state. The user uploaded
        # incident logs to analyze against the existing baseline, not to
        # shift it. Only SIEM/synthetic sources (or file with update_baseline=True)
        # update the baseline.
        skip_baseline = source == "file" and not update_baseline

        # Store baseline snapshot (skip for ad-hoc file uploads)
        try:
            if detection.baselines and not skip_baseline:
                host_processes = _extract_host_processes_from_entries(ingestion.entries)
                store_baseline_snapshot(detection.baselines, host_processes)
                logger.info("Baseline snapshot stored")
        except Exception as e:
            logger.warning("Failed to store baseline snapshot: %s", e)
            degradations.append("baseline_snapshot")

        # A10: flag quarantine for entities that fired anomalies this run
        # (detection phase only — baseline-phase runs ARE the absorption)
        # N5 (round 4): severity gate + explicit hold list. The old code
        # flagged EVERY entity with ANY anomaly — medium statistical noise
        # froze baselines for a week per flag. Gate on severity
        # {high, critical} OR method in QUARANTINE_HOLD_METHODS (the
        # medium-CEILING families that gate attack classes severity can't
        # express: off_hours, unusual_process, pre_flagged, cusum-drift —
        # review REQUIRED 1: severity-only would make the 3am-insider case
        # absorb straight into baselines, A10 reborn).
        if detection.phase != "baseline" and detection.anomalies:
            try:
                from nabla.baselines import flag_quarantine
                from nabla.risk import _data_clock
                flagged = _quarantine_flagged_entities(detection.anomalies)
                if flagged:
                    flag_quarantine(flagged, data_clock=_data_clock())
            except Exception as e:
                logger.warning("Quarantine flagging failed (non-fatal): %s", e)
                degradations.append("quarantine_flagging")

        # Update entity profiles (skip for ad-hoc file uploads)
        if detection.entity_profiles is not None and not skip_baseline:
            try:
                # N-2 (round 7): advance this source's watermark IN MEMORY
                # first — the update loop and the sweep close hours against
                # it. R-17: it persists only AFTER the profile save (a
                # crash then leaves profile-behind-watermark, which the
                # idempotent close absorbs on replay — the harmless side).
                from nabla.pipeline.watermark import newest_event_ts
                from nabla.system_state import advance_source_watermark
                advance_source_watermark(
                    detection.sys_state, ingestion.effective_source,
                    newest_event_ts(ingestion.entries))
                from nabla.system_state import source_watermarks_view
                _src_wm = source_watermarks_view(detection.sys_state).get(
                    ingestion.effective_source, "")
                # N3 (round 4) + STRONG 2: drain approved batches FIRST, at
                # pipeline start, for ALL approved entities — inside this
                # load-save window (the API path never writes profiles; it
                # raced the pipeline and lost, which is how held data died).
                # Also drain TTL-released holds (final-review REQUIRED 1:
                # expiry means "review window elapsed, treat as normal").
                from nabla.baselines import drain_approved_pending, drain_released_pending
                approved = drain_approved_pending(detection.entity_profiles)
                ttl_released, ttl_holds = drain_released_pending(detection.entity_profiles)
                if approved or ttl_released:
                    logger.info(
                        "Quarantine drain: %d approved batches, %d TTL-released (commit deferred to post-save)",
                        sum(len(v) for v in approved.values()),
                        sum(len(v) for v in ttl_released.values()))
                from nabla.baselines import group_entries_by_entity
                groups = group_entries_by_entity(ingestion.entries)
                for (entity_type, entity_id), group_entries in groups.items():
                    if entity_type == "user":
                        detection.entity_profiles.update_user(
                            entity_id, group_entries,
                            source_kind=ingestion.effective_source,
                            watermark=_src_wm)
                    elif entity_type == "host":
                        detection.entity_profiles.update_host(entity_id, group_entries)
                    elif entity_type == "ip":
                        detection.entity_profiles.update_ip(entity_id, group_entries)
                # R-16 (round 7): end-of-run close sweep — quiet entities'
                # finished hours close against their own source's watermark
                # (recorded like live closes, never treated as late).
                # Runs BEFORE the save (R-17).
                from nabla.baselines import sweep_profile_hours
                swept = sweep_profile_hours(
                    detection.entity_profiles, detection.sys_state)
                if swept:
                    logger.info("Clock sweep: %d quiet-entity hours closed",
                                swept)
                detection.entity_profiles.save()
                # R6-16 + R-11 + R-3 (round 7): commit the drains AFTER
                # the profile save — the save is what makes the drained
                # batch IDs durable, so a crash before the commit replays
                # as a no-op instead of losing the verdict. SELECTIVE:
                # only the drained batches are removed; a verdict that
                # arrived mid-run survives for the next run.
                from nabla.baselines import commit_drain_after_save
                commit_drain_after_save(approved, ttl_released, ttl_holds)
                # R-17 (round 7): the watermark persists AFTER the profile
                # save — the save is what makes the closed hours durable.
                from nabla.system_state import save_source_watermarks
                save_source_watermarks(
                    settings.system_state_file, detection.sys_state)
                logger.info(
                    "Entity profiles updated: %d users, %d hosts, %d IPs",
                    len(detection.entity_profiles.users), len(detection.entity_profiles.hosts), len(detection.entity_profiles.ips),
                )
            except Exception as e:
                logger.warning("Failed to update entity profiles (non-fatal): %s", e)
                degradations.append("entity_profiles")

        # Compute peer groups (skip for ad-hoc file uploads)
        peer_groups = None
        if detection.entity_profiles is not None and not skip_baseline:
            try:
                from nabla.peer_groups import compute_peer_groups
                peer_groups = compute_peer_groups(
                    detection.entity_profiles,
                    recompute_interval=settings.peer_group_recompute_interval,
                )
                logger.info("Peer groups computed: %d groups", len(peer_groups.groups))
            except Exception as e:
                logger.warning("Peer group computation failed (non-fatal): %s", e)

        # Check for baseline → detection phase transition (skip for ad-hoc)
        if detection.phase == "baseline" and not skip_baseline:
            from nabla.system_state import (
                baseline_days_remaining, should_transition,
                transition_to_detection, save_system_state,
            )
            warm_user_count = 0
            if detection.entity_profiles is not None:
                warm_user_count = sum(
                    1 for u in detection.entity_profiles.users
                    if detection.entity_profiles.warm_up_complete("user", u)
                )
            if should_transition(detection.sys_state, warm_user_count):
                logger.info(
                    "Phase transition: baseline → detection (%d warm users)",
                    warm_user_count,
                )
                detection.sys_state = transition_to_detection(detection.sys_state)
                save_system_state(settings.system_state_file, detection.sys_state)
                detection.phase = "detection"
            else:
                remaining = baseline_days_remaining(detection.sys_state)
                logger.info(
                    "Still in baseline phase (%d warm users, ~%s days remaining)",
                    warm_user_count, remaining if remaining is not None else "?",
                )

        # ── Step 3: Threat Correlation ─────────────────────────
        t0 = time.monotonic()
        correlation = run_correlation(
            client=client,
            agents=agents,
            anomalies=detection.anomalies,
            graph_context_text=detection.graph_context_text,
            provenance_graph=detection.provenance_graph,
            provenance_communities=detection.provenance_communities,
            provenance_anomalies=detection.provenance_anomalies,
            entity_profiles=detection.entity_profiles,
        )
        results["correlation"] = f"Correlated anomalies into {correlation.findings_count} findings"
        step_durations["correlation"] = time.monotonic() - t0
        logger.info("Threat Correlation completed in %.1fs", step_durations["correlation"])

        # ── Step 4: Supervisor ─────────────────────────────────
        t0 = time.monotonic()
        supervisor_text = run_supervisor(
            client=client,
            agents=agents,
            findings_count=correlation.findings_count,
            findings_text=correlation.findings_text,
            phase=detection.phase,
        )
        results["supervisor"] = supervisor_text
        step_durations["supervisor"] = time.monotonic() - t0
        logger.info("Supervisor completed in %.1fs", step_durations["supervisor"])

        # ── Step 4b: Persist incidents ──────────────────────────
        # The bounded anomaly summary is built HERE (before incident creation)
        # because save_incidents loads it from history for the contributing-
        # anomaly linkage — persisting it only at completion left the linkage
        # reading an empty/absent record (dry-run find: incident ids: 0).
        run_record["anomalies"] = _summarize_anomalies_for_run(
            detection, len(detection.anomalies) if detection.anomalies else 0
        )
        save_run(run_record)
        if correlation.findings:
            try:
                from nabla.incidents import save_incidents
                new_incidents = save_incidents(
                    run_id=run_record["run_id"],
                    findings=correlation.findings,
                    supervisor_text=supervisor_text,
                    evidence_text=correlation.explanation_text,
                )
                if new_incidents > 0:
                    logger.info("Incident persistence: %d new incidents saved", new_incidents)
            except Exception as e:
                logger.warning("Incident persistence failed (non-fatal): %s", e)
                degradations.append("incident_persistence")

        # ── Step 4c: Update entity risk scores ──────────────────
        try:
            from nabla.risk import compute_risk_scores
            from nabla.rl.bandit import DetectionMethodBandit
            # A5: wire the bandit for Bayesian weight adjustment (neutral
            # weights until Phase 3 feeds it real labels — the wiring is real now)
            bandit_store = DetectionMethodBandit.load(settings.rl_state_file)
            # Build entity type map from entity profiles
            entity_type_map: dict[str, str] = {}
            if detection.entity_profiles is not None:
                for eid in detection.entity_profiles.users:
                    entity_type_map[eid] = "user"
                for eid in detection.entity_profiles.hosts:
                    entity_type_map[eid] = "host"
                for eid in detection.entity_profiles.ips:
                    entity_type_map[eid] = "ip"

            # CLOCK-SPEC Rule 4 (round 6): per-entity EVENT clocks — each
            # entity's newest VALID event this batch, attributed exactly as
            # risk attributes anomalies (risk_entities), so hosts advance
            # too (C6). Events, not anomalies: flagged-once users who keep
            # working still decay (R6-4).
            from nabla.risk import risk_entities as _re
            _ev_clocks: dict[str, str] = {}
            for _e in (ingestion.entries or []):
                _ts = str(_e.get("timestamp", "") or "")
                if not _ts:
                    continue  # absent means absent
                for _eid, _et in _re(_e):
                    if _ts > _ev_clocks.get(_eid, ""):
                        _ev_clocks[_eid] = _ts

            risk_store = compute_risk_scores(
                anomalies=detection.anomalies,
                entity_type_map=entity_type_map,
                temporal_chains=detection.temporal_chains if detection.temporal_chains else [],
                watchlist=watchlist,
                peer_groups=peer_groups,
                bandit_store=bandit_store,
                half_life_hours=settings.risk_score_decay_half_life_hours,
                max_anomalies=settings.risk_score_max_anomalies,
                event_clocks=_ev_clocks,
            )
            high_risk = sum(1 for s in risk_store.scores.values() if s.overall >= settings.risk_score_investigation_cutoff)
            if high_risk > 0:
                logger.info("Risk scores: %d entities above investigation cutoff (%.0f)", high_risk, settings.risk_score_investigation_cutoff)
        except Exception as e:
            logger.warning("Risk score update failed (non-fatal): %s", e)
            degradations.append("risk_scores")

        # ── Step 5: RL update ──────────────────────────────────
        t0 = time.monotonic()
        if skip_baseline:
            logger.info("RL update: skipped (ad-hoc file analysis)")
        elif detection.phase == "baseline":
            logger.info("RL update: skipped (baseline phase)")
        else:
            try:
                run_rl_update(client, agents, results)
                step_durations["rl"] = time.monotonic() - t0
                logger.info("RL update completed in %.1fs", step_durations["rl"])
            except Exception as e:
                logger.warning("RL update failed (non-fatal): %s", e)

        # ── Finalize run record ────────────────────────────────
        anomaly_count = len(detection.anomalies) if detection.anomalies else 0
        findings_count = _extract_count(results["correlation"])
        complete_run(
            run_record,
            anomaly_count=anomaly_count,
            findings_count=findings_count,
            step_durations=step_durations,
        )
        # (anomaly summary moved to pre-incident, above)
        # Persist findings summary + supervisor narrative (UI-4): the run
        # detail view and history table consume these.
        run_record["findings"] = _summarize_findings_for_run(
            correlation.findings if correlation else []
        )
        # Course-ingest provenance (sumologic-import plan): chunk key for
        # resumability + siem-data/frozen-baseline flags land on the record.
        if ingest_meta:
            run_record.update(ingest_meta)

        # Per-layer counts INCLUDING zeros (silent-swallow sweep) — a dead
        # layer reports 0 rather than vanishing from the record.
        run_record["degradations"] = degradations  # A22: surfaced in UI as a degraded-run indicator
        run_record["layer_counts"] = {
            "base": len(detection.anomalies) if detection else 0,
            "gcn_lof": len(detection.gcn_lof_anomalies) if detection else 0,
            "provenance": len(detection.provenance_anomalies) if detection else 0,
            "temporal": len(detection.temporal_anomalies) if detection else 0,
            "exfiltration": getattr(detection, "exfiltration_count", 0),
        }
        # N7: chain-gate fallback uses (0 once every merged anomaly carries
        # event_ids; >0 means a producer is not stamping — visible, not silent)
        run_record["temporal_stats"] = (
            dict(getattr(detection, "temporal_stats", {})) if detection else {}
        )
        run_record["supervisor_narrative"] = (
            (results.get("supervisor") or "")[:NARRATIVE_CAP] or None
        )

        total_duration = sum(step_durations.values())
        logger.info(
            "Pipeline completed in %.1fs — "
            "ingestion: %.1fs, anomaly: %.1fs, correlation: %.1fs, "
            "supervisor: %.1fs, anomalies=%s, findings=%s",
            total_duration,
            step_durations.get("ingestion", 0),
            step_durations.get("anomaly", 0),
            step_durations.get("correlation", 0),
            step_durations.get("supervisor", 0),
            anomaly_count,
            findings_count,
        )

    except Exception as e:
        complete_run(run_record, error=str(e))
        raise

    finally:
        save_run(run_record)

    return results


def _gcn_lof_warning() -> None:
    """N11 (round 4): GCN-LOF stays disabled by default; when explicitly
    turned on, say WHY, loudly — an operator flipping the flag must know
    what the benign-rate ceiling was before trusting its output."""
    import sys
    print(
        "WARNING: GCN-LOF is EXPERIMENTAL and disabled by default for a "
        "reason (round 3, R3): under the current z-score/bank anchoring "
        "it flagged 13-18% of BENIGN entities (77% of them high "
        "severity), poisoning quarantine and correlation. Full fix "
        "(percentile redesign + harness <1% benign ceiling) is deferred "
        "— treat every GCN-LOF finding as unvetted signal.",
        file=sys.stderr,
    )


def run_pipeline(
    client: Letta | None = None,
    log_types: list[str] | str = "all",
    log_count: int = 20,
    source: str = "auto",
    watchlist_groups: list[str] | None = None,
    reset_ingestion: bool = False,
    file_path: str | None = None,
    file_format: str | None = None,
    column_map: dict[str, str] | None = None,
    update_baseline: bool = False,
    skip_graph: bool = False,
    gcn_lof_enabled: bool = False,
    ingest_meta: dict | None = None,
) -> dict[str, str]:
    """Public entry: the pipeline body under the R6-8 run guard (per-call
    scope — same-process sequential runs like the CLI chunk loop compose;
    concurrent runs across processes fail fast, never queue). Signature
    mirrors the body exactly (introspection-friendly: N11's default check
    reads it)."""
    from nabla.pipeline.run_guard import acquire_run_guard
    guard = acquire_run_guard()
    try:
        return _run_pipeline_body(client, log_types=log_types, log_count=log_count,
                                  source=source, watchlist_groups=watchlist_groups,
                                  reset_ingestion=reset_ingestion, file_path=file_path,
                                  file_format=file_format, column_map=column_map,
                                  update_baseline=update_baseline, skip_graph=skip_graph,
                                  gcn_lof_enabled=gcn_lof_enabled, ingest_meta=ingest_meta)
    finally:
        guard.release()
