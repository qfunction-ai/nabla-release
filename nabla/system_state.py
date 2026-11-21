"""System phase tracking for baseline learning vs detection.

Nabla operates in two phases:
- **baseline**: Building entity profiles from SIEM data. Signature-based
  detection is active, but baseline-dependent methods (z-score, off-hours,
  activity spike, etc.) are suppressed to avoid false positives from
  incomplete baselines. The supervisor LLM is also skipped.
- **detection**: All detection methods active. Supervisor reviews findings
  and generates incident reports.

The transition from baseline → detection happens when:
1. ``first_ingestion_at`` is at least ``baseline_min_days`` ago
2. Entity profiles have sufficient observations (≥3 users with warm-up complete)

Once in detection phase, the system never returns to baseline.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from nabla.log import get_logger

logger = get_logger("system_state")

# Detection methods that require mature baselines to be meaningful.
# These are suppressed during the baseline phase.
BASELINE_DEPENDENT_METHODS = frozenset({
    "z_score",
    "entity_z_score",
    "failed_login_ratio",
    "entity_auth_failure",
    "off_hours",
    "entity_off_hours",
    "multi_ip",
    "entity_new_ip",
    "activity_spike",
    "entity_activity_spike",
    "unusual_process",
    "entity_new_process",
    "entity_unusual_process",
    "ewma",
    "cusum",
    "entity_behavior_composite",
    "entity_host_composite",
})

# Detection methods that are always active — signature-based or structural.
# These don't depend on statistical baselines.
ALWAYS_ACTIVE_METHODS = frozenset({
    "pre_flagged",
    "lolbin",
    "parent_child",
    "critical_host_escalation",
    "attack_script",
    "renamed_tool",
    "enumeration_behavior",
    "action_sequence",
    "suspicious_path",
    "integrity_anomaly",
    "registry_abuse",
    "network_anomaly",
    "gcn_lof",
    "provenance_community",
    "temporal_chain",
})


def _default_state() -> dict[str, Any]:
    """Return a default system state dict."""
    return {
        "phase": "baseline",
        "first_ingestion_at": None,
        "baseline_min_days": 21,
        "transitioned_at": None,
    }


def load_system_state(path: str) -> dict[str, Any]:
    """Load system state from a JSON file.

    Returns default state if the file doesn't exist or is corrupted.
    """
    if not os.path.exists(path):
        return _default_state()
    try:
        with open(path, "r") as f:
            data = json.load(f)
        # Ensure all expected keys exist
        defaults = _default_state()
        for key in defaults:
            if key not in data:
                data[key] = defaults[key]
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load system state from %s: %s — using defaults", path, e)
        return _default_state()


def save_system_state(path: str, state: dict[str, Any]) -> None:
    """Save system state to a JSON file atomically."""
    from nabla.persistence import atomic_write_json
    try:
        atomic_write_json(path, state)
    except OSError as e:
        logger.warning("Cannot write system state to %s: %s", path, e)


def should_transition(
    state: dict[str, Any],
    warm_user_count: int = 0,
    entity_profiles: Any = None,
    entity_warmup_observations: int = 3,
) -> bool:
    """Check whether the system should transition from baseline to detection.

    Transition conditions:
    1. first_ingestion_at is at least baseline_min_days ago
    2. Entity profiles have ≥3 users with observation_count >= warm-up threshold

    Args:
        state: Current system state dict.
        warm_user_count: Number of users with warm-up complete. If >0,
            used directly instead of counting from entity_profiles.
        entity_profiles: EntityProfileStore instance (optional, used if
            warm_user_count is 0).
        entity_warmup_observations: Minimum observations for warm-up.

    Returns:
        True if the system should transition to detection phase.
    """
    if state.get("phase") == "detection":
        return False  # Already in detection phase

    first_ingestion = state.get("first_ingestion_at")
    if not first_ingestion:
        return False  # No SIEM ingestion yet

    # Time-based condition: ingested-data span when available, wall-clock
    # fallback otherwise (phase-mechanics — span measures history directly;
    # the fallback preserves pre-upgrade deployments).
    baseline_min_days = state.get("baseline_min_days", 21)
    from nabla.utils import parse_iso_timestamp

    span_days = _baseline_span_days(state)
    if span_days is not None:
        if span_days < baseline_min_days:
            return False
    else:
        first_dt = parse_iso_timestamp(first_ingestion)
        if first_dt is None:
            return False
        elapsed_days = (datetime.now(timezone.utc) - first_dt).total_seconds() / 86400
        if elapsed_days < baseline_min_days:
            return False

    # Check entity profile condition
    if warm_user_count > 0:
        if warm_user_count < 3:
            return False
    elif entity_profiles is not None:
        warm_users = 0
        for user_id, profile in entity_profiles.users.items():
            if profile.observation_count >= entity_warmup_observations:
                warm_users += 1
        if warm_users < 3:
            return False

    return True


def transition_to_detection(state: dict[str, Any]) -> dict[str, Any]:
    """Mark the system as transitioned to detection phase.

    Returns the updated state dict (does not save to disk).
    """
    state["phase"] = "detection"
    state["transitioned_at"] = datetime.now(timezone.utc).isoformat()
    return state


def record_ingestion(
    state: dict[str, Any],
    source: str,
    entry_timestamps: list[str] | None = None,
) -> dict[str, Any]:
    """Record a successful SIEM ingestion — first-ingestion anchor + data span.

    Only counts real SIEM sources (splunk, sumologic), not synthetic or file.
    Tracks the min/max event timestamps of real-SIEM batches so the phase
    clock can measure ingested-history span rather than wall-clock patience
    (phase-mechanics plan, 2026-09-03).
    Returns the updated state dict (does not save to disk).
    """
    if source not in ("splunk", "sumologic"):
        return state  # Synthetic/file don't count as first SIEM ingestion

    if state.get("first_ingestion_at") is None:
        state["first_ingestion_at"] = datetime.now(timezone.utc).isoformat()
        logger.info("First SIEM ingestion recorded: %s (source=%s)", state["first_ingestion_at"], source)

    # Data-span tracking: running min/max of real-SIEM event timestamps
    from nabla.utils import parse_iso_timestamp

    parsed = [parse_iso_timestamp(str(ts)) for ts in (entry_timestamps or [])]
    parsed = [p for p in parsed if p is not None]
    # N-5 (round 7): the Rule 2 ceiling INSIDE the span tracker. The CLI
    # feeds RAW file timestamps here (its own scan bypasses
    # normalize_and_validate), and the tracker used to take max() with
    # no bound — one 2099 stamp in a file poisoned data_newest_ts (and
    # with it the __legacy__ watermark view). R6-1's disease, resurrected
    # through the CLI path; the ceiling belongs where the data lands.
    from nabla.pipeline.clock_ingestion import future_ceiling
    ceiling = future_ceiling()
    poisoned = [p for p in parsed if p > ceiling]
    if poisoned:
        logger.warning(
            "span tracker: dropped %d future-stamped events past the "
            "Rule 2 ceiling (newest offender %s)",
            len(poisoned), max(poisoned).isoformat())
    parsed = [p for p in parsed if p <= ceiling]
    if parsed:
        batch_oldest = min(parsed).isoformat()
        batch_newest = max(parsed).isoformat()
        prev_oldest = state.get("data_oldest_ts")
        prev_newest = state.get("data_newest_ts")
        old_dt = parse_iso_timestamp(prev_oldest) if prev_oldest else None
        new_dt = parse_iso_timestamp(prev_newest) if prev_newest else None
        if old_dt is None or min(parsed) < old_dt:
            state["data_oldest_ts"] = batch_oldest
        if new_dt is None or max(parsed) > new_dt:
            state["data_newest_ts"] = batch_newest
        logger.info(
            "Ingestion data span: batch %s..%s (overall %s..%s)",
            batch_oldest[:10], batch_newest[:10],
            state.get("data_oldest_ts", "?")[:10], state.get("data_newest_ts", "?")[:10],
        )
    return state


def advance_source_watermark(state: dict[str, Any], source: str,
                             newest_ts: str) -> dict[str, Any]:
    """N-2 (round 7): advance this source's watermark, monotone (never
    moves backwards). Mutates the IN-MEMORY state dict; the caller
    persists it AFTER the profile store save (R-17 order — a crash can
    then only leave the harmless profile-behind-watermark state, which
    the registry's idempotent close absorbs)."""
    if not source or not newest_ts:
        return state
    wms: dict[str, str] = dict(state.get("source_watermarks") or {})
    prev = wms.get(source) or ""
    from nabla.utils import parse_iso_timestamp
    prev_dt = parse_iso_timestamp(prev) if prev else None
    new_dt = parse_iso_timestamp(newest_ts)
    if new_dt is not None and (prev_dt is None or new_dt > prev_dt):
        wms[source] = newest_ts
        state["source_watermarks"] = wms
    return state


def source_watermarks_view(state: dict[str, Any]) -> dict[str, str]:
    """The per-source watermarks plus the reserved __legacy__ view (the
    migrated single-accumulator hours close against the data clock —
    any real-SIEM batch advances it)."""
    from nabla.pipeline.watermark import LEGACY_SOURCE
    view = {k: str(v or "") for k, v in (state.get("source_watermarks") or {}).items()}
    view[LEGACY_SOURCE] = str(state.get("data_newest_ts") or "")
    return view


def save_source_watermarks(path: str, state: dict[str, Any]) -> None:
    """R-17: persist ONLY the source watermarks into the state file,
    read-modify-write (the pipeline holds the run lock; the API path
    never writes system state). Called after the profile store save."""
    wms = state.get("source_watermarks")
    if not wms:
        return
    current = load_system_state(path)
    current["source_watermarks"] = wms
    save_system_state(path, current)


def _baseline_span_days(state: dict[str, Any]) -> float | None:
    """Days of ingested real-SIEM history (oldest→newest event), or None."""
    from nabla.utils import parse_iso_timestamp

    oldest = parse_iso_timestamp(state.get("data_oldest_ts") or "")
    newest = parse_iso_timestamp(state.get("data_newest_ts") or "")
    if oldest is None or newest is None:
        return None
    return (newest - oldest).total_seconds() / 86400


def baseline_days_remaining(state: dict[str, Any]) -> int | None:
    """Return days remaining in baseline phase, or None if already in detection.

    Uses ingested-data span when available ("days of history"), wall-clock
    elapsed since first ingestion otherwise. Returns 0 if the baseline period
    is satisfied but the transition hasn't happened yet.
    """
    if state.get("phase") == "detection":
        return None

    baseline_min_days = state.get("baseline_min_days", 21)

    # Span of ingested real-SIEM history when available
    span_days = _baseline_span_days(state)
    if span_days is not None:
        remaining = baseline_min_days - span_days
        return max(0, int(remaining))

    first_ingestion = state.get("first_ingestion_at")
    if not first_ingestion:
        return None  # No SIEM ingestion yet

    from nabla.utils import parse_iso_timestamp
    first_dt = parse_iso_timestamp(first_ingestion)
    if first_dt is None:
        return None
    elapsed_days = (datetime.now(timezone.utc) - first_dt).total_seconds() / 86400
    remaining = baseline_min_days - elapsed_days
    return max(0, int(remaining))


def warm_up_summary(
    entity_profiles: Any = None,
    min_observations: int = 3,
) -> dict[str, Any]:
    """Compute warm-up progress summary from entity profiles.

    Args:
        entity_profiles: EntityProfileStore instance (optional).
        min_observations: Minimum observations for warm-up.

    Returns:
        Dict with warm_up counts and percentages per entity type.
    """
    result: dict[str, Any] = {
        "users": {"total": 0, "warm": 0, "pct": 0},
        "hosts": {"total": 0, "warm": 0, "pct": 0},
        "ips": {"total": 0, "warm": 0, "pct": 0},
        "min_observations": min_observations,
    }

    if entity_profiles is None:
        return result

    for entity_type, store_key in [("users", "users"), ("hosts", "hosts"), ("ips", "ips")]:
        store = getattr(entity_profiles, store_key, {})
        total = len(store)
        warm = 0
        for _eid, profile in store.items():
            if profile.observation_count >= min_observations:
                warm += 1
        result[entity_type] = {
            "total": total,
            "warm": warm,
            "pct": round(100 * warm / total) if total > 0 else 0,
        }

    return result


def format_phase_summary(
    state: dict[str, Any],
    warm_up: dict[str, Any] | None = None,
) -> str:
    """Format a human-readable phase summary for the CLI.

    Args:
        state: Current system state dict.
        warm_up: Warm-up summary dict (from warm_up_summary).

    Returns:
        Multi-line string summarizing current phase status.
    """
    phase = state.get("phase", "detection")
    lines = [f"Phase: {phase.upper()}"]

    if phase == "baseline":
        first_ing = state.get("first_ingestion_at")
        if first_ing:
            lines.append(f"First SIEM ingestion: {first_ing}")
            remaining = baseline_days_remaining(state)
            if remaining is not None:
                lines.append(f"Days until transition: {remaining}")
        else:
            lines.append("No SIEM ingestion recorded yet")
            lines.append("Transition requires: first SIEM ingestion + 21 days of data")

        lines.append("")
        lines.append("Active detection methods:")
        for method in sorted(ALWAYS_ACTIVE_METHODS):
            lines.append(f"  ✓ {method}")
        lines.append("")
        lines.append("Suppressed (waiting for baselines):")
        for method in sorted(BASELINE_DEPENDENT_METHODS):
            lines.append(f"  ✗ {method}")

        if warm_up:
            lines.append("")
            lines.append("Entity warm-up progress:")
            for entity_type in ("users", "hosts", "ips"):
                info = warm_up[entity_type]
                bar_len = 20
                filled = int(bar_len * info["pct"] / 100)
                bar = "█" * filled + "░" * (bar_len - filled)
                lines.append(
                    f"  {entity_type:6s} [{bar}] {info['warm']}/{info['total']} ({info['pct']}%)"
                )
            lines.append(f"  Warm-up threshold: {warm_up['min_observations']} observations")
            lines.append("")
            lines.append("Transition requires:")
            lines.append("  • 21 days since first SIEM ingestion")
            lines.append("  • ≥3 users with warm-up complete")
    else:
        lines.append("All detection methods active")
        if warm_up:
            lines.append(
                f"Entity profiles: {warm_up['users']['total']} users, "
                f"{warm_up['hosts']['total']} hosts, "
                f"{warm_up['ips']['total']} IPs"
            )
        transitioned = state.get("transitioned_at")
        if transitioned:
            lines.append(f"Transitioned from baseline: {transitioned}")

    return "\n".join(lines)


def format_system_phase_block(
    state: dict[str, Any],
    warm_up: dict[str, Any] | None = None,
) -> str:
    """Format the system_phase shared block content.

    This is written to the supervisor's system_phase block so the LLM
    can reason about which detection methods are active.

    Args:
        state: Current system state dict.
        warm_up: Warm-up summary dict (from warm_up_summary).

    Returns:
        String content for the system_phase block.
    """
    phase = state.get("phase", "detection")
    lines = [f"Phase: {phase.upper()}"]

    if phase == "baseline":
        lines.append("")
        lines.append("ACTIVE detection methods (signature-based):")
        for method in sorted(ALWAYS_ACTIVE_METHODS):
            lines.append(f"  - {method}")
        lines.append("")
        lines.append("SUPPRESSED detection methods (waiting for baselines):")
        for method in sorted(BASELINE_DEPENDENT_METHODS):
            lines.append(f"  - {method}")
        lines.append("")
        lines.append("IMPLICATIONS FOR REVIEW:")
        lines.append(
            "- Only signature-based findings (LOLBIN, attack scripts, renamed tools, "
            "critical host escalation, etc.) can appear in this phase."
        )
        lines.append(
            "- Statistical anomalies (z-score, off-hours, activity spike, multi-IP, "
            "EWMA, CUSUM, entity composites) are NOT generated during baseline."
        )
        lines.append(
            "- Findings during baseline are high-confidence — they are based on "
            "known attack patterns, not statistical deviation."
        )
        lines.append(
            "- Do NOT flag the absence of statistical findings as suspicious. "
            "They are intentionally suppressed."
        )
        if warm_up:
            lines.append("")
            lines.append("WARM-UP PROGRESS:")
            for entity_type in ("users", "hosts", "ips"):
                info = warm_up[entity_type]
                lines.append(f"  {entity_type}: {info['warm']}/{info['total']} warm ({info['pct']}%)")
            lines.append(f"  threshold: {warm_up['min_observations']} observations")
    else:
        lines.append("All detection methods active (signature + statistical + entity)")
        if warm_up:
            lines.append(
                f"Entity profiles: {warm_up['users']['total']} users, "
                f"{warm_up['hosts']['total']} hosts, "
                f"{warm_up['ips']['total']} IPs"
            )

    return "\n".join(lines)
