"""Label-driven threshold calibration (Phase 3, external review A3).

Replaces the deleted Q-learning (which random-walked on mislabeled
self-graded rewards). Supervised calibration on analyst dispositions:

- Every anomaly carries a stable anomaly_id (Phase 2) and, where the
  detector computes one, a raw_score.
- Incident dispositions write labeled records to the feedback store
  (JSONL, keyed anomaly_id, last-wins).
- calibrate() picks, per tunable threshold with enough labels, the value
  meeting a target precision — step-limited, evidence-logged, never
  random. Below min_labels: PINNED at defaults (the honest state).

This module is also the new home of THRESHOLDS metadata (lo/hi/step/
default), migrated from nabla/rl/thresholds.py before that module's
deletion — detection.py imports it at startup, so the metadata moves
FIRST.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from nabla.log import get_logger

logger = get_logger("rl.calibration")

# ── Threshold definitions: name -> (min, max, step, default) ──────────────
# Migrated from nabla/rl/thresholds.py (Phase 3 migration table row 1).
THRESHOLDS = {  # noqa: E241
    "z_score_sigma":                  (2.0, 4.0, 0.25, 2.0),
    "brute_force_ratio":              (0.3, 0.8, 0.1,  0.5),
    "off_hours_count":                (2,   8,   1,    3),
    "multi_ip_count":                 (2,   6,   1,    3),
    "spike_multiplier":               (2.0, 6.0, 0.5,  3.0),
    "lolbin_sensitivity":             (0.3, 1.0, 0.1,  0.7),
    "parent_child_sensitivity":       (0.3, 1.0, 0.1,  0.7),
    "critical_host_sensitivity":       (0.3, 1.0, 0.1,  0.7),
    "unusual_process_sensitivity":     (0.3, 1.0, 0.1,  0.5),
    "action_sequence_window_minutes": (5,   120, 5,    30),
    "gcn_lof_alpha":                  (0.3, 0.7, 0.1,  0.5),
    "gcn_lof_threshold":              (0.5, 0.95, 0.05, 0.75),
    "provenance_anomaly_density":     (0.1, 0.5, 0.05, 0.3),
    "provenance_min_community_size":  (2,   10,  1,    3),
    "temporal_chain_window_minutes":  (5,   120, 5,    30),
    "temporal_min_chain_length":      (2,   6,   1,    3),
    "suspicious_path_sensitivity":    (0.3, 1.0, 0.1,  0.7),
    "integrity_anomaly_sensitivity":  (0.3, 1.0, 0.1,  0.7),
    "registry_abuse_sensitivity":     (0.3, 1.0, 0.1,  0.7),
    "network_anomaly_sensitivity":    (0.3, 1.0, 0.1,  0.7),
    "ewma_sensitivity":               (0.3, 1.0, 0.1,  0.7),
    "cusum_sensitivity":             (0.3, 1.0, 0.1,  0.7),
    "enumeration_sensitivity":       (0.3, 1.0, 0.1,  0.7),
    "entity_event_count_sigma":     (1.0, 4.0, 0.25, 2.0),
    "entity_new_ip_threshold":      (1,   5,   1,    2),
    "entity_auth_failure_sigma":    (1.0, 4.0, 0.25, 2.0),
    "entity_new_process_threshold":  (1,   10,  1,    3),
    "entity_new_user_threshold":    (1,   5,   1,    1),
    "entity_behavior_composite_threshold": (0.1, 1.0, 0.1, 0.6),
    "risk_score_investigation_cutoff":    (20.0, 80.0, 5.0, 50.0),
}

# Detection method -> tunable threshold (A4: exact emitted strings only;
# static detectors map to None and are never calibrated).
METHOD_TO_THRESHOLD = {
    "z_score_spike": "z_score_sigma",
    "brute_force_attempt": "brute_force_ratio",
    "off_hours_activity": "off_hours_count",
    "multi_ip": "multi_ip_count",
    "activity_spike": "spike_multiplier",
    "lolbin_abuse": "lolbin_sensitivity",
    "unusual_parent_child": "parent_child_sensitivity",
    "critical_host_escalation": "critical_host_sensitivity",
    "unusual_process": "unusual_process_sensitivity",
    "entity_z_score": "entity_event_count_sigma",
    "entity_auth_failure": "entity_auth_failure_sigma",
    "entity_new_ip": "entity_new_ip_threshold",
    "entity_new_process": "entity_new_process_threshold",
}

# Methods that fire on deterministic signatures — no threshold to tune.
STATIC_DETECTORS = {
    "pre_flagged", "known_attack_script", "attack_script", "renamed_attack_tool",
    "failed_login_ratio", "multiple_source_ips", "exfil_destination", "exfil_volume",
    "exfil_staging", "integrity_anomaly", "registry_abuse", "network_anomaly",
    "suspicious_path", "enumeration", "cusum", "ewma", "action_sequence",
    "gcn_lof", "provenance", "temporal_chain", "peer_group_deviation",
    "entity_behavior_composite", "entity_host_composite", "entity_activity_spike",
}

TARGET_PRECISION = 0.5
MIN_LABELS = 30


# ── Feedback store (JSONL, keyed anomaly_id, last-wins) ───────────────────

def feedback_store_path() -> Path:
    from nabla.config import get_settings
    d = Path(get_settings().data_dir) / "feedback"
    d.mkdir(parents=True, exist_ok=True)
    return d / "labels.jsonl"


def write_labels(records: list[dict]) -> None:
    """Write label records; earlier records for the same anomaly_id are
    flagged superseded (STRONG 2: last disposition wins, history retained)."""
    path = feedback_store_path()
    existing = []
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                existing.append(json.loads(line))
    new_ids = {r["anomaly_id"] for r in records}
    out = []
    for r in existing:
        if r["anomaly_id"] in new_ids:
            r["superseded"] = True
        out.append(r)
    out.extend(records)
    with path.open("w") as f:
        for r in out:
            f.write(json.dumps(r) + "\n")


def current_labels() -> list[dict]:
    """The current (non-superseded) label set — calibrate() reads only this."""
    path = feedback_store_path()
    if not path.exists():
        return []
    latest: dict[str, dict] = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        latest[r["anomaly_id"]] = r  # last wins by file order
    return list(latest.values())


# ── Calibration store (the threshold source of truth) ─────────────────────

def calibration_store_path() -> Path:
    from nabla.config import get_settings
    d = Path(get_settings().data_dir) / "feedback"
    d.mkdir(parents=True, exist_ok=True)
    return d / "calibration.json"


def load_calibration() -> dict:
    """{threshold: {current, default, pinned, evidence}} — created from
    THRESHOLDS metadata on first read."""
    path = calibration_store_path()
    if path.exists():
        return json.loads(path.read_text())
    store = {}
    for name, (lo, hi, step, default) in THRESHOLDS.items():
        store[name] = {
            "current": default, "default": default, "pinned": False,
            "lo": lo, "hi": hi, "step": step, "evidence": None,
        }
    save_calibration(store)
    return store


def save_calibration(store: dict) -> None:
    path = calibration_store_path()
    path.write_text(json.dumps(store, indent=2))


def effective_thresholds() -> dict[str, float]:
    """The values detection reads: calibrated currents over THRESHOLDS
    defaults (pinned thresholds return their pinned current)."""
    store = load_calibration()
    return {name: float(v["current"]) for name, v in store.items()}


# ── The calibrate engine (review A3 recommendation, our implementation) ────

def calibrate(
    labels: list[dict],
    current: float,
    target_precision: float = TARGET_PRECISION,
    min_labels: int = MIN_LABELS,
    step: float | None = None,
) -> tuple[float, str]:
    """Pick the threshold meeting target precision from labeled (score, TP?) pairs.

    Returns (proposed, reason). Below min_labels the current value is
    returned with a pinned reason — the honest no-op.
    """
    alerts = [
        (r.get("raw_score"), r.get("disposition") in ("true_positive", "benign_true_positive"))
        for r in labels
        if r.get("raw_score") is not None
    ]
    if len(alerts) < min_labels:
        return current, f"pinned — {len(alerts)}/{min_labels} labels"

    # Walk thresholds LOW to HIGH tracking the precision at each; the chosen
    # value is the HIGHEST threshold that still meets target precision while
    # retaining at least one true positive. This never loosens in response to
    # false positives (the lowest-meeting-t form would: an FP-heavy corpus
    # meets target at a low t by sheer TP filtering and stops there).
    proposal = current
    candidates = sorted({s for s, _ in alerts if s is not None})
    best_meeting = None
    for t in candidates:
        kept = [tp for s, tp in alerts if s >= t]
        if not kept:
            break  # higher t only filters further
        if sum(kept) / len(kept) >= target_precision and any(kept):
            best_meeting = t
    if best_meeting is not None:
        proposal = best_meeting
    if step is not None:
        proposal = min(max(proposal, current - step), current + step)
    reason = f"{len(alerts)} labels, precision target {target_precision}"
    return proposal, reason


def run_calibration() -> dict:
    """Calibrate every tunable threshold from current labels. Returns the report."""
    labels = current_labels()
    store = load_calibration()
    report: dict = {}

    by_threshold: dict[str, list[dict]] = {}
    for r in labels:
        tname = METHOD_TO_THRESHOLD.get(r.get("detection_method", ""))
        if tname:
            by_threshold.setdefault(tname, []).append(r)

    for tname, meta in THRESHOLDS.items():
        entry = store.get(tname, {"current": meta[3], "default": meta[3], "pinned": False})
        if entry.get("pinned"):
            report[tname] = {"status": "pinned_by_operator", "current": entry["current"]}
            continue
        tlabels = by_threshold.get(tname, [])
        if not tlabels:
            report[tname] = {"status": "pinned", "current": entry["current"], "reason": f"pinned — 0/{MIN_LABELS} labels"}
            continue
        proposed, reason = calibrate(
            tlabels, entry["current"],
            step=meta[2],  # one step per cycle max
        )
        if proposed != entry["current"]:
            entry["evidence"] = {
                "changed_at": datetime.now(timezone.utc).isoformat(),
                "from": entry["current"], "to": proposed,
                "reason": reason, "labels": len(tlabels),
            }
            entry["current"] = proposed
            store[tname] = entry
            report[tname] = {"status": "moved", "from": entry["evidence"]["from"], "to": proposed, "reason": reason}
        else:
            report[tname] = {"status": "held", "current": entry["current"], "reason": reason}

    save_calibration(store)
    logger.info("Calibration run: %s", {k: v.get("status") for k, v in report.items()})
    return report
