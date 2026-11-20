"""CLOCK-SPEC migration (C11 + S-4 + V-3) — run once at upgrade.

Rule 1 changes the timestamp strings event_id/anomaly_id hash from, and
the clock rules invalidate state written under the old regime:

1. Reset the closed-hours registries (C11). A one-time re-observation of
   warm hours is self-correcting under the watermark.
2. Dedupe retained anomalies once by (method, entity, normalized time):
   re-fired anomalies with new hash ids would double-count for about one
   half-life (C11).
3. Repair poisoned clocks (S-4): cap persisted entity data_clocks and the
   global data_newest_ts at wall + 1h — clocks never go backwards, so
   R6-1/R6-14 victims stay wrong forever without this. Log each change.
4. Initialize the new state (V-3): SIEM watermark from the repaired
   data_newest_ts, other per-source watermarks empty, the existing
   open_hour/open_count carried into the per-hour map as its only entry.

Idempotent: a marker in system_state.json prevents a second run.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger("nabla.pipeline.clock_migration")

MARKER = "clock_spec_migrated"
_CEILING_HOURS = 1


def run_clock_migration(data_dir: str) -> dict:
    """Execute the migration; returns a summary dict. Safe to call on
    every boot — the marker short-circuits."""
    d = Path(data_dir)
    state_path = d / "system_state.json"
    state: dict = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text() or "{}")
        except (json.JSONDecodeError, OSError):
            state = {}
    if state.get(MARKER):
        return {"skipped": True}

    summary = {"registries_reset": 0, "anomalies_deduped": 0,
               "clocks_repaired": 0, "watermarks_initialized": 0}
    ceiling = datetime.now(timezone.utc) + timedelta(hours=_CEILING_HOURS)
    ceiling_iso = ceiling.isoformat()

    # 1. Reset closed-hours registries in profiles
    profiles_path = d / "entity_profiles.json"
    if profiles_path.exists():
        try:
            profiles = json.loads(profiles_path.read_text() or "{}")
        except (json.JSONDecodeError, OSError):
            profiles = {}
        for kind in ("users", "hosts", "ips"):
            for eid, prof in (profiles.get(kind) or {}).items():
                if prof.pop("closed_hours", None) is not None:
                    summary["registries_reset"] += 1
                # V-3: carry the single accumulator into the per-hour map
                oh, oc = prof.get("open_hour", ""), prof.get("open_count", 0)
                if oh and not prof.get("open_hours"):
                    prof["open_hours"] = {oh: oc}
                # 2. Dedupe retained anomalies by (method, entity, norm time)
                retained = prof.get("contributing_anomalies") or []
                if isinstance(retained, list) and retained:
                    seen: set[tuple] = set()
                    kept = []
                    for a in retained:
                        if not isinstance(a, dict):
                            continue
                        key = (a.get("method") or a.get("detection_method", ""),
                               eid, str(a.get("timestamp", ""))[:16])
                        if key in seen:
                            summary["anomalies_deduped"] += 1
                            continue
                        seen.add(key)
                        kept.append(a)
                    prof["contributing_anomalies"] = kept
                # 3. Repair poisoned entity clocks (entity_risk file also below)
        _atomic_write(profiles_path, profiles)

    # 3. Repair clocks in the risk store + global data_newest_ts
    risk_path = d / "entity_risk_scores.json"
    if risk_path.exists():
        try:
            risk = json.loads(risk_path.read_text() or "{}")
        except (json.JSONDecodeError, OSError):
            risk = {}
        entities = risk.get("entities", risk)
        if isinstance(entities, dict):
            for eid, ent in entities.items():
                if not isinstance(ent, dict):
                    continue
                dc = str(ent.get("data_clock", "") or "")
                if dc and dc > ceiling_iso:
                    ent["data_clock"] = ceiling_iso
                    summary["clocks_repaired"] += 1
                    logger.warning("clock repair: %s data_clock %s -> %s",
                                   eid, dc, ceiling_iso)
            _atomic_write(risk_path, risk)

    if state.get("data_newest_ts") and str(state["data_newest_ts"]) > ceiling_iso:
        logger.warning("clock repair: data_newest_ts %s -> %s",
                       state["data_newest_ts"], ceiling_iso)
        state["data_newest_ts"] = ceiling_iso
        summary["clocks_repaired"] += 1

    # 4. V-3: initialize per-source watermarks
    if "source_watermarks" not in state:
        state["source_watermarks"] = {
            "siem": state.get("data_newest_ts", ""),
            "synthetic": "",
            "file": "",
        }
        summary["watermarks_initialized"] = 3

    state[MARKER] = datetime.now(timezone.utc).isoformat()
    _atomic_write(state_path, state)
    logger.info("clock migration complete: %s", summary)
    return summary


def _atomic_write(path: Path, data: dict) -> None:
    from nabla.persistence import atomic_write_json
    atomic_write_json(str(path), data)
