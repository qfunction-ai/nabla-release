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
MARKER_V2 = "clock_spec_migrated_v2"
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
    # v2 (round 7) is the master short-circuit: the stateful Rule 6
    # engine changed the shapes the v1 migration seeded, so v2 must run
    # on v1 installs too (and after a first-time v1 run, same boot).
    if state.get(MARKER_V2):
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
                # V-3's flat open_hours carry is GONE: the v2 section
                # re-homes the single accumulators directly (below) —
                # seeding the flat shape here would crash the engine.
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
        # round 7: seed the REAL SIEM kinds — "siem" was a v1 bug (no
        # source is named that); v2's re-key only serves old v1 stores.
        state["source_watermarks"] = {
            "splunk": state.get("data_newest_ts", ""),
            "sumologic": state.get("data_newest_ts", ""),
            "synthetic": "",
            "file": "",
        }
        summary["watermarks_initialized"] = 4

    state[MARKER] = datetime.now(timezone.utc).isoformat()
    _atomic_write(state_path, state)
    logger.info("clock migration complete: %s", summary)
    summary.update(_run_v2(data_dir, state, state_path))
    return summary


def _run_v2(data_dir: str, state: dict, state_path: Path) -> dict:
    """Round 7 (N-2): re-home state written by the v1 migration and the
    pre-round-7 accumulator fields into the stateful engine's shapes.

    1. open_hours: v1 seeded a FLAT {hour: count} map; the engine reads
       {source|hour: {count, ids, reopen_wm}}. Flat entries re-home under
       the reserved __legacy__ source (they close against the data
       clock — source_watermarks_view exposes it).
    2. The old single accumulators (open_hour/open_count and the net_*
       twins) carry into the open maps the same way; closed_hours and
       the old scalar fields are popped (dead).
    3. Watermarks: v1 seeded a "siem" key — no source kind is named
       that. The repaired data_newest_ts re-homes to BOTH real SIEM
       kinds (splunk, sumologic): either could have fed the data, and a
       watermark that is too OLD only delays closes (never drops
       them), so seeding both from the data clock is the safe side.
    """
    from nabla.pipeline.watermark import LEGACY_SOURCE
    summary = {"open_hours_rehomed": 0, "accumulators_rehomed": 0,
               "watermarks_rekeyed": 0}

    def _rehome(prof: dict) -> None:
        oh = prof.get("open_hours")
        if isinstance(oh, dict) and any(
                isinstance(v, int) for v in oh.values()):
            prof["open_hours"] = {
                f"{LEGACY_SOURCE}|{h}": {"count": int(c), "ids": [],
                                         "reopen_wm": ""}
                for h, c in oh.items() if isinstance(c, int)
            }
            summary["open_hours_rehomed"] += 1
        noh = prof.get("net_open_hours")
        if isinstance(noh, dict) and any(
                isinstance(v, int) for v in noh.values()):
            prof["net_open_hours"] = {
                f"{LEGACY_SOURCE}|{h}": {"count": int(c), "ids": [],
                                         "reopen_wm": ""}
                for h, c in noh.items() if isinstance(c, int)
            }
            summary["open_hours_rehomed"] += 1
        # pre-round-7 single accumulators (stores that never ran v1)
        for scalar, count, target in (
                ("open_hour", "open_count", "open_hours"),
                ("net_open_hour", "net_open_count", "net_open_hours")):
            h = prof.pop(scalar, "")
            c = prof.pop(count, 0)
            if h and isinstance(c, int):
                tgt = prof.setdefault(target, {})
                if isinstance(tgt, dict) and f"{LEGACY_SOURCE}|{h}" not in tgt:
                    tgt[f"{LEGACY_SOURCE}|{h}"] = {
                        "count": int(c), "ids": [], "reopen_wm": ""}
                    summary["accumulators_rehomed"] += 1
        prof.pop("closed_hours", None)

    profiles_path = Path(data_dir) / "entity_profiles.json"
    if profiles_path.exists():
        try:
            profiles = json.loads(profiles_path.read_text() or "{}")
        except (json.JSONDecodeError, OSError):
            profiles = {}
        for kind in ("users", "hosts", "ips"):
            for prof in (profiles.get(kind) or {}).values():
                if isinstance(prof, dict):
                    _rehome(prof)
        if summary["open_hours_rehomed"] or summary["accumulators_rehomed"]:
            _atomic_write(profiles_path, profiles)

    wms = state.get("source_watermarks")
    if isinstance(wms, dict) and "siem" in wms:
        siem_ts = str(wms.pop("siem") or "")
        for kind in ("splunk", "sumologic"):
            prev = str(wms.get(kind) or "")
            if siem_ts and (not prev or siem_ts > prev):
                wms[kind] = siem_ts
        state["source_watermarks"] = wms
        summary["watermarks_rekeyed"] = 1

    state[MARKER_V2] = datetime.now(timezone.utc).isoformat()
    _atomic_write(state_path, state)
    logger.info("clock migration v2 complete: %s", summary)
    return summary


def _atomic_write(path: Path, data: dict) -> None:
    from nabla.persistence import atomic_write_json
    atomic_write_json(str(path), data)
