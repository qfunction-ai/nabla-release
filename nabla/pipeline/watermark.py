"""CLOCK-SPEC Rule 6 — the watermark late-data engine (stateful, round 7).

States an hour can be in:
  OPEN            — accumulating; ID-deduped (S-3); closes when its
                    source watermark passes it (or batch end for
                    hour-aligned backfill/file hours, V-2, and approved
                    drains, T-1).
  OBSERVED        — registered in the observed-hours registry with the
                    count it closed at and the watermark value that
                    closed it (R-14: idempotent re-close); later events
                    are excluded from BASELINE ABSORPTION ONLY (S-2:
                    detection still sees them).
  NEVER-OBSERVED
  BEHIND-WATERMARK — RE-OPENED (U-1): pieces merge until the source
                    watermark reaches (its value at re-open) + 2h.
  OVER-WINDOW     — older than the registry window measured against
                    the source watermark; excluded.

R-1 (round 7): the engine is STATEFUL. State comes in and goes back out
through persistence (the profile store); the round-6 reference engine's
call-local dicts observed every 5-minute slice as a complete hour when
wired per-batch — the 12x undercount. The step function is
absorb_state(state, watermark, batch) -> (new_state, observations).

R-15: open hours and registry entries are keyed (source_kind, hour) — an
entity fed by two source kinds in the same hour produces two per-source
observations (R-19: documented split-rate behavior; cross-source
sum-at-close is banked). A synthetic watermark therefore cannot close a
SIEM source's open hours.

R-7: the registry stores COUNTS only — event IDs live only while an
hour is open (ID filters on 21d of observed hours would be ~590KB per
entity; counts are ~3KB).

Approved drains (T-1) are schedule FRAGMENTS, not hours — the caller
merges them per entity-hour before observing (mode="drain" observes
each hour in the batch immediately, registry-checked).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger("nabla.pipeline.watermark")

ALLOWED_LATENESS_HOURS = 2.0

# ID-dedup bound per open hour: beyond this, events count without dedup
# (dedup is guaranteed for the first _ID_CAP ids of an open hour; a
# hostile hour cannot grow the open state unboundedly).
_ID_CAP = 1000

# The migrated single-accumulator hour (v1 stores) re-homes under this
# reserved source kind; the sweep closes it against the data clock.
LEGACY_SOURCE = "__legacy__"


def _hour_key(entry: dict[str, Any]) -> str:
    from nabla.pipeline.clock_ingestion import event_hour_key
    return event_hour_key(entry)


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    from nabla.utils import parse_iso_timestamp
    return parse_iso_timestamp(str(ts))


def _hour_end(hour_key: str) -> datetime | None:
    """A hour_key ("YYYY-MM-DDTH") names the hour STARTING at that
    instant; the hour ends one tick later."""
    dt = _parse(hour_key + ":00:00Z") if len(hour_key) == 13 else _parse(hour_key)
    return dt + timedelta(hours=1) if dt is not None else None


def make_key(source_kind: str, hour_key: str) -> str:
    return f"{source_kind}|{hour_key}"


def split_key(key: str) -> tuple[str, str]:
    src, _, hour = key.partition("|")
    return src, hour


def new_state() -> dict:
    return {"open": {}, "observed": {}}


def _closable(entry: dict, hour_key: str, wm: datetime | None) -> bool:
    """The close predicate (R-16): a normally-open hour closes when the
    watermark passes its end + allowed lateness; a re-opened hour closes
    when the watermark passes (its re-open value) + allowed lateness —
    late pieces get their merge window (U-1)."""
    if wm is None:
        return False
    reopen = _parse(entry.get("reopen_wm", ""))
    if reopen is not None:
        return wm >= reopen + timedelta(hours=ALLOWED_LATENESS_HOURS)
    h_end = _hour_end(hour_key)
    if h_end is None:
        return False
    return wm >= h_end + timedelta(hours=ALLOWED_LATENESS_HOURS)


def _over_window(hour_key: str, wm: datetime | None, window_days: float) -> bool:
    if wm is None or window_days <= 0:
        return False
    h_end = _hour_end(hour_key)
    if h_end is None:
        return False
    return h_end < wm - timedelta(days=window_days)


def _prune_registry(observed: dict, wm: datetime | None, window_days: float) -> None:
    """R-7/R-9: bound the registry to the window (max(TP-hold days,
    baseline_min_days), computed by the caller at wiring time)."""
    if wm is None:
        return
    stale = [k for k in observed
             if _over_window(split_key(k)[1], wm, window_days)]
    for k in stale:
        observed.pop(k, None)


def _max_ts(watermarks: dict[str, str]) -> str:
    best = ""
    for ts in watermarks.values():
        if ts and ts > best:
            best = ts
    return best


def close_open(state: dict, watermarks: dict[str, str],
               window_days: float) -> list[tuple[str, int]]:
    """Close every open hour whose source's watermark satisfies its
    close predicate. Returns the observations [(key, count)] — one
    complete-hour EWMA observation each. Idempotent (R-14): closed
    hours leave the open map and enter the registry stamped with the
    watermark value that closed them, so a crash-replay re-close is a
    no-op. Used by live absorption (this source) and the end-of-run
    sweep (all sources, quiet entities included — R-16)."""
    observations: list[tuple[str, int]] = []
    for key in sorted(list(state["open"].keys())):
        src, hour = split_key(key)
        wm = _parse(watermarks.get(src))
        entry = state["open"][key]
        if not _closable(entry, hour, wm):
            continue
        count = int(entry.get("count", 0))
        state["observed"][key] = {
            "count": count,
            "wm": watermarks.get(src) or "",
        }
        del state["open"][key]
        observations.append((key, count))
    _prune_registry(state["observed"], _parse(_max_ts(watermarks)), window_days)
    return observations


def absorb_state(state: dict, watermark: str | None, batch: list[dict],
                 *, source_kind: str, mode: str = "live",
                 window_days: float = 21.0,
                 ) -> tuple[dict, list[tuple[str, int]], int]:
    """The Rule 6 step function (R-1): absorb one batch into the
    profile's engine state and return (new_state, observations,
    excluded_count). observations are complete-hour EWMA updates
    [(source|hour, count)]; excluded counts events dropped from
    BASELINE ABSORPTION ONLY (S-2: detection still sees them).

    Modes:
    - live: 5-minute scheduled arrival. Events open/merge into the
      per-(source, hour) map (ID-deduped); never-observed hours that
      are already behind the watermark RE-OPEN (U-1) and merge pieces
      until the watermark passes re-open + 2h; closable hours close.
    - backfill (V-2): hour-aligned windows upstream (file/synthetic
      chunks) — each hour in the batch closes at BATCH END with its
      merged count, registry-checked.
    - drain (T-1): approved/TTL-released holds — the caller already
      merged fragments per hour; each hour observes immediately,
      registry-checked (merge-once: "already observed" is the only
      drop condition).
    """
    open_map: dict = state.setdefault("open", {})
    observed: dict = state.setdefault("observed", {})
    excluded = 0
    wm = _parse(watermark)

    if mode in ("backfill", "drain"):
        # V-2 / T-1: merge the batch per hour, then observe each hour
        # immediately (registry-checked — merge-once).
        counts: dict[str, int] = {}
        ids: dict[str, set] = {}
        for e in batch:
            h = _hour_key(e)
            if not h:
                continue
            eid = str(e.get("event_id", "") or "")
            h_ids = ids.setdefault(h, set())
            if eid and eid in h_ids:
                continue  # S-3: duplicate within the batch
            h_ids.add(eid)
            counts[h] = counts.get(h, 0) + 1
        observations: list[tuple[str, int]] = []
        for h in sorted(counts):
            key = make_key(source_kind, h)
            if key in observed:
                excluded += counts[h]
                continue  # merge-once: the observation exists
            observed[key] = {"count": counts[h], "wm": watermark or ""}
            open_map.pop(key, None)  # superseded by the complete hour
            observations.append((key, counts[h]))
        _prune_registry(observed, wm, window_days)
        return state, observations, excluded

    # live: add events to the open map (S-3 dedup while open; U-1
    # re-open for never-observed hours behind the watermark)
    for e in batch:
        h = _hour_key(e)
        if not h:
            continue
        key = make_key(source_kind, h)
        if key in observed:
            excluded += 1  # S-2: observed — absorption only
            continue
        if _over_window(h, wm, window_days):
            excluded += 1
            continue
        entry = open_map.get(key)
        if entry is None:
            reopen = ""
            h_end = _hour_end(h)
            if wm is not None and h_end is not None and (
                    wm >= h_end + timedelta(hours=ALLOWED_LATENESS_HOURS)):
                # U-1: never observed, already behind — re-open and
                # give late pieces their 2h merge window
                reopen = watermark or ""
            entry = open_map[key] = {"count": 0, "ids": [], "reopen_wm": reopen}
        eid = str(e.get("event_id", "") or "")
        if eid and len(entry["ids"]) < _ID_CAP:
            if eid in entry["ids"]:
                continue  # S-3: duplicate pull
            entry["ids"].append(eid)
        entry["count"] += 1

    # close this source's hours that the watermark has passed
    observations = close_open(state, {source_kind: watermark or ""}, window_days)
    return state, observations, excluded


def newest_event_ts(entries: list[dict]) -> str:
    """The batch's newest event timestamp as ISO ("" if none parse) —
    the value the pipeline advances the source watermark to."""
    best: datetime | None = None
    for e in entries:
        dt = _parse(str(e.get("timestamp", "") or ""))
        if dt is not None and (best is None or dt > best):
            best = dt
    return best.isoformat() if best is not None else ""
