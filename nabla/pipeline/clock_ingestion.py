"""CLOCK-SPEC Rules 0, 1, 2, 5 — the single ingestion-time entry point.

Rule 1: event time is parsed once, here. Naive stamps read in the
source timezone; offsets normalize to UTC; nothing downstream re-parses.
Rule 2: far-future stamps become ABSENT (original preserved); absent
means absent; only this module ever compares event time to wall clock.
Rule 0: event identity distinguishes occurrences (native source ID or
field-hash + occurrence counter).
Rule 5: hour keys derive from the parsed UTC time via event_hour_key.

This module IS the specification's ingest surface. Connectors and
parsers route through normalize_and_validate; per-connector stamp
handling and raw [:13] slicing are forbidden downstream (see
tests/test_clock_conformance.py).
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger("nabla.pipeline.clock_ingestion")

# Rule 2: the only skew tolerance in the system.
FUTURE_BOUNDARY = timedelta(hours=1)


def future_ceiling() -> datetime:
    """Rule 2's shared wall+1h validation ceiling. One definition —
    risk's _future_ceiling and the span tracker's guard both delegate
    here (N-9: three inline copies had already drifted apart once)."""
    return datetime.now(timezone.utc) + FUTURE_BOUNDARY

# Rule 0: the field-hash key material (stable order).
_ID_FIELDS = (
    "timestamp", "user", "host", "source_ip", "process", "action",
    "event_code", "dest_ip",
)

# Rule 0: source-native ID fields, in preference order.
_NATIVE_ID_FIELDS = (
    "event_record_id",   # Sysmon EventRecordID
    "record_id",
    "message_id",        # SumoLogic
    "_cd",               # Splunk (paired with index by the connector)
)

_DEGRADATIONS = "clock_degradations"


def _source_tz(entry: dict[str, Any]) -> timezone:
    """Rule 1: naive stamps read in the source's timezone. Per-entry
    override first (connectors know their source), then the site
    setting, then UTC."""
    raw = entry.get("_source_timezone")
    if raw:
        try:
            return _parse_tz(str(raw))
        except ValueError:
            logger.warning("bad _source_timezone %r — falling back to site", raw)
    from nabla.config import get_settings
    return _parse_tz(getattr(get_settings(), "timezone", "UTC") or "UTC")


def _parse_tz(name: str) -> timezone:
    name = name.strip()
    if name.upper() in ("UTC", "", "Z"):
        return timezone.utc
    # "UTC+5" / "UTC-3" (the settings' historical format)
    s = name.upper().replace(" ", "")
    if s.startswith("UTC+") or s.startswith("GMT+"):
        return timezone(timedelta(hours=float(s[4:])))
    if s.startswith("UTC-") or s.startswith("GMT-"):
        return timezone(-timedelta(hours=float(s[4:])))
    from zoneinfo import ZoneInfo
    return ZoneInfo(name)  # raises ValueError for garbage


def _parse_naive(stamp: str, tz: timezone) -> datetime:
    return datetime.fromisoformat(stamp).replace(tzinfo=tz)


def normalize_and_validate(
    entries: list[dict[str, Any]],
    *,
    source: str = "",
) -> list[dict[str, Any]]:
    """The single Rule-1/2 entry point. Mutates and returns entries.

    - parses every stamp to aware UTC ISO-8601 (naive → source tz first);
    - strips far-future stamps to absent, original preserved;
    - counts degradations in each entry (key ``clock_degradations``) and
      rolls ONE bulk warning per batch when a source is stripped in bulk
      (likely timezone misconfiguration, not skew);
    - stamps occurrence-safe event_ids (Rule 0) when missing;
    - preserves native source ids when present.
    """
    wall = datetime.now(timezone.utc)
    stripped = absent = 0
    seen_keys: dict[str, int] = {}

    for e in entries:
        degs: list[str] = e.get(_DEGRADATIONS, [])

        # ── Rule 1: parse once, to UTC ─────────────────────────────
        ts = str(e.get("timestamp", "") or "").strip()
        parsed: datetime | None = None
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = _parse_naive(ts, _source_tz(e))  # C5
                parsed = dt.astimezone(timezone.utc)
            except ValueError:
                parsed = None

        # ── Rule 2: far-future → absent; absent stays absent ───────
        if parsed is not None and parsed > wall + FUTURE_BOUNDARY:
            e["_original_timestamp"] = ts
            e["timestamp"] = ""
            degs.append("future_timestamp_stripped")
            stripped += 1
            parsed = None
        elif parsed is not None:
            e["timestamp"] = parsed.isoformat()
        elif ts:
            e["timestamp"] = ""  # unparseable: absent, never "now" (R6-14)
            degs.append("absent_timestamp")
            absent += 1
        else:
            degs.append("absent_timestamp")
            absent += 1

        # ── Rule 0: occurrence-safe identity ───────────────────────
        if not e.get("event_id"):
            native = next((e[f] for f in _NATIVE_ID_FIELDS if e.get(f)), None)
            if native:
                e["event_id"] = f"{source}:{native}" if source else str(native)
            else:
                key = "|".join(str(e.get(k, "") or "") for k in _ID_FIELDS)
                n = seen_keys.get(key, 0)
                seen_keys[key] = n + 1
                e["event_id"] = hashlib.sha256(
                    f"{key}#{n}".encode()).hexdigest()[:16]
        if degs:
            e[_DEGRADATIONS] = degs

    if stripped and len(entries) and stripped >= max(1, len(entries) // 2):
        logger.warning(
            "CLOCK Rule 2: %d/%d entries stripped as far-future from this "
            "batch — a timezone misconfiguration is more likely than skew "
            "(check the source timezone setting)", stripped, len(entries))
    elif stripped:
        logger.info("CLOCK Rule 2: %d far-future stamp(s) stripped", stripped)
    if absent:
        logger.info("CLOCK Rule 2: %d absent/unparseable stamp(s)", absent)
    return entries


def event_hour_key(entry: dict[str, Any]) -> str:
    """Rule 5: the one absolute-hour key derivation ('%Y-%m-%dT%H' on the
    parsed UTC time). Both bucketing and evidence slicing use this — the
    R6-6 disease was two derivations that never matched."""
    ts = str(entry.get("timestamp", "") or "")
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return ""  # Rule 2 already normalized; a naive stamp here is a bug
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H")
    except ValueError:
        return ""
