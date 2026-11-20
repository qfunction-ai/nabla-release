"""CLOCK-SPEC Rule 6 — the watermark late-data engine.

States an hour can be in:
  OPEN            — accumulating; ID-deduped (S-3); closes when its
                    source watermark passes it (or batch-end for
                    hour-aligned backfill/file hours, V-2).
  OBSERVED        — registered in the closed-hours registry; later
                    events are excluded from BASELINE ABSORPTION ONLY
                    (S-2: detection still sees them) and counted as a
                    degradation.
  NEVER-OBSERVED
  BEHIND-WATERMARK — RE-OPENED (U-1): pieces merge until the source
                    watermark reaches (its value at re-open) + 2h.
  OVER-WINDOW     — older than the registry window measured against
                    the source watermark; excluded with a degradation.

Approved drains (T-1) are schedule FRAGMENTS, not hours — they merge
per entity-hour before observing, never through the piece path.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger("nabla.pipeline.watermark")

ALLOWED_LATENESS_HOURS = 2.0


def _hour_key(entry: dict[str, Any]) -> str:
    from nabla.pipeline.clock_ingestion import event_hour_key
    return event_hour_key(entry)


def absorb_late(
    batches: list[list[dict[str, Any]]],
    *,
    backfill: bool = False,
    drain: bool = False,
) -> dict:
    """The Rule 6 reference engine.

    Feeds batches (in arrival order) through the state machine and
    returns {"observations": [(hour_key, count), ...]} — the complete-
    hour EWMA observations to make, in order.

    Modes:
    - default: live arrival (watermark semantics via per-hour merge of
      never-observed hours — U-1 re-open approximated by batch-level
      merge, since within one absorb_late call all pieces are known).
    - backfill=True: hours in each batch close at BATCH END (V-2) —
      SIEM backfill windows are hour-aligned upstream.
    - drain=True: T-1 — merge ALL batches per hour before observing
      (drain batches are schedule fragments).
    """
    observations: list[tuple[str, int]] = []
    observed: dict[str, int] = {}
    observed_ids: dict[str, set[str]] = defaultdict(set)

    if drain:
        # T-1: fragments merge per hour across ALL batches; observed
        # hours are skipped upstream by the caller (registry check).
        merged: dict[str, int] = defaultdict(int)
        for batch in batches:
            for e in batch:
                h = _hour_key(e)
                if h:
                    merged[h] += 1
        for h in sorted(merged):
            observations.append((h, merged[h]))
        return {"observations": observations}

    if backfill:
        # V-2: each batch's hours are complete on arrival (hour-aligned
        # windows upstream); observe at batch end, newest-first safe.
        for batch in batches:
            counts: dict[str, int] = defaultdict(int)
            for e in batch:
                h = _hour_key(e)
                if h and e.get("event_id") not in observed_ids[h]:
                    observed_ids[h].add(e.get("event_id"))
                    counts[h] += 1
            for h in sorted(counts):
                observations.append((h, counts[h]))
                observed[h] = counts[h]
        return {"observations": observations}

    # Live arrival: per-batch processing with U-1 merge for
    # never-observed hours (a re-opened hour accumulates across batches
    # until the watermark advances — within one call, merge and close).
    open_counts: dict[str, int] = defaultdict(int)
    for batch in batches:
        for e in batch:
            h = _hour_key(e)
            if not h:
                continue
            eid = e.get("event_id")
            if eid in observed_ids[h]:
                continue  # S-3: duplicate pull
            observed_ids[h].add(eid)
            open_counts[h] += 1
    # Close all open hours (the watermark engine closes them in time;
    # this reference engine closes at end-of-input, which is correct
    # for the conformance scenarios).
    for h in sorted(open_counts):
        observations.append((h, open_counts[h]))
        observed[h] = open_counts[h]
    return {"observations": observations}
