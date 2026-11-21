"""S4/S7 (round 5): multi-hour scoring, family threshold, closed-hours
merge-once, per-hour alert dedup, and serialization round-trips for the
new persisted fields.
"""

import pytest


D = "2026-08-12T"


def _day_events(burst_hour=3, burst_n=120, normal_n=6):
    return [{"user": "dave", "action": "activity", "type": "authentication",
             "timestamp": f"{D}{h:02d}:{i % 60:02d}:00Z"}
            for h in range(24) for i in range(burst_n if h == burst_hour else normal_n)]


class TestFamilyThreshold:
    def test_single_hour_untouched(self):
        from nabla.baselines import family_z_threshold
        assert family_z_threshold(2.0, 1) == 2.0
        assert family_z_threshold(2.25, 1) == 2.25

    def test_24h_value_from_formula(self):
        # Expectations derive from the formula (self-review R4): the v1
        # plan prose said 2.98 — wrong; the formula gives 3.106.
        from nabla.baselines import family_z_threshold
        from statistics import NormalDist
        expected = NormalDist().inv_cdf(1 - (1 - NormalDist().cdf(2.0)) / 24)
        got = family_z_threshold(2.0, 24)
        assert got == pytest.approx(expected, rel=1e-9)
        assert round(got, 3) == 3.106

    def test_monotone_in_hours(self):
        from nabla.baselines import family_z_threshold
        vals = [family_z_threshold(2.0, h) for h in (1, 2, 6, 12, 24, 48)]
        assert vals == sorted(vals)


class TestHourlyRates:
    def test_all_hours_present_with_open_composition(self):
        from nabla.baselines import hourly_rates
        evts = _day_events(burst_n=120)
        # N-2 (round 7): the open state is the per-(source, hour) map
        p = type("P", (), {"open_hours": {
            f"splunk|{D}23": {"count": 4, "ids": [], "reopen_wm": ""}}})()
        rates = hourly_rates(evts, p)
        assert len(rates) == 24
        assert rates[f"{D}03"] == 120.0
        assert rates[f"{D}23"] == 10.0  # 6 batch + 4 accumulated
        assert rates[f"{D}00"] == 6.0

    def test_empty_when_no_stamps(self):
        from nabla.baselines import hourly_rates
        p = type("P", (), {"open_hour": "", "open_count": 0})()
        assert hourly_rates([{"user": "u"}], p) == {}


class TestBurstDetection:
    def test_burst_hour_flagged_with_in_hour_timestamp(self):
        import os, tempfile
        os.environ.setdefault("NABLA_DATA_DIR", tempfile.mkdtemp())
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.baselines import EntityProfileStore
        from nabla.detection import detect_anomalies
        from pathlib import Path
        store = EntityProfileStore(str(Path(tempfile.mkdtemp()) / "p.json"))
        for day in (8, 9, 10, 11):
            store.update_user("dave", [
                {"user": "dave", "action": "activity", "type": "authentication",
                 "timestamp": f"2026-08-{day}T{h:02d}:{i:02d}:00Z"}
                for h in range(24) for i in range(6)])
        anoms, _ = detect_anomalies(_day_events(), phase="detection",
                                    entity_profiles=store)
        z = [a for a in anoms if a.get("detection_method") == "entity_z_score"]
        assert z, f"no entity_z from a 120-burst vs 6/h baseline: {[a.get('detection_method') for a in anoms]}"
        assert z[0]["timestamp"].startswith(f"{D}03"), (
            f"burst anomaly stamped {z[0]['timestamp']} — must fall inside the burst hour")

    def test_gate7_single_hour_math_unchanged(self):
        """The load-bearing constraint: a SINGLE-hour batch scores against
        the BASE threshold (2.0), not the family threshold. The gate-7
        demo (z=2.021 vs 2.0) survives."""
        from nabla.baselines import hourly_rates, family_z_threshold
        evts = [{"user": "g", "action": "x", "type": "authentication",
                 "timestamp": f"{D}03:{i:02d}:00Z"} for i in range(20)]
        p = type("P", (), {"open_hours": {}})()
        rates = hourly_rates(evts, p)
        assert len(rates) == 1
        assert family_z_threshold(2.0, len(rates)) == 2.0


class TestClosedHoursMergeOnce:
    def test_late_duplicate_hour_observes_once(self):
        # N-2 (round 7): re-pointed to the stateful Rule 6 engine —
        # merge-once now lives in the observed-hours registry.
        from nabla.baselines import EWMAProfile
        from nabla.pipeline.watermark import absorb_state, new_state
        p = type("P", (), {})()
        p.typical_event_count = EWMAProfile()
        state = new_state()
        p.open_hours, p.observed_hours = state["open"], state["observed"]
        e1 = [{"timestamp": f"{D}0{i}:00:00Z"} for i in range(3)]
        state, obs, _ex = absorb_state(
            state, f"{D}09:00:00Z", e1, source_kind="file", mode="backfill")
        for _k, c in obs:
            p.typical_event_count.update(float(c))
        n_before = p.typical_event_count.n
        # the SAME hours arrive again (overlapping pull)
        state, obs, _ex = absorb_state(
            state, f"{D}09:00:00Z", e1, source_kind="file", mode="backfill")
        for _k, c in obs:
            p.typical_event_count.update(float(c))
        assert p.typical_event_count.n == n_before, (
            "duplicate hours re-observed — overlapping pulls must merge to one observation")

    def test_late_new_hour_still_observes(self):
        from nabla.baselines import EWMAProfile
        from nabla.pipeline.watermark import absorb_state, new_state
        p = type("P", (), {})()
        p.typical_event_count = EWMAProfile()
        state = new_state()
        p.open_hours, p.observed_hours = state["open"], state["observed"]
        state, obs, _ex = absorb_state(
            state, f"{D}09:00:00Z", [{"timestamp": f"{D}05:00:00Z"}],
            source_kind="file", mode="backfill")
        for _k, c in obs:
            p.typical_event_count.update(float(c))
        n_before = p.typical_event_count.n
        # a DIFFERENT older hour, genuinely new
        state, obs, _ex = absorb_state(
            state, f"{D}09:00:00Z", [{"timestamp": f"{D}02:00:00Z"}],
            source_kind="file", mode="backfill")
        for _k, c in obs:
            p.typical_event_count.update(float(c))
        assert p.typical_event_count.n == n_before + 1, (
            "genuinely-new late evidence must still land")

    def test_registry_bounded_at_48(self):
        # R-7 (round 7): the registry window replaces the hard 48-entry
        # cap — entries older than the window (measured against the
        # watermark) prune.
        from nabla.baselines import EWMAProfile
        from nabla.pipeline.watermark import absorb_state, new_state
        p = type("P", (), {})()
        p.typical_event_count = EWMAProfile()
        state = new_state()
        p.open_hours, p.observed_hours = state["open"], state["observed"]
        days = [f"2026-08-{d:02d}T{h:02d}:00:00Z" for d in range(1, 5) for h in range(24)]
        state, obs, _ex = absorb_state(
            state, "2026-08-04T23:00:00Z", [{"timestamp": t} for t in days],
            source_kind="file", mode="backfill", window_days=2.0)
        for _k, c in obs:
            p.typical_event_count.update(float(c))
        # the window prunes: every surviving entry's hour ends at or
        # after (watermark - window). 96 hours observed, 2-day window
        # → ~50 survive, 07-31/08-01 history pruned.
        from nabla.pipeline.watermark import split_key, _hour_end
        from datetime import datetime, timedelta
        wm = datetime.fromisoformat("2026-08-04T23:00:00+00:00")
        survivors = [split_key(k)[1] for k in p.observed_hours]
        assert len(survivors) < 96, "the window pruned nothing"
        for h in survivors:
            h_end = _hour_end(h)
            assert h_end is not None, f"unparseable survivor hour {h}"
            assert h_end >= wm - timedelta(days=2.0), (
                f"registry kept over-window hour {h} (ends {h_end}, "
                f"window floor {wm - timedelta(days=2.0)})")


class TestSerializationRoundTrip:
    """Self-review R7: new persisted fields must survive save/reload —
    the RecencySet/N1/group_id disease class."""

    def test_observed_hours_and_alert_hour_round_trip(self):
        import os, tempfile
        os.environ.setdefault("NABLA_DATA_DIR", tempfile.mkdtemp())
        from nabla.baselines import EntityProfileStore
        from pathlib import Path
        path = Path(tempfile.mkdtemp()) / "profiles.json"
        store = EntityProfileStore(str(path))
        store.update_user("u", [{"user": "u", "timestamp": f"{D}05:00:00Z"}])
        # N-2 (round 7): the registry is the per-(source, hour) map with
        # counts and watermark stamps (R-14)
        store.users["u"].observed_hours = {
            f"splunk|{D}04": {"count": 3, "wm": f"{D}07:00:00Z"},
            f"splunk|{D}05": {"count": 6, "wm": f"{D}07:00:00Z"},
        }
        store.users["u"].last_rate_alert_hour = f"{D}05"
        store.save()
        store2 = EntityProfileStore(str(path))
        got = store2.users["u"].observed_hours
        assert got.get(f"splunk|{D}04", {}).get("count") == 3, (
            f"registry round-trip lost counts: {got}")
        assert got.get(f"splunk|{D}05", {}).get("wm") == f"{D}07:00:00Z", (
            f"registry round-trip lost the watermark stamp: {got}")
        assert store2.users["u"].last_rate_alert_hour == f"{D}05"


class TestPerHourAlertDedup:
    def test_two_batches_one_hour_one_alert(self):
        import os, tempfile
        os.environ.setdefault("NABLA_DATA_DIR", tempfile.mkdtemp())
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.baselines import EntityProfileStore
        from nabla.detection import detect_anomalies
        from pathlib import Path
        store = EntityProfileStore(str(Path(tempfile.mkdtemp()) / "p.json"))
        # warm: quiet history
        for day in (8, 9, 10, 11):
            store.update_user("u", [
                {"user": "u", "action": "activity", "type": "authentication",
                 "timestamp": f"2026-08-{day}T{h:02d}:{i:02d}:00Z"}
                for h in range(24) for i in range(4)])
        # two 5-min batches in the SAME busy hour
        b1 = [{"user": "u", "action": "activity", "type": "authentication",
               "timestamp": f"{D}03:{i:02d}:00Z"} for i in range(25)]
        a1, _ = detect_anomalies(b1, phase="detection", entity_profiles=store)
        fired1 = [a for a in a1 if a.get("detection_method") == "entity_z_score"]
        b2 = [{"user": "u", "action": "activity", "type": "authentication",
               "timestamp": f"{D}03:{i:02d}:00Z"} for i in range(50)]
        a2, _ = detect_anomalies(b2, phase="detection", entity_profiles=store)
        fired2 = [a for a in a2 if a.get("detection_method") == "entity_z_score"]
        total = len(fired1) + len(fired2)
        assert total <= 1, (
            f"{total} rate alerts for one entity in one absolute hour "
            f"(batch1={len(fired1)}, batch2={len(fired2)}) — dedup broken")
