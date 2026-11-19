"""N4 (round 4): rate observations must be batch-size independent.

The reviewer's verified table: a steady 6/hr user's `observation_rate`
reads ~1.2 on 5-minute batches, ~6 on 1-day batches, ~17.7 on 3-day
batches — the value tracks batch size, not behavior, because
hour-of-DAY buckets (0-23) merge days and partial hours read at the
single-event floor. Our Phase-2 probe confirmed z=11 for the
5min-baseline/1day-detect cross (blunted only by the R4 Poisson floor).

The fix: bucket by ABSOLUTE hour ("YYYY-MM-DDTH"). Each EWMA
observation is one complete hour — a batch closes every hour it
completes and accumulates the partial current hour on the profile
(open_hour/open_count, persisted). Detection compares the current
hour's count (open_count + this batch's same-hour events) against the
EWMA. Late (out-of-order) hours merge without reopening.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest


def _ev(ts: datetime, user: str = "n4") -> dict:
    return {"timestamp": ts.isoformat().replace("+00:00", "Z"),
            "log_type": "auth", "user": user, "action": "login_success"}


def _steady_events(t0: datetime, hours: int, per_hour: int = 6) -> list[dict]:
    out = []
    for h in range(hours):
        for k in range(per_hour):
            out.append(_ev(t0 + timedelta(hours=h, minutes=k * 9)))
    return out


T0 = datetime(2026, 11, 1, tzinfo=timezone.utc)


class TestAbsoluteHourBuckets:
    def test_buckets_are_absolute_not_hour_of_day(self):
        from nabla.baselines import absolute_hour_counts
        evs = _steady_events(T0, hours=26)  # spans a day boundary
        buckets = absolute_hour_counts(evs)
        assert len(buckets) == 26, (
            f"expected 26 distinct absolute hours, got {len(buckets)} — "
            f"hour-of-DAY bucketing (N4) merges days"
        )
        assert all(v == 6 for v in buckets.values())


class TestObservationsAreBatchSizeIndependent:
    def test_same_user_similar_observations_across_cadences(self, tmp_path):
        """THE N4 witness (reviewer's test): one steady 6/hr user observed
        as 5-minute, hourly, and daily batches yields SIMILAR EWMA values
        and NO false alarms on the cross-cadence detections."""
        from nabla.baselines import EntityProfileStore

        def build(cadence_minutes: int) -> EntityProfileStore:
            import os
            p = str(tmp_path / f"prof-{cadence_minutes}.json")
            os.path.exists(p) and os.remove(p)
            store = EntityProfileStore(p)
            day = _steady_events(T0, hours=24)
            step = cadence_minutes
            i = 0
            while i < len(day):
                batch = day[i:i + max(1, step // 9)]  # ~cadence-sized slices
                store.update_user("n4", batch)
                i += max(1, step // 9)
            return store

        five_min = build(5)
        hourly = build(60)
        daily = EntityProfileStore.__new__(EntityProfileStore)
        import os
        p = str(tmp_path / "prof-1440.json")
        os.path.exists(p) and os.remove(p)
        daily = EntityProfileStore(p)
        daily.update_user("n4", _steady_events(T0, hours=24))

        vals = {
            "5min": five_min.get_user("n4").typical_event_count.value,
            "hourly": hourly.get_user("n4").typical_event_count.value,
            "daily": daily.get_user("n4").typical_event_count.value,
        }
        spread = max(vals.values()) - min(vals.values())
        # one complete hour = observation of 6 under every cadence
        assert spread <= 1.0, (
            f"observation spread across cadences: {vals} (spread {spread:.2f}) — "
            f"the EWMA tracks batch size, not behavior (N4)"
        )

    def test_detection_on_daily_batch_after_5min_baseline(self, tmp_path):
        """The FP direction end-to-end: baseline from small batches, then
        one normal DAY batch of the same steady user — no entity_z fire."""
        import os
        from nabla.baselines import EntityProfileStore
        from nabla.detection import detect_anomalies

        p = str(tmp_path / "prof.json")
        os.path.exists(p) and os.remove(p)
        store = EntityProfileStore(p)
        day = _steady_events(T0, hours=24)
        i = 0
        while i < len(day):  # 5-minute slices
            store.update_user("n4", day[i:i + 2])
            i += 2

        next_day = _steady_events(T0 + timedelta(days=1), hours=24)
        anoms, _ = detect_anomalies(next_day, entity_profiles=store, phase="detection")
        z = [a for a in anoms
             if a.get("user", a.get("entity")) == "n4"
             and a.get("detection_method") in ("entity_z_score", "z_score")]
        assert not z, (
            f"steady user fired z on a normal day-batch: "
            f"{[(a.get('detection_method'), a.get('raw_score')) for a in z]} (N4)"
        )


class TestOpenHourAccumulator:
    def test_open_hour_and_count_roundtrip(self, tmp_path):
        """open_hour/open_count persist — the accumulator survives the
        save/reload cycle (round-4's reload lesson applied at birth)."""
        import os
        from nabla.baselines import EntityProfileStore
        p = str(tmp_path / "prof.json")
        store = EntityProfileStore(p)
        # a partial hour (2 of the eventual 6 events)
        store.update_user("n4", _steady_events(T0, hours=1)[:2])
        store.save()
        store2 = EntityProfileStore(p)
        u = store2.get_user("n4")
        assert getattr(u, "open_hour", None) is not None, "open_hour not persisted"
        assert getattr(u, "open_count", 0) == 2, (
            f"open_count round-trip broken: {getattr(u, 'open_count', None)}"
        )

    def test_partial_hours_accumulate_then_close(self, tmp_path):
        """Two half-hour batches in the same wall hour make ONE observation
        of 6, not two observations of 3."""
        import os
        from nabla.baselines import EntityProfileStore
        p = str(tmp_path / "prof.json")
        os.path.exists(p) and os.remove(p)
        store = EntityProfileStore(p)
        hour_events = _steady_events(T0, hours=1)  # 6 events, minutes 0..45
        store.update_user("n4", hour_events[:3])   # first half
        store.update_user("n4", hour_events[3:])   # second half, SAME hour
        # hour not yet closed (no later hour seen) -> still open, no obs yet
        u = store.get_user("n4")
        assert u.typical_event_count.n == 0, "partial hour closed early"
        assert u.open_count == 6, f"accumulator lost events: {u.open_count}"
        # a later hour arrives -> the first hour closes as ONE observation of 6
        store.update_user("n4", _steady_events(T0 + timedelta(hours=1), hours=1))
        u = store.get_user("n4")
        assert u.typical_event_count.n >= 1
        first = u.typical_event_count
        assert first.value == pytest.approx(6.0, abs=0.5), (
            f"closed-hour observation {first.value} != 6 — split hours must "
            f"compose to one complete-hour observation (N4)"
        )

    def test_late_out_of_order_hours_merge_not_reopen(self, tmp_path):
        """Out-of-order data merges into its hour without moving the
        accumulator backwards."""
        from nabla.baselines import EntityProfileStore
        store = EntityProfileStore(str(tmp_path / "prof.json"))
        store.update_user("n4", _steady_events(T0 + timedelta(hours=2), hours=1))  # hour 2
        store.update_user("n4", _steady_events(T0, hours=1))                      # hour 0: late
        u = store.get_user("n4")
        assert u.open_hour == "2026-11-01T02", (
            f"late hour reopened the accumulator: open_hour={u.open_hour}"
        )
