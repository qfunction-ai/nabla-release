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
        and NO false alarms on the cross-cadence detections.

        N-2 (round 7): the 5-minute cadence is a LIVE stream (splunk/
        synthetic schedule) — hours compose in the open map and the
        watermark closes them. Hourly/daily are FILE backfill — the
        chunker cuts at hour boundaries, so batch-end close is exact.
        Feeding sub-hour batches through file mode is no longer a real
        production path (it was the 12x-undercount shape R-1 killed)."""
        from nabla.baselines import EntityProfileStore

        def build(cadence_minutes: int, source: str) -> EntityProfileStore:
            import os
            p = str(tmp_path / f"prof-{cadence_minutes}.json")
            os.path.exists(p) and os.remove(p)
            store = EntityProfileStore(p)
            day = _steady_events(T0, hours=24)
            step = cadence_minutes
            i = 0
            wm = ""
            while i < len(day):
                batch = day[i:i + max(1, step // 9)]  # ~cadence-sized slices
                if source == "file":
                    store.update_user("n4", batch, source_kind="file")
                else:
                    from nabla.pipeline.watermark import newest_event_ts
                    wm = newest_event_ts(batch)
                    store.update_user("n4", batch, source_kind=source,
                                       watermark=wm)
                i += max(1, step // 9)
            return store

        five_min = build(5, "splunk")
        hourly = build(60, "file")
        daily = EntityProfileStore.__new__(EntityProfileStore)
        import os
        p = str(tmp_path / "prof-1440.json")
        os.path.exists(p) and os.remove(p)
        daily = EntityProfileStore(p)
        daily.update_user("n4", _steady_events(T0, hours=24),
                          source_kind="file")

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
        from nabla.pipeline.watermark import newest_event_ts
        while i < len(day):  # 5-minute slices
            batch = day[i:i + 2]
            store.update_user("n4", batch, source_kind="splunk",
                              watermark=newest_event_ts(batch))
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
        """The open-hours map persists — the engine state survives the
        save/reload cycle (round-4's reload lesson applied at birth)."""
        import os
        from nabla.baselines import EntityProfileStore
        p = str(tmp_path / "prof.json")
        store = EntityProfileStore(p)
        # a partial hour (2 of the eventual 6 events)
        store.update_user("n4", _steady_events(T0, hours=1)[:2],
                          source_kind="splunk", watermark=f"{T0.isoformat()}")
        store.save()
        store2 = EntityProfileStore(p)
        u = store2.get_user("n4")
        assert u.open_hours, "open-hours map not persisted"
        entry = next(iter(u.open_hours.values()))
        assert entry["count"] == 2, (
            f"open count round-trip broken: {entry}"
        )

    def test_partial_hours_accumulate_then_close(self, tmp_path):
        """Two half-hour batches in the same wall hour make ONE observation
        of 6, not two observations of 3. (Live mode: the hour stays open
        until the watermark passes it — R-1's stateful composition.)"""
        import os
        from nabla.baselines import EntityProfileStore
        p = str(tmp_path / "prof.json")
        os.path.exists(p) and os.remove(p)
        store = EntityProfileStore(p)
        hour_events = _steady_events(T0, hours=1)  # 6 events, minutes 0..45
        from nabla.pipeline.watermark import newest_event_ts
        store.update_user("n4", hour_events[:3], source_kind="splunk",
                          watermark=newest_event_ts(hour_events[:3]))   # first half
        store.update_user("n4", hour_events[3:], source_kind="splunk",
                          watermark=newest_event_ts(hour_events[3:]))   # second half
        # hour not yet closed (watermark inside it) -> still open, no obs yet
        u = store.get_user("n4")
        assert u.typical_event_count.n == 0, "partial hour closed early"
        assert next(iter(u.open_hours.values()))["count"] == 6, (
            f"open map lost events: {u.open_hours}")
        # a later hour arrives -> the first hour closes as ONE observation of 6
        later = _steady_events(T0 + timedelta(hours=4), hours=1)
        store.update_user("n4", later, source_kind="splunk",
                          watermark=newest_event_ts(later))
        u = store.get_user("n4")
        assert u.typical_event_count.n >= 1
        first = u.typical_event_count
        assert first.value == pytest.approx(6.0, abs=0.5), (
            f"closed-hour observation {first.value} != 6 — split hours must "
            f"compose to one complete-hour observation (N4)"
        )

    def test_late_out_of_order_hours_merge_not_reopen(self, tmp_path):
        """Out-of-order data merges into its hour without moving the
        open map backwards (U-1: a never-observed hour behind the
        watermark RE-OPENS and merges pieces — not one-piece-only)."""
        from nabla.baselines import EntityProfileStore
        store = EntityProfileStore(str(tmp_path / "prof.json"))
        h2 = _steady_events(T0 + timedelta(hours=2), hours=1)
        wm = "2026-11-01T03:30:00Z"  # source watermark past hour 0's close line
        store.update_user("n4", h2, source_kind="splunk",
                          watermark=wm)              # hour 2 advances the source
        # hour 0 arrives LATE, behind the advanced watermark (monotone —
        # the source's watermark does not go back for old data)
        h0 = _steady_events(T0, hours=1)
        store.update_user("n4", h0[:3], source_kind="splunk",
                          watermark=wm)          # hour 0: late, piece 1
        store.update_user("n4", h0[3:], source_kind="splunk",
                          watermark=wm)          # hour 0: piece 2
        u = store.get_user("n4")
        late_key = f"splunk|2026-11-01T00"
        assert late_key in u.open_hours, (
            f"late hour did not re-open: {list(u.open_hours)}")
        assert u.open_hours[late_key]["count"] == 6, (
            f"late pieces did not merge: {u.open_hours[late_key]}")
        assert u.open_hours[late_key].get("reopen_wm"), (
            "re-opened hour must carry its reopen watermark (U-1)")
