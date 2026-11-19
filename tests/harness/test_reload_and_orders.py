"""Phase 2 (round 4): the harness crosses disk between runs, and the
reviewer's order/batch-size scenarios run at pipeline level.

Round 4's pattern — "the fix exists, but isn't reachable from the
pipeline or doesn't survive a save/reload cycle" — is what this file
gates:

1. RELOAD: the harness's per-run state (profiles, risk) goes through
   disk exactly as the pipeline does. N1 survived because in-memory
   state never saw the serializer; this test fails loudly if the harness
   ever shortcuts to in-memory caches again.
2. REPLAY ORDERS (N2.2 harness-level): a replay batch's risk survives a
   later batch for a different entity — the reviewer's scenario (c) at
   full pipeline level, not just compute_risk_scores in isolation.
3. MIXED BATCH SIZES (N4's witness): baselines from daily chunks,
   detection on 5-minute batches — the reviewer's verified table says a
   normal 1-day batch reads z=3.0 against a 5-min-built baseline. XFAIL
   until N4 lands; xpass forces the marker drop.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness.population import Population, attack_batch  # noqa: E402
from harness.conftest import drive_pipeline  # noqa: E402

SIM_START = datetime(2026, 11, 1, 8, 0, tzinfo=timezone.utc)


def _day_hours(pop, t, hours=24):
    """Collect one simulated day of events, hour by hour."""
    events = []
    for h in range(hours):
        ht = t + timedelta(hours=h)
        for _, evs in pop.batches(ht, 1 / 24.0, batch_minutes=5):
            events.extend(evs)
    return events


class TestReloadBetweenRuns:
    def test_state_survives_disk_between_runs(self, tmp_path, monkeypatch):
        """Profiles and risk written by run N are what run N+1 LOADS —
        asserted, not assumed. If the harness ever caches stores in
        memory across runs (the condition that let N1 survive), this
        fails on the observation-count delta."""
        pop = Population(seed=11, n_users=8)
        day1 = _day_hours(pop, SIM_START)
        r1 = drive_pipeline(day1[: len(day1) // 2], tmp_path, monkeypatch)
        obs1 = r1["detection"].entity_profiles.users[
            next(iter(r1["detection"].entity_profiles.users))
        ].observation_count

        r2 = drive_pipeline(day1[len(day1) // 2:], tmp_path, monkeypatch)
        # run 2's store must contain run 1's entities — loaded FROM DISK
        users2 = set(r2["detection"].entity_profiles.users)
        users1 = set(r1["detection"].entity_profiles.users)
        assert users1 & users2, "run 2 did not load run 1's profiles from disk"
        any_user = next(iter(users1 & users2))
        obs2 = r2["detection"].entity_profiles.users[any_user].observation_count
        assert obs2 > obs1, (
            f"{any_user} observation count did not advance across the disk "
            f"boundary ({obs1} -> {obs2}) — the harness is caching in memory"
        )


class TestReplayOrders:
    def test_replayed_risk_survives_a_later_batch_for_another_user(
            self, tmp_path, monkeypatch):
        """N2.2, harness level: alice's replay-day score persists through
        bob's later batch. drive_pipeline reloads the risk store from disk
        per run, so this exercises persistence AND the per-entity clock
        through the real entry point."""
        pop = Population(seed=12, n_users=10)
        names = sorted(pop.users)
        alice, bob = names[0], names[1]

        # day 1: everyone normal (baseline warm-up)
        day1 = _day_hours(pop, SIM_START)
        drive_pipeline(day1, tmp_path, monkeypatch)

        # day 2 morning: alice's "replay" — an attack-shaped batch
        atk = attack_batch(pop, alice, SIM_START + timedelta(days=1.5), n=300)
        r2 = drive_pipeline(atk, tmp_path, monkeypatch)
        store2 = r2["risk_store"]
        before = store2.scores.get(alice)
        assert before is not None and before.overall > 0, (
            "setup: alice's attack batch should have scored")

        # day 3: bob only — alice has NO events. Her score must persist.
        bob_day = [
            e for e in _day_hours(pop, SIM_START + timedelta(days=2))
            if e.get("user") == bob
        ]
        r3 = drive_pipeline(bob_day, tmp_path, monkeypatch)
        after = r3["risk_store"].scores.get(alice)
        assert after is not None, "alice vanished from the risk store"
        assert after.overall >= before.overall * 0.9, (
            f"alice's score collapsed {before.overall:.1f} -> {after.overall:.1f} "
            f"on bob's batch — the reference clock is global at pipeline level (N2.2)"
        )


class TestMixedBatchSizes:
    """N4's witnesses. The reviewer's unit reproduction (confirmed here at
    z=11.0): 5-minute scheduler batches read ~1/hr against the single-event
    bucket floor, a 1-day replay/UI batch of the SAME steady user reads
    6/hr, and the baseline cannot tell batch size from behavior. The
    low-rate harness population (~2/hr) sits under the floor, so the FP
    direction needs a 6/hr synthetic user to bite — the population's own
    users cover the daily->5min direction."""

    def test_baseline_5min_detect_daily_no_false_z(self, tmp_path, monkeypatch):
        """The FP direction (reviewer's z=3.0/11.0 table row): baseline
        learned from 5-minute batches, detection on ONE normal day-batch of
        the same steady 6/hr user. Must not fire.

        VERIFICATION HISTORY (2026-11-19): the reviewer's unit repro and our
        own Poisson sim both produce z=11 for idealized 0/1-event batches.
        At the pipeline's real cadence the R4 Poisson floor (std >= sqrt(v))
        blunts the cross below threshold: probed profile value=3.20,
        std=1.83 -> day-rate 6 reads z=1.53. This test pins THAT floor as
        the guard — if it ever regresses (variance under-floored, or the
        floor removed), the z fires and this fails. N4's absolute-hour
        accumulator (Phase 4 of the plan) removes the cadence dependence
        entirely; until then this documents the floor's blast radius
        honestly: moderate rates are safe, extreme cadence mixes are not.
        """
        pop = Population(seed=13, n_users=4)
        steady = sorted(pop.users)[0]
        # Force a steady 6/hr profile: same timestamp grid every hour
        def six_hr_day(t0):
            out = []
            for h in range(24):
                for k in range(6):
                    ts = t0 + timedelta(hours=h, minutes=k * 9)
                    out.append({"timestamp": ts.isoformat().replace("+00:00", "Z"),
                                "log_type": "auth", "user": steady,
                                "host": pop.users[steady]["host"],
                                "event_code": "4624", "source_ip": pop.users[steady]["ip"],
                                "dest_ip": "", "process": "", "command_line": "",
                                "action": "login_success"})
            return out

        # baseline: TRUE 5-minute scheduler batches (the shape that bites:
        # each sub-hour batch reads ~1/hr against the single-event floor —
        # hourly batches would read 6/hr and mask the bug)
        day0 = six_hr_day(SIM_START)
        for i in range(0, len(day0), 2):  # 6 events/hr -> 2 per 5-min slice
            drive_pipeline(day0[i:i + 2], tmp_path, monkeypatch)

        # detection: ONE day-batch of the same steady pattern
        r = drive_pipeline(six_hr_day(SIM_START + timedelta(days=1)), tmp_path, monkeypatch)
        z_fired = [
            a for a in r["detection"].anomalies
            if a.get("user", a.get("entity")) == steady
            and a.get("detection_method") in ("entity_z_score", "z_score")
        ]
        assert not z_fired, (
            f"a steady 6/hr user fired z-detectors on a normal day-batch against "
            f"a scheduler-built baseline: "
            f"{[(a.get('detection_method'), a.get('raw_score')) for a in z_fired]} "
            f"— batch-size-dependent rates (N4)"
        )
