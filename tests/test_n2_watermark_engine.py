"""Round 7 Phase 3 witnesses — the stateful Rule 6 engine (N-2).

RED-first: every test here failed against the round-6 code (the
stateless reference engine + single-accumulator absorption) or against
the first per-batch wiring cut. The findings they pin:

  R-1   the engine must be STATEFUL — per-batch wiring undercounts 12x
  R-2   the network stream has its own open/observed state
  R-14  closes are idempotent (crash between profile save and
        watermark persist replays as a no-op)
  R-15  hours key per (source, hour) — one source's watermark cannot
        close another source's open hours
  R-16  the end-of-run sweep closes quiet entities' finished hours
  R-19  two sources feeding the same hour produce two per-source
        observations (documented split; cross-source sum is banked)
  v2    migration re-homes v1's flat open_hours and the "siem"
        watermark key
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

D = "2026-08-15T"
T0 = datetime(2026, 8, 15, tzinfo=timezone.utc)


def _fresh_dir() -> Path:
    d = Path(tempfile.mkdtemp())
    os.environ["NABLA_DATA_DIR"] = str(d)
    import nabla.config as cfg
    cfg._settings = None
    return d


def _ev(ts: str, user: str = "u", eid: str = "") -> dict:
    e = {"user": user, "timestamp": ts, "action": "activity",
         "type": "authentication"}
    if eid:
        e["event_id"] = eid
    return e


def _steady_hour(hour: int, per_hour: int = 6) -> list[dict]:
    return [_ev(f"{D}{hour:02d}:{k * 9:02d}:00Z") for k in range(per_hour)]


class TestR1StatefulEngine:
    def test_five_minute_batches_one_observation_per_hour(self):
        """R-1 (THE round-7 blocker): a steady 12/hr user delivered in
        5-minute batches through update_user must yield ONE observation
        of 12 for the hour. The round-6 reference engine was stateless —
        wiring it per batch would have observed each 5-minute slice as
        a complete hour (12x undercount on EVERY live batch: EWMA 1.0)."""
        _fresh_dir()
        from nabla.baselines import EntityProfileStore
        from nabla.pipeline.watermark import newest_event_ts
        store = EntityProfileStore(str(_fresh_dir() / "p.json"))
        # hour 0 arrives as twelve 5-minute pieces, watermark advancing
        for k in range(12):
            piece = [_ev(f"{D}00:{k * 5:02d}:00Z")]
            store.update_user("u", piece, source_kind="splunk",
                               watermark=newest_event_ts(piece))
        # hour 0 still open (watermark inside it)
        u = store.get_user("u")
        assert u.typical_event_count.n == 0, "hour closed before it ended"
        # hours 3-4 arrive -> watermark passes hour 0's close line
        later = _steady_hour(3) + _steady_hour(4)
        store.update_user("u", later, source_kind="splunk",
                          watermark=newest_event_ts(later))
        u = store.get_user("u")
        assert u.typical_event_count.n >= 1, "hour 0 never closed"
        assert u.typical_event_count.value == pytest.approx(12.0, abs=1.0), (
            f"steady 12/hr user observed as {u.typical_event_count.value} — "
            f"the per-batch 12x undercount (R-1)")

    def test_state_persists_across_store_reload(self):
        """R-1: the engine state lives on the PROFILE — a reload between
        batches composes exactly like a single process (the round-4
        reload lesson applied to the new engine)."""
        d = _fresh_dir()
        from nabla.baselines import EntityProfileStore
        from nabla.pipeline.watermark import newest_event_ts
        path = str(d / "p.json")
        store = EntityProfileStore(path)
        p1 = _steady_hour(0)[:3]
        store.update_user("u", p1, source_kind="splunk",
                          watermark=newest_event_ts(p1))
        store.save()
        # a DIFFERENT process picks up the next piece
        store2 = EntityProfileStore(path)
        p2 = _steady_hour(0)[3:]
        store2.update_user("u", p2, source_kind="splunk",
                           watermark=newest_event_ts(p2))
        u = store2.get_user("u")
        key = f"splunk|{D[:11]}00"
        assert u.open_hours.get(key, {}).get("count") == 6, (
            f"reloaded engine lost the first piece: {u.open_hours}")


class TestR2NetworkStreamSeparateState:
    def test_network_hour_observed_despite_event_stream_registry(self):
        """R-2: the network stream keeps its OWN open/observed state —
        the old shared closed_hours list blocked network observation of
        any hour the event stream had already observed."""
        _fresh_dir()
        from nabla.baselines import EntityProfileStore
        from nabla.pipeline.watermark import newest_event_ts
        store = EntityProfileStore(str(_fresh_dir() / "p.json"))
        # hour 0: mixed events — file chunks close at batch end
        batch = [_ev(f"{D}00:0{k}:00Z") for k in range(4)]
        batch += [{"user": "u", "timestamp": f"{D}00:3{k}:00Z",
                   "action": "network_connect", "type": "network"}
                  for k in range(4)]
        store.update_user("u", batch, source_kind="file")
        u = store.get_user("u")
        assert u.typical_event_count.n == 1, "event stream should observe hour 0"
        assert u.network_event_rate.n == 1, (
            "network stream must observe its own hour — the shared-registry "
            "disease (R-2)")
        assert u.network_event_rate.value == pytest.approx(4.0, abs=0.5), (
            f"network hour observed as {u.network_event_rate.value}, not 4")


class TestR14IdempotentClose:
    def test_crash_replay_does_not_double_observe(self):
        """R-14: the profile saved, the process died before the
        watermark persisted — the replay re-closes the same hours and
        must produce ZERO new observations (registry-stamped, idempotent)."""
        _fresh_dir()
        from nabla.baselines import EntityProfileStore
        from nabla.pipeline.watermark import newest_event_ts
        store = EntityProfileStore(str(_fresh_dir() / "p.json"))
        # hour 0 opens live; hours 3-4 arrive and close it
        store.update_user("u", _steady_hour(0), source_kind="splunk",
                          watermark=f"{D}00:50:00Z")
        later = _steady_hour(3) + _steady_hour(4)
        store.update_user("u", later, source_kind="splunk",
                          watermark=newest_event_ts(later))
        u = store.get_user("u")
        n_after = u.typical_event_count.n
        v_after = u.typical_event_count.value
        assert n_after >= 1, "hour 0 never closed"
        # CRASH: profile state saved, watermark NOT persisted. The
        # replay re-delivers the same batch against the same watermark.
        store.update_user("u", later, source_kind="splunk",
                          watermark=newest_event_ts(later))
        u = store.get_user("u")
        assert u.typical_event_count.n == n_after, (
            f"crash replay re-observed: n {n_after} -> "
            f"{u.typical_event_count.n} (R-14)")
        assert u.typical_event_count.value == pytest.approx(v_after), (
            "crash replay moved the EWMA (R-14)")


class TestR15R19SourceKeying:
    def test_synthetic_watermark_cannot_close_siem_hours(self):
        """R-15: open hours key per (source, hour) — a synthetic
        watermark advancing past a splunk hour must not close it."""
        _fresh_dir()
        from nabla.baselines import EntityProfileStore
        from nabla.pipeline.watermark import newest_event_ts
        store = EntityProfileStore(str(_fresh_dir() / "p.json"))
        # splunk hour 0 opens
        store.update_user("u", _steady_hour(0), source_kind="splunk",
                          watermark=f"{D}00:50:00Z")
        # synthetic data arrives much later — its watermark is far ahead
        synth = [_ev(f"{D}12:00:00Z", user="u")]
        store.update_user("u", synth, source_kind="synthetic",
                          watermark=newest_event_ts(synth))
        u = store.get_user("u")
        key = f"splunk|{D[:11]}00"
        assert key in u.open_hours, (
            f"synthetic watermark closed the splunk hour: {u.open_hours}")
        assert u.typical_event_count.n == 0, (
            "splunk hour observed by a synthetic watermark (R-15)")

    def test_two_sources_same_hour_two_observations(self):
        """R-19: an entity fed by two source kinds in the same hour
        produces two per-source observations (documented split-rate
        behavior; cross-source sum-at-close is banked)."""
        _fresh_dir()
        from nabla.baselines import EntityProfileStore
        from nabla.pipeline.watermark import newest_event_ts
        store = EntityProfileStore(str(_fresh_dir() / "p.json"))
        # splunk piece of hour 0 (live), then a file chunk carrying the
        # same wall hour (backfill — closes at batch end)
        store.update_user("u", _steady_hour(0)[:3], source_kind="splunk",
                          watermark=f"{D}00:30:00Z")
        store.update_user("u", _steady_hour(0)[3:], source_kind="file")
        u = store.get_user("u")
        assert f"file|{D[:11]}00" in u.observed_hours, (
            f"file hour not observed at batch end: {u.observed_hours}")
        assert f"splunk|{D[:11]}00" in u.open_hours, (
            f"splunk hour must stay open for its own watermark: {u.open_hours}")


class TestR16QuietEntitySweep:
    def test_sweep_closes_quiet_entity_hours(self):
        """R-16: an entity with open hours but NO events this run still
        gets its finished hours observed — the end-of-run sweep closes
        against each hour's own source watermark. Hours closed by the
        sweep are recorded, never treated as late."""
        _fresh_dir()
        from nabla.baselines import EntityProfileStore
        from nabla.pipeline.watermark import newest_event_ts
        d = _fresh_dir()
        store = EntityProfileStore(str(d / "p.json"))
        # alice has an open splunk hour from yesterday's run
        store.update_user("alice", _steady_hour(0), source_kind="splunk",
                          watermark=f"{D}00:50:00Z")
        # today's run: only bob has events; the watermark advances far
        # past alice's open hour
        bob = _steady_hour(10)
        store.update_user("bob", bob, source_kind="splunk",
                          watermark=newest_event_ts(bob))
        # the sweep (as the orchestration runs it, pre-save)
        from nabla.baselines import sweep_profile_hours
        state = {"source_watermarks": {"splunk": newest_event_ts(bob)}}
        swept = sweep_profile_hours(store, state)
        assert swept >= 1, "sweep closed nothing"
        alice = store.get_user("alice")
        key = f"splunk|{D[:11]}00"
        assert key in alice.observed_hours, (
            f"quiet entity's hour not swept into the registry: "
            f"{alice.observed_hours}")
        assert key not in alice.open_hours, "swept hour left open"
        assert alice.typical_event_count.n >= 1, (
            "swept hour never became an EWMA observation (R-16)")


class TestV2Migration:
    def _v1_store(self, d: Path) -> None:
        """A store as the round-6 v1 migration left it: flat open_hours,
        a 'siem' watermark key, v1 marker set."""
        profiles = {"users": {"u": {
            "entity_id": "u", "open_hours": {"2026-08-14T22": 5},
            "net_open_hours": {"2026-08-14T22": 2},
            "open_hour": "2026-08-14T23", "open_count": 3,
            "closed_hours": ["2026-08-14T21"],
        }}}
        (d / "entity_profiles.json").write_text(json.dumps(profiles))
        state = {"clock_spec_migrated": "2026-11-01T00:00:00Z",
                 "data_newest_ts": "2026-08-15T06:00:00Z",
                 "source_watermarks": {"siem": "2026-08-15T06:00:00Z",
                                       "synthetic": "", "file": ""}}
        (d / "system_state.json").write_text(json.dumps(state))

    def test_v2_rehomes_flat_state_and_siwm_key(self):
        d = _fresh_dir()
        self._v1_store(d)
        from nabla.pipeline.clock_migration import run_clock_migration
        summary = run_clock_migration(str(d))
        assert not summary.get("skipped"), "v2 migration skipped a v1 store"
        profiles = json.loads((d / "entity_profiles.json").read_text())
        prof = profiles["users"]["u"]
        assert prof["open_hours"] == {
            "__legacy__|2026-08-14T22": {"count": 5, "ids": [], "reopen_wm": ""},
            "__legacy__|2026-08-14T23": {"count": 3, "ids": [], "reopen_wm": ""},
        }, f"flat open_hours not re-homed: {prof['open_hours']}"
        assert prof["net_open_hours"] == {
            "__legacy__|2026-08-14T22": {"count": 2, "ids": [], "reopen_wm": ""}}, (
            f"net accumulator not re-homed: {prof['net_open_hours']}")
        assert "closed_hours" not in prof, "dead closed_hours survived"
        state = json.loads((d / "system_state.json").read_text())
        wms = state["source_watermarks"]
        assert "siem" not in wms, "bogus 'siem' key survived"
        assert wms.get("splunk") == "2026-08-15T06:00:00Z", (
            f"splunk watermark not seeded from the data clock: {wms}")
        assert wms.get("sumologic") == "2026-08-15T06:00:00Z", (
            f"sumologic watermark not seeded: {wms}")
        assert state.get("clock_spec_migrated_v2"), "v2 marker not set"
        # idempotent: second run skips
        assert run_clock_migration(str(d)).get("skipped") is True

    def test_fresh_store_needs_no_rehome(self):
        d = _fresh_dir()
        from nabla.pipeline.clock_migration import run_clock_migration
        summary = run_clock_migration(str(d))
        # fresh: v1 initializes watermarks, v2 finds nothing to re-home
        assert summary.get("open_hours_rehomed", 0) == 0
        assert summary.get("watermarks_rekeyed", 0) == 0
