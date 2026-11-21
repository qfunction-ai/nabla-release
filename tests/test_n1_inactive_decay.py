"""N-1 (round 7): the inactive-decay branch must RECOMPUTE the score
from the retained anomalies' base_contribution x decay against the
entity's own reference — the active branch's formula.

The shipped branch multiplied the already-decayed overall by a decay
measured from a last_updated that never advanced: every quiet batch
re-decayed the whole elapsed span, compounding (measured: a critical
finding at 7.5 reached 0.0000 after 25h of quiet 5-minute batches where
the closed form gives ~3.6).

Witnesses (plan v5, Phase 1):
- closed form at 5-min and 6h cadence (+-1% of day0 x 0.5^(h/24))
- cadence invariance: N quiet batches to T == one batch at T
- legacy score with no data_clock falls back to ref_clock exactly once
- dormant entity (no events) keeps its score (guard)
- contributions pruned below 0.05 in the inactive branch too
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

T0 = datetime(2026, 8, 16, 0, 0, tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _critical(ts: str) -> dict:
    return {
        "anomaly_id": "a-crit-1",
        "user": "victim",
        "host": "WS-01",
        "type": "critical_host_escalation",
        "detection_method": "critical_host_escalation",
        "severity": "critical",
        "confidence": 0.5,
        "timestamp": ts,
        "finding": "sudo on critical host",
    }


def _use_dir(monkeypatch, path) -> None:
    """Point Settings at a fresh data dir (get_settings caches the module
    global — reset it around every switch; round-5 lesson)."""
    monkeypatch.setenv("NABLA_DATA_DIR", str(path))
    import nabla.config as config_mod
    config_mod._settings = None


def _run(anomalies, clock, event_clocks=None):
    import nabla.risk as risk_mod
    with patch.object(risk_mod, "_data_clock", return_value=clock):
        return risk_mod.compute_risk_scores(
            anomalies, {"victim": "user"}, half_life_hours=24.0,
            event_clocks=event_clocks,
        )


def _load_score():
    from nabla.config import get_settings
    from nabla.risk import EntityRiskStore
    return EntityRiskStore(get_settings().entity_risk_scores_file).scores["victim"]


def _seed_legacy_score(base: float, ts: str, data_clock: str) -> None:
    """Write a store by hand (legacy shapes the API never writes)."""
    from nabla.config import get_settings
    from nabla.risk import EntityRiskScore, EntityRiskStore
    store = EntityRiskStore(get_settings().entity_risk_scores_file)
    s = EntityRiskScore(entity_id="victim", entity_type="user")
    s.overall = base
    s.categories = {
        "insider_threat": 0.0, "account_compromise": base,
        "data_exfiltration": 0.0, "lateral_movement": 0.0,
    }
    s.last_updated = ts
    s.data_clock = data_clock
    s.contributing_anomalies = [{
        "anomaly_id": "a-seed-1", "method": "unusual_process",
        "severity": "high", "timestamp": ts,
        "base_contribution": base, "contribution": base,
        "categories": ["account_compromise"],
    }]
    store.scores["victim"] = s
    store.save()


class TestClosedForm:
    def test_5min_cadence_25h(self, tmp_path, monkeypatch):
        _use_dir(monkeypatch, tmp_path)
        store = _run([_critical(_iso(T0))], T0)
        day0 = store.scores["victim"].overall
        assert day0 > 0, "seeding run produced no score"

        clock = T0
        for _ in range(300):  # 25h of quiet 5-minute batches
            clock += timedelta(minutes=5)
            _run([], clock, event_clocks={"victim": _iso(clock)})

        s = _load_score()
        h = (clock - T0).total_seconds() / 3600
        expected = day0 * 0.5 ** (h / 24.0)
        assert abs(s.overall - expected) <= 0.01 * expected, (
            f"after {h}h quiet at 5-min cadence: overall={s.overall:.4f} "
            f"expected={expected:.4f} (compounding decay — N-1)")

    def test_6h_cadence_24h(self, tmp_path, monkeypatch):
        _use_dir(monkeypatch, tmp_path)
        store = _run([_critical(_iso(T0))], T0)
        day0 = store.scores["victim"].overall

        clock = T0
        for _ in range(4):  # 24h of quiet 6-hour batches
            clock += timedelta(hours=6)
            _run([], clock, event_clocks={"victim": _iso(clock)})

        s = _load_score()
        h = (clock - T0).total_seconds() / 3600
        expected = day0 * 0.5 ** (h / 24.0)
        assert abs(s.overall - expected) <= 0.01 * expected, (
            f"after {h}h quiet at 6h cadence: overall={s.overall:.4f} "
            f"expected={expected:.4f} (compounding decay — N-1)")


class TestCadenceInvariance:
    def test_many_batches_equal_one_batch(self, tmp_path, monkeypatch):
        # 12 five-minute quiet batches to T0+1h  ==  ONE batch at T0+1h
        d_slow = tmp_path / "slow"; d_slow.mkdir()
        d_fast = tmp_path / "fast"; d_fast.mkdir()

        _use_dir(monkeypatch, d_slow)
        _run([_critical(_iso(T0))], T0)
        clock = T0
        for _ in range(12):
            clock += timedelta(minutes=5)
            _run([], clock, event_clocks={"victim": _iso(clock)})
        slow = _load_score().overall

        _use_dir(monkeypatch, d_fast)
        _run([_critical(_iso(T0))], T0)
        _run([], T0 + timedelta(hours=1),
             event_clocks={"victim": _iso(T0 + timedelta(hours=1))})
        fast = _load_score().overall

        assert abs(slow - fast) <= 0.01 * max(fast, 1e-9), (
            f"cadence-dependent decay: 12x5min={slow:.4f} vs 1x1h={fast:.4f}")


class TestLegacyFallback:
    def test_no_data_clock_falls_back_once(self, tmp_path, monkeypatch):
        _use_dir(monkeypatch, tmp_path)
        # Legacy score: data_clock empty, last_updated = anomaly time.
        _seed_legacy_score(6.0, _iso(T0), data_clock="")
        ref = T0 + timedelta(hours=10)

        _run([], ref)  # first pass: honest one-shot decay to ref, stamps clock
        s1 = _load_score()
        expected = 6.0 * 0.5 ** (10.0 / 24.0)
        assert abs(s1.overall - expected) <= 0.01 * expected, (
            f"legacy first pass: {s1.overall:.4f} vs closed form {expected:.4f}")
        assert s1.data_clock, "legacy pass did not stamp data_clock"

        _run([], ref)  # second pass at the same reference: score stands
        s2 = _load_score()
        assert abs(s2.overall - s1.overall) <= 0.01 * s1.overall, (
            f"legacy fallback applied twice: {s1.overall:.4f} -> {s2.overall:.4f}")


class TestDormantGuard:
    def test_dormant_entity_score_stands(self, tmp_path, monkeypatch):
        _use_dir(monkeypatch, tmp_path)
        store = _run([_critical(_iso(T0))], T0)
        before = store.scores["victim"].overall

        # Dormant: no events at all; the batch reference advances but the
        # entity's own clock does not — score stands (R6-4 dormancy).
        for h in (5, 11, 23):
            _run([], T0 + timedelta(hours=h))
        s = _load_score()
        assert abs(s.overall - before) <= 0.01 * before, (
            f"dormant entity decayed: {before:.4f} -> {s.overall:.4f}")


class TestPrune:
    def test_aged_out_contributions_pruned(self, tmp_path, monkeypatch):
        _use_dir(monkeypatch, tmp_path)
        # A small contribution aged 8 half-lives: below the 0.05 prune.
        _seed_legacy_score(0.5, _iso(T0), data_clock="")
        _run([], T0 + timedelta(hours=8 * 24))
        s = _load_score()
        assert s.overall == 0.0, f"unpruned husk survived: {s.overall}"
        assert s.contributing_anomalies == [], "pruned anomaly retained"


class TestZombieGuard:
    def test_empty_ts_survivors_dropped(self, tmp_path, monkeypatch):
        _use_dir(monkeypatch, tmp_path)
        from nabla.config import get_settings
        from nabla.risk import EntityRiskScore, EntityRiskStore
        store = EntityRiskStore(get_settings().entity_risk_scores_file)
        s = EntityRiskScore(entity_id="victim", entity_type="user")
        s.overall = 4.0
        s.categories = {"account_compromise": 4.0}
        s.last_updated = _iso(T0)
        s.data_clock = _iso(T0)
        s.contributing_anomalies = [{
            "anomaly_id": "z1", "method": "x", "severity": "high",
            "timestamp": "",  # N2.3 zombie: no timestamp
            "base_contribution": 4.0, "contribution": 4.0,
            "categories": ["account_compromise"],
        }]
        store.scores["victim"] = s
        store.save()

        _run([], T0 + timedelta(hours=3))
        s2 = _load_score()
        assert s2.contributing_anomalies == [], "empty-ts zombie retained"
        assert s2.overall == 0.0, "zombie kept the score alive"
