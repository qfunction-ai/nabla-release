"""Tests for nabla.risk — entity risk scoring."""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from nabla import risk
from nabla.risk import (
    THREAT_CATEGORIES,
    EntityRiskScore,
    EntityRiskStore,
    compute_risk_scores,
    get_trend_label,
    _decay_factor,
    _hours_since,
    _resolve_categories,
    SEVERITY_WEIGHTS,
    METHOD_CATEGORIES,
)


# ---------------------------------------------------------------------------
# EntityRiskScore
# ---------------------------------------------------------------------------

class TestEntityRiskScore:
    def test_default_values(self):
        score = EntityRiskScore(entity_id="alice", entity_type="user")
        assert score.overall == 0.0
        assert score.peak == 0.0
        assert score.trend == 0.0
        assert all(cat in score.categories for cat in THREAT_CATEGORIES)

    def test_to_dict_roundtrip(self):
        score = EntityRiskScore(
            entity_id="bob",
            entity_type="host",
            overall=42.5,
            peak=60.0,
            trend=1.2,
            last_updated="2026-01-01T00:00:00+00:00",
            categories={"insider_threat": 10.0, "account_compromise": 42.5,
                        "data_exfiltration": 0.0, "lateral_movement": 5.0},
            contributing_anomalies=[{"method": "brute_force", "severity": "high"}],
        )
        d = score.to_dict()
        assert d["entity_id"] == "bob"
        assert d["overall"] == 42.5
        assert d["peak"] == 60.0
        assert d["trend"] == 1.2

        restored = EntityRiskScore.from_dict(d)
        assert restored.entity_id == "bob"
        assert restored.overall == 42.5
        assert restored.peak == 60.0

    def test_serialization_truncates_history(self):
        score = EntityRiskScore(entity_id="test")
        score.score_history = [(f"2026-01-01T{i:02d}:00:00", float(i)) for i in range(30)]
        d = score.to_dict()
        assert len(d["score_history"]) == 24

    def test_serialization_truncates_anomalies(self):
        score = EntityRiskScore(entity_id="test")
        score.contributing_anomalies = [{"method": f"m{i}"} for i in range(30)]
        d = score.to_dict()
        assert len(d["contributing_anomalies"]) == 20


# ---------------------------------------------------------------------------
# EntityRiskStore
# ---------------------------------------------------------------------------

class TestEntityRiskStore:
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "risk_scores.json")
            store = EntityRiskStore(path)
            score = store.get_or_create("alice", "user")
            score.overall = 55.0
            score.peak = 55.0
            score.categories["account_compromise"] = 55.0
            store.save()

            store2 = EntityRiskStore(path)
            loaded = store2.get("alice")
            assert loaded is not None
            assert loaded.overall == 55.0
            assert loaded.categories["account_compromise"] == 55.0

    def test_get_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "risk_scores.json")
            store = EntityRiskStore(path)
            assert store.get("nonexistent") is None

    def test_top_risky(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "risk_scores.json")
            store = EntityRiskStore(path)
            for name in ["alice", "bob", "carol"]:
                s = store.get_or_create(name, "user")
                s.overall = {"alice": 80, "bob": 30, "carol": 55}[name]
            top = store.top_risky(limit=2)
            assert len(top) == 2
            assert top[0].entity_id == "alice"
            assert top[1].entity_id == "carol"

    def test_handles_corrupt_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "risk_scores.json")
            with open(path, "w") as f:
                f.write("not json")
            store = EntityRiskStore(path)
            assert len(store.scores) == 0


# ---------------------------------------------------------------------------
# Decay and time helpers
# ---------------------------------------------------------------------------

class TestDecay:
    def test_recent_anomaly_no_decay(self):
        now = datetime.now(timezone.utc).isoformat()
        assert _decay_factor(now, half_life_hours=24.0) > 0.9

    def test_one_half_life(self):
        one_half_ago = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        decay = _decay_factor(one_half_ago, half_life_hours=24.0)
        assert 0.45 < decay < 0.55

    def test_two_half_lives(self):
        two_ago = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        decay = _decay_factor(two_ago, half_life_hours=24.0)
        assert 0.2 < decay < 0.3

    def test_invalid_timestamp(self):
        assert _decay_factor("garbage", half_life_hours=24.0) < 0.01


class TestHoursSince:
    def test_recent(self):
        now = datetime.now(timezone.utc).isoformat()
        assert _hours_since(now) < 0.1

    def test_one_hour_ago(self):
        one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        hours = _hours_since(one_hour_ago)
        assert 0.9 < hours < 1.1


# ---------------------------------------------------------------------------
# Category resolution
# ---------------------------------------------------------------------------

class TestResolveCategories:
    def test_brute_force_maps_to_account_compromise(self):
        anomaly = {"detection_method": "brute_force_attempt"}
        cats = _resolve_categories(anomaly)
        assert "account_compromise" in cats

    def test_lolbin_maps_to_lateral_movement(self):
        anomaly = {"detection_method": "lolbin_abuse"}
        cats = _resolve_categories(anomaly)
        assert "lateral_movement" in cats

    def test_temporal_chain_uses_phase(self):
        anomaly = {"detection_method": "temporal_chain", "phases": ["initial_access", "credential_access"]}
        cats = _resolve_categories(anomaly)
        assert "account_compromise" in cats  # credential_access → account_compromise

    def test_unknown_method_defaults_to_insider_threat(self):
        anomaly = {"detection_method": "unknown_method_xyz"}
        cats = _resolve_categories(anomaly)
        assert "insider_threat" in cats

    def test_multi_category_method(self):
        anomaly = {"detection_method": "known_attack_script"}
        cats = _resolve_categories(anomaly)
        assert "lateral_movement" in cats
        assert "account_compromise" in cats


# ---------------------------------------------------------------------------
# compute_risk_scores
# ---------------------------------------------------------------------------

class TestComputeRiskScores:
    def _make_anomaly(self, entity="alice", method="brute_force_attempt",
                      severity="high", confidence=0.8, hours_ago=0):
        ts = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
        return {
            "entity": entity,
            "detection_method": method,
            "severity": severity,
            "confidence": confidence,
            "timestamp": ts,
        }

    def test_basic_scoring(self):
        anomalies = [self._make_anomaly(method="brute_force_attempt", severity="high")]
        entity_type_map = {"alice": "user"}

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("nabla.config.get_settings") as mock_settings:
                s = MagicMock()
                s.entity_risk_scores_file = os.path.join(tmpdir, "risk.json")
                s.system_state_file = os.path.join(tmpdir, "nonexistent_state.json")  # data clock -> wall fallback
                s.system_state_file = os.path.join(tmpdir, "nonexistent_state.json")  # data clock -> wall fallback
                mock_settings.return_value = s

                store = compute_risk_scores(
                    anomalies=anomalies,
                    entity_type_map=entity_type_map,
                )
                score = store.get("alice")
                assert score is not None
                assert score.overall > 0
                assert score.categories["account_compromise"] > 0

    def test_decay_reduces_old_anomalies(self):
        recent = self._make_anomaly(hours_ago=0, severity="high")
        old = self._make_anomaly(hours_ago=48, severity="high")
        entity_type_map = {"alice": "user"}
        # CLOCK-SPEC Rule 4 (round 6): an entity's clock comes from its
        # EVENTS. Both runs simulate a live user whose event stream is at
        # "now" (the pipeline always passes event_clocks) — the OLD
        # anomaly's age is real; without the clock it would read age-0
        # (a fresh entity cannot decay from before it existed).
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        ev_clocks = {"alice": now_iso}

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("nabla.config.get_settings") as mock_settings:
                s = MagicMock()
                s.entity_risk_scores_file = os.path.join(tmpdir, "risk.json")
                s.system_state_file = os.path.join(tmpdir, "nonexistent_state.json")  # data clock -> wall fallback
                mock_settings.return_value = s

                # Recent anomaly alone
                store_recent = compute_risk_scores(
                    anomalies=[recent],
                    entity_type_map=entity_type_map,
                    event_clocks=ev_clocks,
                )
                recent_score = store_recent.get("alice").overall

                # Old anomaly alone — fresh store file (A6 retention means
                # a shared file carries the recent anomaly into the old run)
                s.entity_risk_scores_file = os.path.join(tmpdir, "risk_old.json")
                store_old = compute_risk_scores(
                    anomalies=[old],
                    entity_type_map=entity_type_map,
                    event_clocks=ev_clocks,
                )
                old_score = store_old.get("alice").overall

                assert recent_score > old_score

    def test_severity_weights(self):
        low = self._make_anomaly(severity="low")
        critical = self._make_anomaly(severity="critical")
        entity_type_map = {"alice": "user"}

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("nabla.config.get_settings") as mock_settings:
                s = MagicMock()
                s.entity_risk_scores_file = os.path.join(tmpdir, "risk.json")
                s.system_state_file = os.path.join(tmpdir, "nonexistent_state.json")  # data clock -> wall fallback
                mock_settings.return_value = s

                store_low = compute_risk_scores([low], entity_type_map)
                store_crit = compute_risk_scores([critical], entity_type_map)
                assert store_crit.get("alice").overall > store_low.get("alice").overall

    def test_no_anomalies_empty_store(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("nabla.config.get_settings") as mock_settings:
                s = MagicMock()
                s.entity_risk_scores_file = os.path.join(tmpdir, "risk.json")
                s.system_state_file = os.path.join(tmpdir, "nonexistent_state.json")  # data clock -> wall fallback
                mock_settings.return_value = s

                store = compute_risk_scores(
                    anomalies=[],
                    entity_type_map={},
                )
                assert len(store.scores) == 0

    def test_inactive_entity_decays(self, monkeypatch):
        """An entity with a previous score but no new anomalies should decay.

        The data clock is pinned rather than inherited. `_data_clock()` falls
        back to the wall clock when the state file is unreadable, and this
        test used to leave `system_state_file` unset — a MagicMock, so
        `os.path.exists()` raised TypeError, `_data_clock` swallowed it, and
        both runs landed microseconds apart. A 24-hour half-life over two
        microseconds is a ~1e-11 decay: a float64 coin flip, not an
        assertion. Pinning the clock one half-life apart makes the expected
        value exact.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "risk.json")

            with patch("nabla.config.get_settings") as mock_settings:
                s = MagicMock()
                s.entity_risk_scores_file = path
                s.system_state_file = os.path.join(tmpdir, "state.json")
                mock_settings.return_value = s

                start = datetime.now(timezone.utc)
                monkeypatch.setattr(risk, "_data_clock", lambda: start)
                monkeypatch.setattr(risk, "_future_ceiling",
                                    lambda: start + timedelta(hours=48))

                # First run: score alice, with the anomaly stamped at the
                # reference instant so its age is exactly zero.
                anomaly = self._make_anomaly(severity="high")
                anomaly["timestamp"] = start.isoformat()
                store1 = compute_risk_scores([anomaly], {"alice": "user"})
                score_before = store1.get("alice").overall
                assert score_before > 0, "setup failed: alice was never scored"

                # Second run, exactly one half-life later. N2.2 (round 4): a
                # dormant entity keeps its score until ITS OWN stream
                # advances — an empty batch no longer ages it (the global
                # clock did; that's the bug N2.2 removed). One later-stamped
                # anomaly for alice advances her own clock one half-life;
                # the retained seed then decays to half.
                later = start + timedelta(hours=24)
                monkeypatch.setattr(risk, "_data_clock", lambda: later)
                monkeypatch.setattr(risk, "_future_ceiling",
                                    lambda: later + timedelta(hours=48))
                advance = self._make_anomaly(severity="low")
                advance["timestamp"] = later.isoformat()
                advance["detection_method"] = "later_advance"
                store2 = compute_risk_scores([advance], {"alice": "user"})
                score_after = store2.get("alice").overall

                assert score_after < score_before
                assert score_after <= score_before * 0.9, (
                    f"one half-life past the seed should decay it, "
                    f"got {score_before} -> {score_after}"
                )

    def test_peak_tracksHighest(self):
        anomalies = [self._make_anomaly(severity="critical")]
        entity_type_map = {"alice": "user"}

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("nabla.config.get_settings") as mock_settings:
                s = MagicMock()
                s.entity_risk_scores_file = os.path.join(tmpdir, "risk.json")
                s.system_state_file = os.path.join(tmpdir, "nonexistent_state.json")  # data clock -> wall fallback
                mock_settings.return_value = s

                store = compute_risk_scores(anomalies, entity_type_map)
                score = store.get("alice")
                assert score.peak >= score.overall

    def test_multi_entity_scoring(self):
        anomalies = [
            self._make_anomaly(entity="alice", method="brute_force_attempt", severity="high"),
            self._make_anomaly(entity="bob", method="lolbin_abuse", severity="medium"),
        ]
        entity_type_map = {"alice": "user", "bob": "user"}

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("nabla.config.get_settings") as mock_settings:
                s = MagicMock()
                s.entity_risk_scores_file = os.path.join(tmpdir, "risk.json")
                s.system_state_file = os.path.join(tmpdir, "nonexistent_state.json")  # data clock -> wall fallback
                mock_settings.return_value = s

                store = compute_risk_scores(anomalies, entity_type_map)
                assert store.get("alice") is not None
                assert store.get("bob") is not None
                # Alice's brute force (high=10) should score higher than bob's lolbin (medium=5)
                assert store.get("alice").overall > store.get("bob").overall

    def test_score_capped_at_100(self):
        """Even with many critical anomalies, overall should not exceed 100."""
        anomalies = [self._make_anomaly(severity="critical") for _ in range(20)]
        entity_type_map = {"alice": "user"}

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("nabla.config.get_settings") as mock_settings:
                s = MagicMock()
                s.entity_risk_scores_file = os.path.join(tmpdir, "risk.json")
                s.system_state_file = os.path.join(tmpdir, "nonexistent_state.json")  # data clock -> wall fallback
                mock_settings.return_value = s

                store = compute_risk_scores(anomalies, entity_type_map)
                score = store.get("alice")
                assert score.overall <= 100.0
                for cat_val in score.categories.values():
                    assert cat_val <= 100.0


# ---------------------------------------------------------------------------
# Trend labels
# ---------------------------------------------------------------------------

class TestTrendLabel:
    def test_rising(self):
        assert get_trend_label(1.0) == "rising"

    def test_declining(self):
        assert get_trend_label(-1.0) == "declining"

    def test_stable(self):
        assert get_trend_label(0.0) == "stable"

    def test_slightly_rising(self):
        assert get_trend_label(0.3) == "stable"

    def test_slightly_declining(self):
        assert get_trend_label(-0.3) == "stable"
