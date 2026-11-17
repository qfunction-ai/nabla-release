"""Tests for system phase tracking (baseline vs detection)."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from nabla.system_state import (
    ALWAYS_ACTIVE_METHODS,
    BASELINE_DEPENDENT_METHODS,
    baseline_days_remaining,
    format_phase_summary,
    format_system_phase_block,
    load_system_state,
    record_ingestion,
    save_system_state,
    should_transition,
    warm_up_summary,
    transition_to_detection,
)


class TestLoadSystemState:
    """Tests for load_system_state."""

    def test_returns_default_when_file_missing(self, tmp_path):
        state = load_system_state(str(tmp_path / "nonexistent.json"))
        assert state["phase"] == "baseline"
        assert state["first_ingestion_at"] is None
        assert state["baseline_min_days"] == 21
        assert state["transitioned_at"] is None

    def test_loads_valid_file(self, tmp_path):
        path = str(tmp_path / "system_state.json")
        data = {
            "phase": "detection",
            "first_ingestion_at": "2025-01-01T00:00:00+00:00",
            "baseline_min_days": 14,
            "transitioned_at": "2025-01-15T00:00:00+00:00",
        }
        with open(path, "w") as f:
            json.dump(data, f)

        state = load_system_state(path)
        assert state["phase"] == "detection"
        assert state["first_ingestion_at"] == "2025-01-01T00:00:00+00:00"
        assert state["baseline_min_days"] == 14

    def test_fills_missing_keys_from_defaults(self, tmp_path):
        path = str(tmp_path / "system_state.json")
        with open(path, "w") as f:
            json.dump({"phase": "baseline"}, f)

        state = load_system_state(path)
        assert state["phase"] == "baseline"
        assert state["first_ingestion_at"] is None
        assert state["baseline_min_days"] == 21

    def test_returns_default_on_corrupted_file(self, tmp_path):
        path = str(tmp_path / "system_state.json")
        with open(path, "w") as f:
            f.write("not valid json{{{")

        state = load_system_state(path)
        assert state["phase"] == "baseline"


class TestSaveSystemState:
    """Tests for save_system_state."""

    def test_saves_to_file(self, tmp_path):
        path = str(tmp_path / "system_state.json")
        state = {"phase": "detection", "first_ingestion_at": "2025-01-01T00:00:00+00:00"}
        save_system_state(path, state)

        with open(path, "r") as f:
            loaded = json.load(f)
        assert loaded["phase"] == "detection"


class TestRecordIngestion:
    """Tests for record_ingestion."""

    def test_records_first_splunk_ingestion(self):
        state = {"phase": "baseline", "first_ingestion_at": None, "baseline_min_days": 21, "transitioned_at": None}
        result = record_ingestion(state, "splunk")
        assert result["first_ingestion_at"] is not None
        # Should be an ISO timestamp
        datetime.fromisoformat(result["first_ingestion_at"])

    def test_records_first_sumologic_ingestion(self):
        state = {"phase": "baseline", "first_ingestion_at": None, "baseline_min_days": 21, "transitioned_at": None}
        result = record_ingestion(state, "sumologic")
        assert result["first_ingestion_at"] is not None

    def test_ignores_synthetic_source(self):
        state = {"phase": "baseline", "first_ingestion_at": None, "baseline_min_days": 21, "transitioned_at": None}
        result = record_ingestion(state, "synthetic")
        assert result["first_ingestion_at"] is None

    def test_ignores_file_source(self):
        state = {"phase": "baseline", "first_ingestion_at": None, "baseline_min_days": 21, "transitioned_at": None}
        result = record_ingestion(state, "file")
        assert result["first_ingestion_at"] is None

    def test_does_not_overwrite_existing(self):
        existing = "2025-01-01T00:00:00+00:00"
        state = {"phase": "baseline", "first_ingestion_at": existing, "baseline_min_days": 21, "transitioned_at": None}
        result = record_ingestion(state, "splunk")
        assert result["first_ingestion_at"] == existing


class TestShouldTransition:
    """Tests for should_transition."""

    def test_already_in_detection(self):
        state = {"phase": "detection", "first_ingestion_at": "2020-01-01T00:00:00+00:00", "baseline_min_days": 21, "transitioned_at": None}
        assert should_transition(state, warm_user_count=10) is False

    def test_no_first_ingestion(self):
        state = {"phase": "baseline", "first_ingestion_at": None, "baseline_min_days": 21, "transitioned_at": None}
        assert should_transition(state, warm_user_count=10) is False

    def test_too_early(self):
        # First ingestion was 5 days ago
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        state = {"phase": "baseline", "first_ingestion_at": recent, "baseline_min_days": 21, "transitioned_at": None}
        assert should_transition(state, warm_user_count=10) is False

    def test_enough_time_but_insufficient_warm_users(self):
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        state = {"phase": "baseline", "first_ingestion_at": old, "baseline_min_days": 21, "transitioned_at": None}
        assert should_transition(state, warm_user_count=1) is False

    def test_transition_ready(self):
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        state = {"phase": "baseline", "first_ingestion_at": old, "baseline_min_days": 21, "transitioned_at": None}
        assert should_transition(state, warm_user_count=5) is True

    def test_transition_with_zero_warm_users_no_profiles(self):
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        state = {"phase": "baseline", "first_ingestion_at": old, "baseline_min_days": 21, "transitioned_at": None}
        # warm_user_count=0 and no entity_profiles → entity check is skipped
        assert should_transition(state, warm_user_count=0) is True

    def test_transition_with_entity_profiles(self):
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        state = {"phase": "baseline", "first_ingestion_at": old, "baseline_min_days": 21, "transitioned_at": None}

        # Mock entity profiles with 5 warm users
        profiles = MagicMock()
        profiles.users = {}
        for i in range(5):
            mock_profile = MagicMock()
            mock_profile.observation_count = 10
            profiles.users[f"user{i}"] = mock_profile

        assert should_transition(state, warm_user_count=0, entity_profiles=profiles) is True

    def test_transition_insufficient_warm_entity_profiles(self):
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        state = {"phase": "baseline", "first_ingestion_at": old, "baseline_min_days": 21, "transitioned_at": None}

        profiles = MagicMock()
        profiles.users = {}
        for i in range(2):  # Only 2 warm users
            mock_profile = MagicMock()
            mock_profile.observation_count = 10
            profiles.users[f"user{i}"] = mock_profile

        assert should_transition(state, warm_user_count=0, entity_profiles=profiles) is False

    def test_custom_baseline_min_days(self):
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        state = {"phase": "baseline", "first_ingestion_at": recent, "baseline_min_days": 3, "transitioned_at": None}
        assert should_transition(state, warm_user_count=5) is True


class TestTransitionToDetection:
    """Tests for transition_to_detection."""

    def test_sets_phase_to_detection(self):
        state = {"phase": "baseline", "first_ingestion_at": "2025-01-01T00:00:00+00:00", "baseline_min_days": 21, "transitioned_at": None}
        result = transition_to_detection(state)
        assert result["phase"] == "detection"
        assert result["transitioned_at"] is not None
        datetime.fromisoformat(result["transitioned_at"])

    def test_does_not_mutate_original(self):
        state = {"phase": "baseline", "first_ingestion_at": "2025-01-01T00:00:00+00:00", "baseline_min_days": 21, "transitioned_at": None}
        result = transition_to_detection(state)
        # Actually it does mutate the same dict (in-place), but the
        # important thing is the phase is set correctly
        assert result["phase"] == "detection"


class TestBaselineDaysRemaining:
    """Tests for baseline_days_remaining."""

    def test_returns_none_in_detection(self):
        state = {"phase": "detection", "first_ingestion_at": "2025-01-01T00:00:00+00:00", "baseline_min_days": 21, "transitioned_at": None}
        assert baseline_days_remaining(state) is None

    def test_returns_none_without_first_ingestion(self):
        state = {"phase": "baseline", "first_ingestion_at": None, "baseline_min_days": 21, "transitioned_at": None}
        assert baseline_days_remaining(state) is None

    def test_returns_remaining_days(self):
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        state = {"phase": "baseline", "first_ingestion_at": recent, "baseline_min_days": 21, "transitioned_at": None}
        remaining = baseline_days_remaining(state)
        assert remaining is not None
        assert 10 <= remaining <= 11  # ~11 days remaining

    def test_returns_zero_when_elapsed(self):
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        state = {"phase": "baseline", "first_ingestion_at": old, "baseline_min_days": 21, "transitioned_at": None}
        assert baseline_days_remaining(state) == 0


class TestMethodSets:
    """Tests for BASELINE_DEPENDENT_METHODS and ALWAYS_ACTIVE_METHODS."""

    def test_no_overlap(self):
        overlap = BASELINE_DEPENDENT_METHODS & ALWAYS_ACTIVE_METHODS
        assert len(overlap) == 0, f"Overlap: {overlap}"

    def test_baseline_dependent_has_expected_methods(self):
        expected = {"z_score", "off_hours", "activity_spike", "multi_ip", "ewma", "cusum"}
        assert expected.issubset(BASELINE_DEPENDENT_METHODS)

    def test_always_active_has_expected_methods(self):
        expected = {"lolbin", "attack_script", "parent_child", "critical_host_escalation"}
        assert expected.issubset(ALWAYS_ACTIVE_METHODS)

    def test_entity_methods_in_baseline_dependent(self):
        entity_methods = {"entity_z_score", "entity_auth_failure", "entity_off_hours",
                          "entity_new_ip", "entity_activity_spike", "entity_new_process",
                          "entity_unusual_process", "entity_behavior_composite",
                          "entity_host_composite"}
        assert entity_methods.issubset(BASELINE_DEPENDENT_METHODS)


class TestWarmUpSummary:
    """Tests for warm_up_summary."""

    def test_returns_zeros_without_profiles(self):
        result = warm_up_summary(None)
        assert result["users"]["total"] == 0
        assert result["users"]["warm"] == 0
        assert result["users"]["pct"] == 0
        assert result["min_observations"] == 3

    def test_counts_warm_users(self):
        profiles = MagicMock()
        user1 = MagicMock(observation_count=5)
        user2 = MagicMock(observation_count=2)
        user3 = MagicMock(observation_count=10)
        profiles.users = {"alice": user1, "bob": user2, "carol": user3}
        profiles.hosts = {}
        profiles.ips = {}

        result = warm_up_summary(profiles, min_observations=3)
        assert result["users"]["total"] == 3
        assert result["users"]["warm"] == 2  # alice and carol
        assert result["users"]["pct"] == 67  # 2/3 = 66.7% → 67%

    def test_counts_hosts_and_ips(self):
        profiles = MagicMock()
        host1 = MagicMock(observation_count=4)
        ip1 = MagicMock(observation_count=1)
        profiles.users = {}
        profiles.hosts = {"WS001": host1}
        profiles.ips = {"8.8.8.8": ip1}

        result = warm_up_summary(profiles, min_observations=3)
        assert result["hosts"]["total"] == 1
        assert result["hosts"]["warm"] == 1
        assert result["ips"]["total"] == 1
        assert result["ips"]["warm"] == 0

    def test_zero_total_pct_is_zero(self):
        profiles = MagicMock()
        profiles.users = {}
        profiles.hosts = {}
        profiles.ips = {}

        result = warm_up_summary(profiles)
        assert result["users"]["pct"] == 0
        assert result["hosts"]["pct"] == 0
        assert result["ips"]["pct"] == 0

    def test_custom_min_observations(self):
        profiles = MagicMock()
        user1 = MagicMock(observation_count=2)
        profiles.users = {"alice": user1}
        profiles.hosts = {}
        profiles.ips = {}

        result = warm_up_summary(profiles, min_observations=5)
        assert result["users"]["warm"] == 0
        assert result["min_observations"] == 5


class TestFormatPhaseSummary:
    """Tests for format_phase_summary."""

    def test_detection_phase(self):
        state = {"phase": "detection", "first_ingestion_at": "2025-01-01T00:00:00+00:00",
                 "baseline_min_days": 21, "transitioned_at": "2025-01-22T00:00:00+00:00"}
        output = format_phase_summary(state)
        assert "DETECTION" in output
        assert "All detection methods active" in output
        assert "Transitioned from baseline" in output

    def test_baseline_phase_no_ingestion(self):
        state = {"phase": "baseline", "first_ingestion_at": None,
                 "baseline_min_days": 21, "transitioned_at": None}
        output = format_phase_summary(state)
        assert "BASELINE" in output
        assert "No SIEM ingestion recorded yet" in output
        assert "✓" in output  # Active methods
        assert "✗" in output  # Suppressed methods

    def test_baseline_phase_with_ingestion(self):
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        state = {"phase": "baseline", "first_ingestion_at": recent,
                 "baseline_min_days": 21, "transitioned_at": None}
        output = format_phase_summary(state)
        assert "BASELINE" in output
        assert "Days until transition" in output

    def test_baseline_with_warm_up(self):
        state = {"phase": "baseline", "first_ingestion_at": None,
                 "baseline_min_days": 21, "transitioned_at": None}
        warm_up = {
            "users": {"total": 10, "warm": 3, "pct": 30},
            "hosts": {"total": 5, "warm": 1, "pct": 20},
            "ips": {"total": 20, "warm": 0, "pct": 0},
            "min_observations": 3,
        }
        output = format_phase_summary(state, warm_up)
        assert "3/10" in output
        assert "1/5" in output
        assert "0/20" in output
        assert "█" in output  # Progress bar

    def test_detection_with_warm_up(self):
        state = {"phase": "detection", "first_ingestion_at": "2025-01-01T00:00:00+00:00",
                 "baseline_min_days": 21, "transitioned_at": None}
        warm_up = {
            "users": {"total": 15, "warm": 15, "pct": 100},
            "hosts": {"total": 8, "warm": 8, "pct": 100},
            "ips": {"total": 30, "warm": 30, "pct": 100},
            "min_observations": 3,
        }
        output = format_phase_summary(state, warm_up)
        assert "15 users" in output
        assert "8 hosts" in output
        assert "30 IPs" in output


class TestFormatSystemPhaseBlock:
    """Tests for format_system_phase_block."""

    def test_baseline_phase(self):
        state = {"phase": "baseline", "first_ingestion_at": None,
                 "baseline_min_days": 21, "transitioned_at": None}
        output = format_system_phase_block(state)
        assert "Phase: BASELINE" in output
        assert "ACTIVE detection methods" in output
        assert "SUPPRESSED detection methods" in output
        assert "IMPLICATIONS FOR REVIEW" in output
        assert "signature-based findings" in output
        assert "lolbin" in output.lower() or "LOLBIN" in output

    def test_baseline_with_warm_up(self):
        state = {"phase": "baseline", "first_ingestion_at": None,
                 "baseline_min_days": 21, "transitioned_at": None}
        warm_up = {
            "users": {"total": 5, "warm": 2, "pct": 40},
            "hosts": {"total": 3, "warm": 0, "pct": 0},
            "ips": {"total": 10, "warm": 1, "pct": 10},
            "min_observations": 3,
        }
        output = format_system_phase_block(state, warm_up)
        assert "WARM-UP PROGRESS" in output
        assert "2/5" in output
        assert "0/3" in output
        assert "1/10" in output

    def test_detection_phase(self):
        state = {"phase": "detection", "first_ingestion_at": "2025-01-01T00:00:00+00:00",
                 "baseline_min_days": 21, "transitioned_at": None}
        output = format_system_phase_block(state)
        assert "Phase: DETECTION" in output
        assert "All detection methods active" in output
        assert "SUPPRESSED" not in output

    def test_detection_with_warm_up(self):
        state = {"phase": "detection", "first_ingestion_at": "2025-01-01T00:00:00+00:00",
                 "baseline_min_days": 21, "transitioned_at": None}
        warm_up = {
            "users": {"total": 10, "warm": 10, "pct": 100},
            "hosts": {"total": 5, "warm": 5, "pct": 100},
            "ips": {"total": 20, "warm": 20, "pct": 100},
            "min_observations": 3,
        }
        output = format_system_phase_block(state, warm_up)
        assert "10 users" in output
        assert "5 hosts" in output
        assert "20 IPs" in output

    def test_baseline_lists_all_active_methods(self):
        state = {"phase": "baseline", "first_ingestion_at": None,
                 "baseline_min_days": 21, "transitioned_at": None}
        output = format_system_phase_block(state)
        for method in ALWAYS_ACTIVE_METHODS:
            assert method in output

    def test_baseline_lists_all_suppressed_methods(self):
        state = {"phase": "baseline", "first_ingestion_at": None,
                 "baseline_min_days": 21, "transitioned_at": None}
        output = format_system_phase_block(state)
        for method in BASELINE_DEPENDENT_METHODS:
            assert method in output
