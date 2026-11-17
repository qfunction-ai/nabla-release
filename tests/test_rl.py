"""Unit tests for RL adaptive threshold tuning."""

import json
import os
import tempfile

import pytest

from nabla.rl.thresholds import (
    ThresholdAgent,
    THRESHOLDS,
    ACTIONS,
    format_thresholds_block,
    _discretize_threshold,
    _threshold_from_bin,
    _discretize_precision,
    _discretize_volume,
)
from nabla.rl.reward import (
    compute_reward,
    parse_findings,
    METHOD_TO_THRESHOLD,
)
from nabla.rl.state import (
    extract_anomaly_count,
    extract_method_counts,
    extract_state,
)
from nabla.rl.bandit import DetectionMethodBandit, DETECTION_METHODS


# --- Threshold Agent Tests ---

class TestThresholdAgent:
    def test_default_values(self):
        agent = ThresholdAgent()
        for name, (lo, hi, step, default) in THRESHOLDS.items():
            assert agent.current_values[name] == default

    def test_lolbin_sensitivity_default(self):
        """LOLBIN sensitivity should have a default value."""
        agent = ThresholdAgent()
        assert agent.current_values["lolbin_sensitivity"] == 0.7

    def test_get_thresholds_returns_copy(self):
        agent = ThresholdAgent()
        t = agent.get_thresholds()
        t["z_score_sigma"] = 999
        assert agent.current_values["z_score_sigma"] != 999

    def test_choose_action_returns_valid(self):
        agent = ThresholdAgent()
        for name in THRESHOLDS:
            action = agent.choose_action(name, precision=0.5, alert_count=10)
            assert action in ACTIONS

    def test_apply_action_increase(self):
        agent = ThresholdAgent()
        agent._apply_action("z_score_sigma", "increase")
        assert agent.current_values["z_score_sigma"] == 2.25

    def test_apply_action_decrease(self):
        agent = ThresholdAgent()
        # z_score_sigma min is 2.0, so decrease from 2.5
        agent.current_values["z_score_sigma"] = 2.5
        agent._apply_action("z_score_sigma", "decrease")
        assert agent.current_values["z_score_sigma"] == 2.25

    def test_apply_action_keep(self):
        agent = ThresholdAgent()
        agent._apply_action("z_score_sigma", "keep")
        assert agent.current_values["z_score_sigma"] == 2.0

    def test_apply_action_clamped_low(self):
        agent = ThresholdAgent()
        agent.current_values["z_score_sigma"] = 2.0
        agent._apply_action("z_score_sigma", "decrease")
        agent._apply_action("z_score_sigma", "decrease")
        # 2.0 - 0.25 - 0.25 = 1.5, but min is 2.0
        assert agent.current_values["z_score_sigma"] == 2.0

    def test_apply_action_clamped_high(self):
        agent = ThresholdAgent()
        agent.current_values["z_score_sigma"] = 4.0
        agent._apply_action("z_score_sigma", "increase")
        assert agent.current_values["z_score_sigma"] == 4.0

    def test_update_increments_count(self):
        agent = ThresholdAgent()
        agent.update("z_score_sigma", 0.5, 10, "keep", 1.0, 10, 10)
        assert agent.update_counts["z_score_sigma"] == 1

    def test_serialization_roundtrip(self):
        agent = ThresholdAgent()
        agent.update("z_score_sigma", 0.5, 10, "increase", 0.6, 10, 10)
        data = agent.to_dict()
        restored = ThresholdAgent.from_dict(data)
        assert restored.current_values == agent.current_values
        assert restored.update_counts == agent.update_counts

    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "rl_state.json")
            agent = ThresholdAgent()
            agent.update("z_score_sigma", 0.5, 10, "increase", 0.6, 10, 10)
            agent.save(path)

            loaded = ThresholdAgent.load(path)
            assert loaded.current_values["z_score_sigma"] == agent.current_values["z_score_sigma"]
            assert loaded.update_counts["z_score_sigma"] == 1

    def test_load_missing_file(self):
        agent = ThresholdAgent.load("/nonexistent/path.json")
        assert agent.current_values["z_score_sigma"] == 2.0

    def test_integer_threshold_steps(self):
        agent = ThresholdAgent()
        agent._apply_action("off_hours_count", "increase")
        assert agent.current_values["off_hours_count"] == 4
        agent._apply_action("off_hours_count", "decrease")
        assert agent.current_values["off_hours_count"] == 3


class TestDiscretization:
    def test_threshold_bin(self):
        assert _discretize_threshold("z_score_sigma", 2.0) == 0
        assert _discretize_threshold("z_score_sigma", 4.0) == 8

    def test_threshold_roundtrip(self):
        for name, (lo, hi, step, _) in THRESHOLDS.items():
            for i in range(int((hi - lo) / step) + 1):
                val = _threshold_from_bin(name, i)
                idx = _discretize_threshold(name, val)
                assert idx == i, f"{name}: bin {i} → val {val} → bin {idx}"

    def test_precision_buckets(self):
        assert _discretize_precision(0.1) == 0
        assert _discretize_precision(0.5) == 1
        assert _discretize_precision(0.9) == 2

    def test_volume_buckets(self):
        assert _discretize_volume(5) == 0
        assert _discretize_volume(20) == 1
        assert _discretize_volume(50) == 2


class TestThresholdBlockFormat:
    def test_format_roundtrip(self):
        thresholds = {"z_score_sigma": 2.5, "brute_force_ratio": 0.6,
                      "off_hours_count": 4, "multi_ip_count": 3,
                      "spike_multiplier": 3.5, "lolbin_sensitivity": 0.7}
        text = format_thresholds_block(thresholds)
        for k, v in thresholds.items():
            assert f"{k}: {v}" in text


# --- Reward Tests ---

class TestReward:
    def test_confirmed_finding_positive_reward(self):
        text = "ESCALATED: [HIGH] brute_force_attempt: suspicious activity"
        rewards = compute_reward(text, anomaly_count=1)
        assert rewards["brute_force_ratio"] > 0

    def test_dismissed_finding_negative_reward(self):
        text = "Dismissed: off_hours_activity — benign maintenance"
        rewards = compute_reward(text, anomaly_count=1)
        assert rewards["off_hours_count"] < 0

    def test_no_findings_zero_reward(self):
        rewards = compute_reward("", anomaly_count=0)
        # All thresholds should have zero or near-zero reward
        for name, r in rewards.items():
            assert abs(r) < 1.0

    def test_lolbin_in_method_to_threshold(self):
        """LOLBIN abuse should map to lolbin_sensitivity threshold."""
        assert "lolbin_abuse" in METHOD_TO_THRESHOLD
        assert METHOD_TO_THRESHOLD["lolbin_abuse"] == "lolbin_sensitivity"
        assert "lolbin" in METHOD_TO_THRESHOLD
        assert METHOD_TO_THRESHOLD["lolbin"] == "lolbin_sensitivity"

    def test_parse_findings_mixed(self):
        text = "ESCALATED: [HIGH] brute_force_attempt\nDismissed: off_hours_activity — benign"
        findings = parse_findings(text)
        assert findings["confirmed_count"] == 1
        assert findings["dismissed_count"] == 1


# --- State Extraction Tests ---

class TestStateExtraction:
    def test_extract_anomaly_count_empty(self):
        assert extract_anomaly_count("") == 0

    def test_extract_anomaly_count_pending(self):
        text = "Pending anomalies: 5\n1. [HIGH] brute_force"
        assert extract_anomaly_count(text) == 5

    def test_extract_method_counts(self):
        text = "1. [HIGH] brute_force_attempt: 5/10 failed logins\n2. [MEDIUM] z_score_spike: z=2.5"
        counts = extract_method_counts(text)
        assert counts.get("brute_force", 0) + counts.get("brute_force_attempt", 0) >= 1

    def test_extract_lolbin_method_counts(self):
        """LOLBIN abuse entries should be counted."""
        text = "1. [HIGH] lolbin_abuse: LOLBIN certutil.exe\n2. [HIGH] brute_force_attempt: 5/10"
        counts = extract_method_counts(text)
        assert "lolbin_abuse" in counts
        assert counts["lolbin_abuse"] == 1

    def test_extract_state(self):
        state = extract_state("Pending anomalies: 3", "ESCALATED: brute_force")
        assert state["anomaly_count"] == 3
        assert state["confirmed_count"] == 1


# --- Bandit Tests ---

class TestBandit:
    def test_default_methods(self):
        bandit = DetectionMethodBandit()
        assert len(bandit.methods) == len(DETECTION_METHODS)

    def test_lolbin_in_default_methods(self):
        """LOLBIN should be in the default detection methods."""
        assert "lolbin" in DETECTION_METHODS

    def test_update_confirmed(self):
        bandit = DetectionMethodBandit()
        bandit.update("failed_login_ratio", confirmed=True)
        assert bandit.alpha["failed_login_ratio"] == 2.0
        assert bandit.beta["failed_login_ratio"] == 1.0

    def test_update_dismissed(self):
        bandit = DetectionMethodBandit()
        bandit.update("failed_login_ratio", confirmed=False)
        assert bandit.alpha["failed_login_ratio"] == 1.0
        assert bandit.beta["failed_login_ratio"] == 2.0

    def test_get_means(self):
        bandit = DetectionMethodBandit()
        bandit.update("failed_login_ratio", confirmed=True)
        bandit.update("failed_login_ratio", confirmed=True)
        means = bandit.get_means()
        assert means["failed_login_ratio"] > 0.5

    def test_get_ranking(self):
        bandit = DetectionMethodBandit()
        # Give failed_login_ratio many confirmed observations
        for _ in range(20):
            bandit.update("failed_login_ratio", confirmed=True)
        means = bandit.get_means()
        # With 20 confirmed and 0 dismissed, failed_login_ratio should have highest mean
        assert means["failed_login_ratio"] > 0.9
        assert means["failed_login_ratio"] == max(means.values())

    def test_unknown_method_auto_registered(self):
        bandit = DetectionMethodBandit()
        bandit.update("new_method", confirmed=True)
        assert "new_method" in bandit.methods
        assert bandit.alpha["new_method"] == 2.0

    def test_serialization_roundtrip(self):
        bandit = DetectionMethodBandit()
        bandit.update("failed_login_ratio", confirmed=True)
        data = bandit.to_dict()
        restored = DetectionMethodBandit.from_dict(data)
        assert restored.alpha == bandit.alpha
        assert restored.beta == bandit.beta

    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "rl_state.json")
            # Write a combined state file
            bandit = DetectionMethodBandit()
            bandit.update("failed_login_ratio", confirmed=True)
            state = {"bandit": bandit.to_dict()}
            with open(path, "w") as f:
                json.dump(state, f)

            loaded = DetectionMethodBandit.load(path)
            assert loaded.alpha["failed_login_ratio"] == 2.0

    def test_load_missing_file(self):
        bandit = DetectionMethodBandit.load("/nonexistent/path.json")
        assert len(bandit.methods) == len(DETECTION_METHODS)

    def test_all_detection_methods_in_bandit(self):
        """Every detection_method emitted by detect_anomalies should be in DETECTION_METHODS."""
        from nabla.detection import detect_anomalies
        # The actual method names used in detect_anomalies output
        actual_methods = {
            "pre_flagged", "z_score", "failed_login_ratio", "off_hours",
            "multi_ip", "activity_spike", "lolbin", "parent_child",
            "critical_host_escalation", "unusual_process", "action_sequence",
        }
        for method in actual_methods:
            assert method in DETECTION_METHODS, f"{method} missing from DETECTION_METHODS"

    def test_gcn_lof_and_provenance_in_bandit(self):
        """GCN-LOF and provenance_community should be in DETECTION_METHODS."""
        assert "gcn_lof" in DETECTION_METHODS
        assert "provenance_community" in DETECTION_METHODS

    def test_new_detection_methods_in_bandit(self):
        """New endpoint detection methods should be in DETECTION_METHODS."""
        for method in ("suspicious_path", "integrity_anomaly", "registry_abuse", "network_anomaly"):
            assert method in DETECTION_METHODS, f"{method} missing from DETECTION_METHODS"


# --- RL reward negation patterns ---

class TestRewardNegation:
    """Test that negation patterns in supervisor output are not counted as confirmed findings."""

    def test_no_confirmed_threats(self):
        """'No confirmed threats found' should not count as a confirmed finding."""
        from nabla.rl.reward import parse_findings
        result = parse_findings("No confirmed threats found in this review cycle.")
        assert result["confirmed_count"] == 0
        assert result["dismissed_count"] == 0

    def test_no_findings(self):
        """'No findings to report' should not count as confirmed."""
        from nabla.rl.reward import parse_findings
        result = parse_findings("No findings to report.")
        assert result["confirmed_count"] == 0

    def test_no_threats_detected(self):
        """'No threats detected' should not count as confirmed."""
        from nabla.rl.reward import parse_findings
        result = parse_findings("No threats detected in the current analysis window.")
        assert result["confirmed_count"] == 0

    def test_actual_confirmed_still_works(self):
        """Actual confirmed findings should still be counted."""
        from nabla.rl.reward import parse_findings
        result = parse_findings("Confirmed: brute_force_attempt from 10.0.0.1\nEscalated: [HIGH] suspicious_path")
        assert result["confirmed_count"] == 2

    def test_mixed_negation_and_confirmed(self):
        """Negation lines should be skipped, but confirmed lines should count."""
        from nabla.rl.reward import parse_findings
        text = "No confirmed threats found in batch 1.\nConfirmed: activity_spike on host-1"
        result = parse_findings(text)
        assert result["confirmed_count"] == 1

    def test_zero_confirmed(self):
        """'0 confirmed' should not count as a confirmed finding."""
        from nabla.rl.reward import parse_findings
        result = parse_findings("Review complete: 0 confirmed, 0 dismissed.")
        assert result["confirmed_count"] == 0
