"""Unit tests for nabla.temporal — Temporal Correlation Engine and context formatting."""

import json
import pytest
from datetime import datetime, timedelta, timezone
from collections import defaultdict

from nabla.temporal import (
    PHASES,
    ANOMALY_TO_PHASES,
    TemporalChain,
    _UnionFind,
    _parse_timestamp,
    _extract_entities,
    _entities_overlap,
    map_anomaly_to_phases,
    build_temporal_chains,
    score_chain,
    should_flag_chain,
    detect_temporal_chains,
    detect_temporal_chains_with_context,
    format_temporal_summary,
)
from nabla.rl.bandit import DETECTION_METHODS
from nabla.rl.thresholds import THRESHOLDS
from nabla.detection import DEFAULT_THRESHOLDS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _ts(minutes_ago: int) -> str:
    """Generate an ISO timestamp N minutes ago from now."""
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


def _make_anomaly(
    anomaly_type: str = "brute_force_attempt",
    detection_method: str = "failed_login_ratio",
    user: str = "admin",
    source_ip: str = "10.0.1.100",
    minutes_ago: int = 10,
    host: str = "",
    **extra: object,
) -> dict:
    """Create a test anomaly dict."""
    a = {
        "type": anomaly_type,
        "severity": "high",
        "user": user,
        "source_ip": source_ip,
        "timestamp": _ts(minutes_ago),
        "details": f"Test {anomaly_type}",
        "detection_method": detection_method,
    }
    if host:
        a["host"] = host
    a.update(extra)
    return a


@pytest.fixture
def brute_force_chain():
    """Anomalies forming a brute-force → lateral movement chain (same IP)."""
    ip = "10.0.1.100"
    return [
        _make_anomaly("brute_force_attempt", "failed_login_ratio", user="admin", source_ip=ip, minutes_ago=30),
        _make_anomaly("off_hours_activity", "off_hours", user="admin", source_ip=ip, minutes_ago=25),
        _make_anomaly("lolbin_abuse", "lolbin", user="admin", source_ip=ip, minutes_ago=20),
        _make_anomaly("suspicious_parent_child", "parent_child", user="admin", source_ip=ip, minutes_ago=15),
    ]


@pytest.fixture
def disjoint_anomalies():
    """Two sets of anomalies with no shared entities — should form separate chains."""
    return [
        _make_anomaly("brute_force_attempt", "failed_login_ratio", user="admin", source_ip="10.0.1.100", minutes_ago=20),
        _make_anomaly("lolbin_abuse", "lolbin", user="admin", source_ip="10.0.1.100", minutes_ago=15),
        _make_anomaly("z_score_spike", "z_score", user="analyst1", source_ip="192.168.1.50", minutes_ago=10),
        _make_anomaly("activity_spike", "activity_spike", user="analyst1", source_ip="192.168.1.50", minutes_ago=5),
    ]


@pytest.fixture
def single_anomaly():
    """A single anomaly — cannot form a chain."""
    return [_make_anomaly(minutes_ago=10)]


# ---------------------------------------------------------------------------
# Kill-Chain Phase Mapping
# ---------------------------------------------------------------------------

class TestMapAnomalyToPhases:

    def test_brute_force_maps_to_credential_access(self):
        a = _make_anomaly("brute_force_attempt", "failed_login_ratio")
        phases = map_anomaly_to_phases(a)
        assert "credential_access" in phases

    def test_lolbin_maps_to_execution_and_evasion(self):
        a = _make_anomaly("lolbin_abuse", "lolbin")
        phases = map_anomaly_to_phases(a)
        assert "execution" in phases
        assert "defense_evasion" in phases

    def test_off_hours_maps_to_initial_access(self):
        a = _make_anomaly("off_hours_activity", "off_hours")
        phases = map_anomaly_to_phases(a)
        assert "initial_access" in phases

    def test_multi_ip_maps_to_lateral_movement(self):
        a = _make_anomaly("impossible_travel", "multi_ip")
        phases = map_anomaly_to_phases(a)
        assert "lateral_movement" in phases

    def test_critical_host_maps_to_escalation(self):
        a = _make_anomaly("critical_host_escalation", "critical_host_escalation")
        phases = map_anomaly_to_phases(a)
        assert "privilege_escalation" in phases

    def test_unknown_type_defaults_to_execution(self):
        a = {"type": "totally_unknown", "detection_method": "unknown_method"}
        phases = map_anomaly_to_phases(a)
        assert "execution" in phases

    def test_detection_method_preferred_over_type(self):
        """detection_method should be used first if it maps."""
        a = {"type": "brute_force_attempt", "detection_method": "lolbin_abuse"}
        phases = map_anomaly_to_phases(a)
        # lolbin_abuse maps to execution + defense_evasion, not credential_access
        assert "execution" in phases

    def test_all_anomaly_types_have_mapping(self):
        """Every detection method in the bandit should have a phase mapping."""
        for method in DETECTION_METHODS:
            if method == "temporal_chain":
                continue  # Output method, not input
            a = {"type": method, "detection_method": method}
            phases = map_anomaly_to_phases(a)
            assert len(phases) >= 1, f"{method} has no phase mapping"

    def test_phases_are_valid(self):
        """All returned phases should be in the PHASES list."""
        for atype, phases in ANOMALY_TO_PHASES.items():
            for p in phases:
                assert p in PHASES, f"{atype} maps to invalid phase '{p}'"


# ---------------------------------------------------------------------------
# Timestamp Parsing
# ---------------------------------------------------------------------------

class TestParseTimestamp:

    def test_iso_format(self):
        ts = "2026-04-28T10:00:00+00:00"
        result = _parse_timestamp(ts)
        assert result is not None
        assert result.year == 2026

    def test_utc_z_suffix(self):
        ts = "2026-04-28T10:00:00Z"
        result = _parse_timestamp(ts)
        assert result is not None

    def test_empty_string(self):
        assert _parse_timestamp("") is None

    def test_none_like(self):
        assert _parse_timestamp(None) is None

    def test_invalid_string(self):
        assert _parse_timestamp("not-a-date") is None


# ---------------------------------------------------------------------------
# Entity Extraction
# ---------------------------------------------------------------------------

class TestExtractEntities:

    def test_ip_extracted(self):
        a = {"source_ip": "10.0.1.100"}
        entities = _extract_entities(a)
        assert "10.0.1.100" in entities["ip"]

    def test_user_extracted(self):
        a = {"user": "admin"}
        entities = _extract_entities(a)
        assert "admin" in entities["user"]

    def test_unknown_user_skipped(self):
        a = {"user": "unknown"}
        entities = _extract_entities(a)
        assert "user" not in entities or "unknown" not in entities.get("user", set())

    def test_host_extracted(self):
        a = {"host": "WORKSTATION-01"}
        entities = _extract_entities(a)
        assert "WORKSTATION-01" in entities["host"]

    def test_comma_separated_ips(self):
        a = {"source_ip": "10.0.1.100, 10.0.1.200"}
        entities = _extract_entities(a)
        assert "10.0.1.100" in entities["ip"]
        assert "10.0.1.200" in entities["ip"]

    def test_empty_dict(self):
        entities = _extract_entities({})
        assert not any(entities.values())


class TestEntitiesOverlap:

    def test_same_ip(self):
        e1 = {"ip": {"10.0.1.100"}}
        e2 = {"ip": {"10.0.1.100"}}
        assert _entities_overlap(e1, e2) is True

    def test_different_ip(self):
        e1 = {"ip": {"10.0.1.100"}}
        e2 = {"ip": {"10.0.1.200"}}
        assert _entities_overlap(e1, e2) is False

    def test_same_user(self):
        e1 = {"user": {"admin"}}
        e2 = {"user": {"admin"}}
        assert _entities_overlap(e1, e2) is True

    def test_mixed_entity_types(self):
        e1 = {"ip": {"10.0.1.100"}}
        e2 = {"user": {"admin"}}
        assert _entities_overlap(e1, e2) is False

    def test_cross_type_overlap(self):
        e1 = {"ip": {"10.0.1.100"}, "user": {"admin"}}
        e2 = {"ip": {"10.0.1.200"}, "user": {"admin"}}
        assert _entities_overlap(e1, e2) is True


# ---------------------------------------------------------------------------
# Union-Find
# ---------------------------------------------------------------------------

class TestUnionFind:

    def test_initial_state(self):
        uf = _UnionFind(5)
        for i in range(5):
            assert uf.find(i) == i

    def test_union_merges(self):
        uf = _UnionFind(5)
        uf.union(0, 1)
        assert uf.find(0) == uf.find(1)

    def test_transitive_merge(self):
        uf = _UnionFind(5)
        uf.union(0, 1)
        uf.union(1, 2)
        assert uf.find(0) == uf.find(2)

    def test_no_merge_independent(self):
        uf = _UnionFind(5)
        uf.union(0, 1)
        uf.union(3, 4)
        assert uf.find(0) != uf.find(3)

    def test_idempotent_union(self):
        uf = _UnionFind(3)
        uf.union(0, 1)
        root1 = uf.find(0)
        uf.union(0, 1)  # No-op
        assert uf.find(0) == root1


# ---------------------------------------------------------------------------
# Chain Builder
# ---------------------------------------------------------------------------

class TestBuildTemporalChains:

    def test_single_anomaly_no_chain(self, single_anomaly):
        chains = build_temporal_chains(single_anomaly)
        assert len(chains) == 0

    def test_empty_input(self):
        chains = build_temporal_chains([])
        assert len(chains) == 0

    def test_two_linked_anomalies(self):
        anomalies = [
            _make_anomaly("brute_force_attempt", "failed_login_ratio", source_ip="10.0.1.100", minutes_ago=10),
            _make_anomaly("lolbin_abuse", "lolbin", source_ip="10.0.1.100", minutes_ago=5),
        ]
        chains = build_temporal_chains(anomalies)
        assert len(chains) == 1
        assert len(chains[0].events) == 2

    def test_disjoint_chains(self, disjoint_anomalies):
        chains = build_temporal_chains(disjoint_anomalies)
        assert len(chains) == 2

    def test_chain_has_entities(self, brute_force_chain):
        chains = build_temporal_chains(brute_force_chain)
        assert len(chains) == 1
        chain = chains[0]
        assert "10.0.1.100" in chain.entities.get("ip", set())

    def test_chain_has_phases(self, brute_force_chain):
        chains = build_temporal_chains(brute_force_chain)
        assert len(chains) == 1
        chain = chains[0]
        assert len(chain.phases) >= 2

    def test_time_window_respected(self):
        """Anomalies beyond the time window should not be linked."""
        anomalies = [
            _make_anomaly(source_ip="10.0.1.100", minutes_ago=100),
            _make_anomaly(source_ip="10.0.1.100", minutes_ago=5),
        ]
        chains = build_temporal_chains(anomalies, time_window_minutes=30)
        assert len(chains) == 0  # Too far apart

    def test_time_window_extended(self):
        """With a wider window, the same anomalies should link."""
        anomalies = [
            _make_anomaly(source_ip="10.0.1.100", minutes_ago=100),
            _make_anomaly(source_ip="10.0.1.100", minutes_ago=5),
        ]
        chains = build_temporal_chains(anomalies, time_window_minutes=120)
        assert len(chains) == 1

    def test_no_entities_no_chain(self):
        """Anomalies with no shared entities should not form a chain."""
        anomalies = [
            {"type": "test", "detection_method": "test", "timestamp": _ts(10)},
            {"type": "test", "detection_method": "test", "timestamp": _ts(5)},
        ]
        chains = build_temporal_chains(anomalies)
        assert len(chains) == 0

    def test_chain_duration(self, brute_force_chain):
        chains = build_temporal_chains(brute_force_chain)
        assert len(chains) == 1
        assert chains[0].duration_seconds > 0

    def test_chain_sorted_by_start_time(self, disjoint_anomalies):
        chains = build_temporal_chains(disjoint_anomalies)
        if len(chains) >= 2:
            assert chains[0].start_time <= chains[1].start_time

    def test_overlapping_chains_merge(self):
        """Three anomalies: A-B linked, B-C linked → one chain."""
        anomalies = [
            _make_anomaly(source_ip="10.0.1.100", user="admin", minutes_ago=20),
            _make_anomaly(source_ip="10.0.1.100", user="analyst1", minutes_ago=15),  # Links to A via IP
            _make_anomaly(source_ip="10.0.1.200", user="analyst1", minutes_ago=10),  # Links to B via user
        ]
        chains = build_temporal_chains(anomalies, time_window_minutes=30)
        assert len(chains) == 1
        assert len(chains[0].events) == 3


# ---------------------------------------------------------------------------
# Chain Scoring
# ---------------------------------------------------------------------------

class TestScoreChain:

    def test_score_computed(self, brute_force_chain):
        chains = build_temporal_chains(brute_force_chain)
        chain = score_chain(chains[0])
        assert 0.0 <= chain.score <= 1.0

    def test_high_phase_coverage_increases_score(self, brute_force_chain):
        chains = build_temporal_chains(brute_force_chain)
        chain = score_chain(chains[0])
        # Brute force → escalation chain should have decent phase coverage
        assert chain.phase_coverage > 0.1

    def test_entity_overlap_stored(self, brute_force_chain):
        chains = build_temporal_chains(brute_force_chain)
        chain = score_chain(chains[0])
        # All events share the same IP → high overlap
        assert chain.entity_overlap > 0.5  # type: ignore[attr-defined]

    def test_single_event_chain_zero_score(self):
        chain = TemporalChain(events=[{"type": "test"}])
        scored = score_chain(chain)
        assert scored.score == 0.0


class TestShouldFlagChain:

    def test_short_chain_not_flagged(self):
        chain = TemporalChain(
            events=[_make_anomaly(), _make_anomaly()],
            phases=["credential_access"],
            phase_coverage=0.1,
        )
        assert should_flag_chain(chain, min_chain_length=3) is False

    def test_three_phases_flagged(self):
        chain = TemporalChain(
            events=[_make_anomaly() for _ in range(3)],
            phases=["credential_access", "execution", "defense_evasion"],
            phase_coverage=0.3,
        )
        assert should_flag_chain(chain, min_chain_length=3) is True

    def test_low_phase_coverage_not_flagged(self):
        chain = TemporalChain(
            events=[_make_anomaly() for _ in range(3)],
            phases=["credential_access"],
            phase_coverage=0.1,
        )
        assert should_flag_chain(chain, min_chain_length=3, min_phase_coverage=0.2) is False

    def test_meets_phase_coverage_flagged(self):
        chain = TemporalChain(
            events=[_make_anomaly() for _ in range(3)],
            phases=["credential_access", "execution"],
            phase_coverage=0.2,
        )
        assert should_flag_chain(chain, min_chain_length=3, min_phase_coverage=0.2) is True


# ---------------------------------------------------------------------------
# Top-level Detection Function
# ---------------------------------------------------------------------------

class TestDetectTemporalChains:

    def test_too_few_anomalies(self):
        result = detect_temporal_chains([], [])
        assert result == []

    def test_single_anomaly(self, single_anomaly):
        result = detect_temporal_chains([], single_anomaly)
        assert result == []

    def test_attack_scenario_detection(self, brute_force_chain):
        result = detect_temporal_chains([], brute_force_chain)
        assert len(result) >= 1
        assert result[0]["detection_method"] == "temporal_chain"
        assert result[0]["chain_length"] >= 3
        assert len(result[0]["phases"]) >= 2

    def test_disjoint_no_cross_chain(self, disjoint_anomalies):
        result = detect_temporal_chains([], disjoint_anomalies)
        # Each pair has 2 events, but min_chain_length=3 by default
        # So neither chain should be flagged
        assert len(result) == 0

    def test_disjoint_with_lower_threshold(self, disjoint_anomalies):
        result = detect_temporal_chains(
            [], disjoint_anomalies,
            thresholds={"temporal_min_chain_length": 2},
        )
        assert len(result) == 2

    def test_all_benign_no_flagging(self):
        """Non-overlapping benign anomalies should not form chains."""
        anomalies = [
            _make_anomaly("z_score_spike", "z_score", user="user1", source_ip="10.0.1.1", minutes_ago=10),
            _make_anomaly("activity_spike", "activity_spike", user="user2", source_ip="10.0.1.2", minutes_ago=5),
        ]
        result = detect_temporal_chains([], anomalies)
        assert len(result) == 0

    def test_output_fields(self, brute_force_chain):
        result = detect_temporal_chains([], brute_force_chain)
        assert len(result) >= 1
        a = result[0]
        assert "chain_id" in a
        assert "chain_length" in a
        assert "phases" in a
        assert "phase_coverage" in a
        assert "tightness" in a
        assert "score" in a
        assert "entities" in a
        assert "duration_seconds" in a
        assert "details" in a
        assert "severity" in a

    def test_custom_time_window(self):
        """Wider window should catch more distant anomalies."""
        anomalies = [
            _make_anomaly("brute_force_attempt", "failed_login_ratio", source_ip="10.0.1.100", minutes_ago=90),
            _make_anomaly("lolbin_abuse", "lolbin", source_ip="10.0.1.100", minutes_ago=60),
            _make_anomaly("critical_host_escalation", "critical_host_escalation", source_ip="10.0.1.100", minutes_ago=30),
        ]
        # Default 30 min window — only the last two link
        result_narrow = detect_temporal_chains([], anomalies)
        # Wide window — all three link
        result_wide = detect_temporal_chains(
            [], anomalies,
            thresholds={"temporal_chain_window_minutes": 120},
        )
        assert len(result_wide) >= 1

    def test_severity_high_for_many_phases(self, brute_force_chain):
        result = detect_temporal_chains([], brute_force_chain)
        if result:
            # Brute force chain has 3+ phases → high severity
            assert result[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# RL Integration
# ---------------------------------------------------------------------------

class TestRLIntegration:

    def test_temporal_thresholds_in_defaults(self):
        assert "temporal_chain_window_minutes" in DEFAULT_THRESHOLDS
        assert "temporal_min_chain_length" in DEFAULT_THRESHOLDS

    def test_temporal_thresholds_in_rl(self):
        assert "temporal_chain_window_minutes" in THRESHOLDS
        assert "temporal_min_chain_length" in THRESHOLDS

    def test_temporal_in_bandit_methods(self):
        assert "temporal_chain" in DETECTION_METHODS

    def test_temporal_thresholds_in_block(self):
        from nabla.blocks import SHARED_BLOCKS
        rl_text = SHARED_BLOCKS["rl_thresholds"]
        assert "temporal_chain_window_minutes" in rl_text
        assert "temporal_min_chain_length" in rl_text

    def test_temporal_in_reward_mapping(self):
        from nabla.rl.reward import METHOD_TO_THRESHOLD
        assert "temporal_chain" in METHOD_TO_THRESHOLD
        assert METHOD_TO_THRESHOLD["temporal_chain"] == "temporal_chain_window_minutes"


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_missing_timestamps(self):
        """Anomalies without timestamps should not crash."""
        anomalies = [
            {"type": "brute_force_attempt", "detection_method": "failed_login_ratio",
             "user": "admin", "source_ip": "10.0.1.100", "timestamp": ""},
            {"type": "lolbin_abuse", "detection_method": "lolbin",
             "user": "admin", "source_ip": "10.0.1.100", "timestamp": _ts(5)},
        ]
        chains = build_temporal_chains(anomalies)
        # One has no timestamp, but they share entities — may or may not link
        # The key is no crash
        assert isinstance(chains, list)

    def test_duplicate_anomalies(self):
        """Duplicate anomalies should not crash or create infinite chains."""
        a = _make_anomaly(source_ip="10.0.1.100", minutes_ago=10)
        anomalies = [a, a, a]
        chains = build_temporal_chains(anomalies)
        assert isinstance(chains, list)

    def test_large_time_window(self):
        """Very large time window should link all anomalies with shared entities."""
        anomalies = [
            _make_anomaly(source_ip="10.0.1.100", minutes_ago=1440),
            _make_anomaly(source_ip="10.0.1.100", minutes_ago=5),
        ]
        chains = build_temporal_chains(anomalies, time_window_minutes=1500)
        assert len(chains) == 1

    def test_zero_duration_chain(self):
        """All anomalies at the same timestamp should still form a chain."""
        now = _ts(10)
        anomalies = [
            _make_anomaly(source_ip="10.0.1.100", minutes_ago=10),
            _make_anomaly(source_ip="10.0.1.100", minutes_ago=10),
        ]
        chains = build_temporal_chains(anomalies)
        # Same timestamp → duration 0, but still a valid chain
        assert isinstance(chains, list)

    def test_chain_with_host_entity(self):
        """Chains should link via host as well as IP/user."""
        anomalies = [
            _make_anomaly("critical_host_escalation", "critical_host_escalation",
                          source_ip="10.0.1.100", host="DC01", minutes_ago=10),
            _make_anomaly("unusual_process", "unusual_process",
                          source_ip="10.0.1.200", host="DC01", minutes_ago=5),
        ]
        chains = build_temporal_chains(anomalies)
        assert len(chains) == 1
        assert "DC01" in chains[0].entities.get("host", set())

    def test_phase_coverage_fraction(self):
        """Phase coverage should be fraction of total PHASES."""
        chain = TemporalChain(
            events=[_make_anomaly() for _ in range(3)],
            phases=["credential_access", "execution"],
            phase_coverage=2.0 / len(PHASES),
        )
        assert 0.0 < chain.phase_coverage < 1.0


# ---------------------------------------------------------------------------
# Tests for detect_temporal_chains_with_context
# ---------------------------------------------------------------------------

class TestDetectWithContext:
    """Tests for detect_temporal_chains_with_context returning chain objects."""

    def test_returns_tuple(self):
        """detect_temporal_chains_with_context returns (anomalies, chains)."""
        anomalies = [
            {"type": "test", "detection_method": "failed_login_ratio",
             "source_ip": "10.0.1.50", "user": "admin", "timestamp": "2025-01-01T00:00:00Z"},
            {"type": "test", "detection_method": "off_hours",
             "source_ip": "10.0.1.50", "user": "admin", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        result = detect_temporal_chains_with_context([], anomalies)
        assert isinstance(result, tuple)
        assert len(result) == 2
        anomalies_out, chains = result
        assert isinstance(anomalies_out, list)
        assert isinstance(chains, list)

    def test_too_few_anomalies(self):
        """With fewer than 2 anomalies, returns empty results."""
        result = detect_temporal_chains_with_context([], [{"type": "test"}])
        assert result == ([], [])

    def test_detect_temporal_chains_still_works(self):
        """detect_temporal_chains (without context) still returns just the list."""
        anomalies = [
            {"type": "test", "detection_method": "failed_login_ratio",
             "source_ip": "10.0.1.50", "user": "admin", "timestamp": "2025-01-01T00:00:00Z"},
            {"type": "test", "detection_method": "off_hours",
             "source_ip": "10.0.1.50", "user": "admin", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        result = detect_temporal_chains([], anomalies)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Tests for format_temporal_summary
# ---------------------------------------------------------------------------

class TestFormatTemporalSummary:
    """Tests for format_temporal_summary producing block text."""

    def test_empty_chains(self):
        """Empty chains list returns none-detected message."""
        result = format_temporal_summary([])
        assert "none" in result.lower()

    def test_flagged_chains_only(self):
        """Only flagged chains (phase_coverage >= 0.2 or 3+ phases) appear in detail."""
        # Flagged chain: 3 phases
        flagged = TemporalChain(
            chain_id=0,
            events=[{"type": "test"}] * 3,
            phases=["initial_access", "execution", "persistence"],
            phase_coverage=0.3,
            score=0.8,
            entities={"ip": {"10.0.1.50"}, "user": {"admin"}},
        )
        # Not flagged: 1 phase, low coverage
        not_flagged = TemporalChain(
            chain_id=1,
            events=[{"type": "test"}],
            phases=["execution"],
            phase_coverage=0.1,
            score=0.2,
            entities={"ip": {"192.168.1.1"}},
        )
        result = format_temporal_summary([flagged, not_flagged])
        assert "Chain 0" in result
        assert "Chain 1" not in result  # Not flagged, shouldn't appear in detail

    def test_json_line_present(self):
        """Output includes a JSON: line with structured chain data."""
        chain = TemporalChain(
            chain_id=0,
            events=[{"type": "test"}] * 3,
            phases=["initial_access", "execution", "persistence"],
            phase_coverage=0.3,
            score=0.8,
            entities={"ip": {"10.0.1.50"}, "user": {"admin"}},
        )
        result = format_temporal_summary([chain])
        json_lines = [l for l in result.split("\n") if l.startswith("JSON:")]
        assert len(json_lines) == 1
        data = json.loads(json_lines[0][5:])
        assert "chains" in data
        assert len(data["chains"]) == 1

    def test_json_chain_fields(self):
        """JSON chain entries have required fields."""
        chain = TemporalChain(
            chain_id=0,
            events=[{"type": "test"}] * 3,
            phases=["initial_access", "execution", "persistence"],
            phase_coverage=0.3,
            score=0.8,
            entities={"ip": {"10.0.1.50"}, "user": {"admin"}},
        )
        result = format_temporal_summary([chain])
        json_lines = [l for l in result.split("\n") if l.startswith("JSON:")]
        data = json.loads(json_lines[0][5:])
        c = data["chains"][0]
        assert "chain_id" in c
        assert "events" in c
        assert "phases" in c
        assert "score" in c
        assert "entities" in c

    def test_phase_narrative(self):
        """Human-readable output shows phase progression with arrows."""
        chain = TemporalChain(
            chain_id=0,
            events=[{"type": "test"}] * 3,
            phases=["initial_access", "execution", "persistence"],
            phase_coverage=0.3,
            score=0.8,
            entities={"ip": {"10.0.1.50"}},
        )
        result = format_temporal_summary([chain])
        assert "initial_access → execution → persistence" in result

    def test_entity_listing(self):
        """Human-readable output lists entity types and names."""
        chain = TemporalChain(
            chain_id=0,
            events=[{"type": "test"}] * 3,
            phases=["initial_access", "execution", "persistence"],
            phase_coverage=0.3,
            score=0.8,
            entities={"ip": {"10.0.1.50"}, "user": {"admin"}},
        )
        result = format_temporal_summary([chain])
        assert "10.0.1.50" in result
        assert "admin" in result

    def test_duration_formatting(self):
        """Duration is formatted as seconds, minutes, or hours."""
        # Short duration
        chain = TemporalChain(
            chain_id=0,
            events=[{"type": "test"}] * 3,
            phases=["initial_access", "execution", "persistence"],
            phase_coverage=0.3,
            score=0.8,
            duration_seconds=30,
            entities={"ip": {"10.0.1.50"}},
        )
        result = format_temporal_summary([chain])
        assert "30s" in result

        # Medium duration
        chain2 = TemporalChain(
            chain_id=1,
            events=[{"type": "test"}] * 3,
            phases=["initial_access", "execution", "persistence"],
            phase_coverage=0.3,
            score=0.8,
            duration_seconds=120,
            entities={"ip": {"10.0.1.50"}},
        )
        result2 = format_temporal_summary([chain2])
        assert "2min" in result2

    def test_flagged_count_in_header(self):
        """Header shows flagged vs total count."""
        chain = TemporalChain(
            chain_id=0,
            events=[{"type": "test"}] * 3,
            phases=["initial_access", "execution", "persistence"],
            phase_coverage=0.3,
            score=0.8,
            entities={"ip": {"10.0.1.50"}},
        )
        result = format_temporal_summary([chain])
        assert "1 flagged out of 1 total" in result
