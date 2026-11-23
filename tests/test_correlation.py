"""Unit tests for nabla.correlation — deterministic threat correlation."""

import json
import pytest

from nabla.correlation import (
    parse_anomaly_queue,
    parse_graph_context,
    parse_attack_mapping,
    correlate_anomalies,
    assess_findings,
    format_findings,
    build_timeline,
    run_correlation,
    _extract_process,
    _extract_tool_names,
    _parse_ts,
    _fmt_ts,
    _fmt_duration,
)


# ---------------------------------------------------------------------------
# parse_anomaly_queue
# ---------------------------------------------------------------------------

class TestParseAnomalyQueue:
    def test_empty_queue(self):
        assert parse_anomaly_queue("") == []
        assert parse_anomaly_queue("Pending anomalies: none") == []

    def test_valid_queue(self):
        text = (
            "Pending anomalies: 2 (showing top 2 by severity)\n"
            '  1. [HIGH] lolbin_abuse ts=2024-01-01T00:00:00Z user="admin"\n'
            '  JSON:{"type":"lolbin_abuse","severity":"high","user":"admin","source_ip":"1.2.3.4"}\n'
            '  2. [MEDIUM] off_hours_activity\n'
            '  JSON:{"type":"off_hours_activity","severity":"medium"}'
        )
        result = parse_anomaly_queue(text)
        assert len(result) == 2
        assert result[0]["type"] == "lolbin_abuse"
        assert result[0]["severity"] == "high"
        assert result[1]["type"] == "off_hours_activity"

    def test_malformed_json(self):
        text = (
            "Pending anomalies: 1\n"
            '  JSON:{bad json}\n'
            '  JSON:{"type":"ok"}'
        )
        result = parse_anomaly_queue(text)
        assert len(result) == 1
        assert result[0]["type"] == "ok"

    def test_no_json_lines(self):
        text = "Pending anomalies: 1\n  1. [HIGH] something"
        assert parse_anomaly_queue(text) == []


# ---------------------------------------------------------------------------
# parse_graph_context
# ---------------------------------------------------------------------------

class TestParseGraphContext:
    def test_empty(self):
        ec, ech, comms, chains = parse_graph_context("")
        assert ec == {}
        assert ech == {}
        assert comms == []
        assert chains == []

    def test_not_yet_analyzed(self):
        ec, ech, comms, chains = parse_graph_context("Graph context: not yet analyzed")
        assert ec == {}

    def test_no_provenance(self):
        ec, ech, comms, chains = parse_graph_context(
            "Graph context: no provenance or temporal data available"
        )
        assert ec == {}

    def test_with_communities(self):
        data = {
            "communities": [
                {
                    "id": 1,
                    "anomaly_density": 0.5,
                    "flagged": True,
                    "types": ["process", "ip"],
                    "members": ["certutil.exe", "1.2.3.4"],
                    "neighbors": {"certutil.exe": ["1.2.3.4"]},
                }
            ]
        }
        text = f"Provenance summary:\nJSON:{json.dumps(data)}"
        ec, ech, comms, chains = parse_graph_context(text)
        assert len(comms) == 1
        assert "certutil.exe" in ec
        assert ec["certutil.exe"]["community_id"] == 1
        assert ec["certutil.exe"]["flagged"] is True

    def test_with_chains(self):
        data = {
            "chains": [
                {
                    "chain_id": 1,
                    "phases": ["initial_access", "execution"],
                    "score": 0.8,
                    "phase_coverage": 0.5,
                    "entities": {"ip": ["1.2.3.4"], "user": ["admin"]},
                }
            ]
        }
        text = f"Temporal summary:\nJSON:{json.dumps(data)}"
        ec, ech, comms, chains = parse_graph_context(text)
        assert len(chains) == 1
        assert "ip:1.2.3.4" in ech
        assert ech["ip:1.2.3.4"][0]["chain_id"] == 1
        assert "user:admin" in ech


# ---------------------------------------------------------------------------
# parse_attack_mapping
# ---------------------------------------------------------------------------

class TestParseAttackMapping:
    def test_empty(self):
        assert parse_attack_mapping("") == {}
        assert parse_attack_mapping("ATT&CK mapping: not loaded") == {}

    def test_valid_mapping(self):
        text = (
            "lolbin_abuse:\n"
            "  T1218 | System Binary Proxy Execution | defense-evasion\n"
            "  T1140 | Deobfuscate/Decode Files or Information | defense-evasion\n"
            "brute_force_attempt:\n"
            "  T1110 | Brute Force | credential-access"
        )
        result = parse_attack_mapping(text)
        assert "lolbin_abuse" in result
        assert len(result["lolbin_abuse"]) == 2
        assert result["lolbin_abuse"][0]["id"] == "T1218"
        assert "brute_force_attempt" in result
        assert result["brute_force_attempt"][0]["id"] == "T1110"

    def test_skips_groups_mitigations(self):
        text = (
            "lolbin_abuse:\n"
            "  T1218 | System Binary Proxy Execution | defense-evasion\n"
            "Groups: G001\n"
            "Mitigations: M1015"
        )
        result = parse_attack_mapping(text)
        assert len(result["lolbin_abuse"]) == 1


# ---------------------------------------------------------------------------
# _extract_process
# ---------------------------------------------------------------------------

class TestExtractProcess:
    def test_lolbin_pattern(self):
        a = {"details": "LOLBIN C:\\Windows\\System32\\certutil.exe with command: -urlcache"}
        assert _extract_process(a) == "certutil"

    def test_by_pattern(self):
        a = {"details": "by C:\\Intel\\Build\\LB3.exe: suspicious registry modification"}
        assert _extract_process(a) == "lb3"

    def test_suspicious_path_pattern(self):
        a = {"details": "Process from suspicious path: C:\\Intel\\Build\\LB3.exe (integrity)"}
        assert _extract_process(a) == "lb3"

    def test_no_match(self):
        a = {"details": "Some other anomaly description"}
        assert _extract_process(a) == ""

    def test_empty_details(self):
        a = {"details": ""}
        assert _extract_process(a) == ""


# ---------------------------------------------------------------------------
# correlate_anomalies
# ---------------------------------------------------------------------------

class TestCorrelateAnomalies:
    def _make_anomaly(self, atype="lolbin_abuse", ip="1.2.3.4", user="admin",
                      log_type="auth", severity="high", process=""):
        a = {
            "type": atype,
            "detection_method": atype,
            "severity": severity,
            "source_ip": ip,
            "user": user,
            "log_type": log_type,
            "timestamp": "2024-01-01T00:00:00Z",
            "details": "",
        }
        if process:
            a["details"] = f"LOLBIN C:\\Windows\\System32\\{process}.exe with command"
        return a

    def test_ip_cross_type(self):
        """IP with anomalies across multiple log types → correlation."""
        anomalies = [
            self._make_anomaly(ip="1.2.3.4", log_type="auth"),
            self._make_anomaly(ip="1.2.3.4", log_type="endpoint"),
            self._make_anomaly(ip="1.2.3.4", log_type="dns"),
        ]
        corrs = correlate_anomalies(anomalies, {}, {})
        ip_corrs = [c for c in corrs if c["entity_type"] == "ip"]
        assert len(ip_corrs) >= 1
        assert ip_corrs[0]["entity"] == "1.2.3.4"
        assert set(ip_corrs[0]["log_types"]) == {"auth", "dns", "endpoint"}

    def test_user_cross_type(self):
        """User with anomalies across multiple log types → correlation."""
        anomalies = [
            self._make_anomaly(user="alice", log_type="auth", ip=""),
            self._make_anomaly(user="alice", log_type="endpoint", ip=""),
        ]
        corrs = correlate_anomalies(anomalies, {}, {})
        user_corrs = [c for c in corrs if c["entity_type"] == "user"]
        assert len(user_corrs) >= 1
        assert user_corrs[0]["entity"] == "alice"

    def test_process_multi_type(self):
        """Process flagged by multiple detection methods → correlation."""
        anomalies = [
            self._make_anomaly(atype="lolbin_abuse", process="certutil", ip="", user=""),
            self._make_anomaly(atype="suspicious_path", process="certutil", ip="", user=""),
        ]
        # Override details for second anomaly
        anomalies[1]["details"] = "Process from suspicious path: C:\\temp\\certutil.exe (integrity)"
        corrs = correlate_anomalies(anomalies, {}, {})
        proc_corrs = [c for c in corrs if c["entity_type"] == "process"]
        assert len(proc_corrs) >= 1
        assert proc_corrs[0]["entity"] == "certutil"

    def test_no_correlation_single_type(self):
        """Single anomaly → no correlation (needs at least 2 events)."""
        anomalies = [self._make_anomaly(ip="1.2.3.4", log_type="auth")]
        corrs = correlate_anomalies(anomalies, {}, {})
        ip_corrs = [c for c in corrs if c["entity_type"] == "ip"]
        assert len(ip_corrs) == 0

    def test_user_multi_method_same_log_type(self):
        """User with multiple detection methods in same log type → correlation."""
        anomalies = [
            self._make_anomaly(atype="lolbin_abuse", user="alice", log_type="endpoint", ip=""),
            self._make_anomaly(atype="suspicious_path", user="alice", log_type="endpoint", ip=""),
        ]
        anomalies[1]["details"] = "Process from suspicious path: C:\\temp\\tool.exe (integrity)"
        corrs = correlate_anomalies(anomalies, {}, {})
        user_corrs = [c for c in corrs if c["entity_type"] == "user"]
        assert len(user_corrs) >= 1
        assert user_corrs[0]["entity"] == "alice"

    def test_user_critical_same_log_type(self):
        """User with critical-severity anomalies in same log type → correlation."""
        anomalies = [
            self._make_anomaly(atype="renamed_attack_tool", user="alice", log_type="endpoint", ip="", severity="critical"),
            self._make_anomaly(atype="renamed_attack_tool", user="alice", log_type="endpoint", ip="", severity="critical"),
        ]
        anomalies[0]["details"] = "Renamed attack tool: Kerberos TGS (Rubeus) (process: rsynctool)"
        anomalies[1]["details"] = "Renamed attack tool: Diamond ticket (Rubeus) (process: rsynctool)"
        corrs = correlate_anomalies(anomalies, {}, {})
        user_corrs = [c for c in corrs if c["entity_type"] == "user"]
        assert len(user_corrs) >= 1
        assert user_corrs[0]["severity"] == "critical"

    def test_process_critical_same_method(self):
        """Process with multiple critical anomalies (same method) → correlation."""
        anomalies = [
            self._make_anomaly(atype="renamed_attack_tool", process="rsynctool", ip="", user="", severity="critical"),
            self._make_anomaly(atype="renamed_attack_tool", process="rsynctool", ip="", user="", severity="critical"),
        ]
        anomalies[0]["details"] = "Renamed attack tool: Kerberos TGS (Rubeus) (process: rsynctool)"
        anomalies[1]["details"] = "Renamed attack tool: Diamond ticket (Rubeus) (process: rsynctool)"
        corrs = correlate_anomalies(anomalies, {}, {})
        proc_corrs = [c for c in corrs if c["entity_type"] == "process"]
        assert len(proc_corrs) >= 1
        assert proc_corrs[0]["entity"] == "rsynctool"

    def test_standalone_critical_anomaly(self):
        """Critical anomaly from critical type with no other events → standalone correlation."""
        anomalies = [
            self._make_anomaly(atype="renamed_attack_tool", user="bob", ip="", severity="critical"),
        ]
        anomalies[0]["details"] = "Renamed attack tool: Kerberos TGS (Rubeus) (process: rsynctool)"
        corrs = correlate_anomalies(anomalies, {}, {})
        assert len(corrs) >= 1
        assert corrs[0]["severity"] == "critical"

    def test_extract_process_renamed_tool_pattern(self):
        """_extract_process handles (process: X) pattern from renamed_tool details."""
        a = {"details": "Renamed attack tool: Kerberos TGS (Rubeus) (process: rsynctool)"}
        assert _extract_process(a) == "rsynctool"

    def test_graph_context_enrichment(self):
        """Correlation enriched with graph community data."""
        anomalies = [
            self._make_anomaly(ip="1.2.3.4", log_type="auth"),
            self._make_anomaly(ip="1.2.3.4", log_type="endpoint"),
        ]
        ec = {"1.2.3.4": {"community_id": 1, "anomaly_density": 0.5, "flagged": True, "types": ["ip", "process"]}}
        corrs = correlate_anomalies(anomalies, ec, {})
        ip_corrs = [c for c in corrs if c["entity_type"] == "ip"]
        assert len(ip_corrs) >= 1
        assert ip_corrs[0].get("graph_community") is not None
        assert ip_corrs[0]["graph_community"]["flagged"] is True

    def test_temporal_chain_enrichment(self):
        """Correlation enriched with temporal chain data."""
        anomalies = [
            self._make_anomaly(ip="1.2.3.4", log_type="auth"),
            self._make_anomaly(ip="1.2.3.4", log_type="endpoint"),
        ]
        ech = {"ip:1.2.3.4": [{"chain_id": 1, "phases": ["initial_access", "execution"], "score": 0.8, "phase_coverage": 0.5}]}
        corrs = correlate_anomalies(anomalies, {}, ech)
        ip_corrs = [c for c in corrs if c["entity_type"] == "ip"]
        assert len(ip_corrs) >= 1
        assert ip_corrs[0].get("temporal_chains") is not None


# ---------------------------------------------------------------------------
# assess_findings
# ---------------------------------------------------------------------------

class TestAssessFindings:
    def test_basic_severity(self):
        corrs = [{
            "entity": "1.2.3.4",
            "entity_type": "ip",
            "anomaly_types": ["lolbin_abuse"],
            "log_types": ["auth", "endpoint", "dns"],
            "total_events": 5,
            "anomalous_events": 5,
        }]
        findings = assess_findings(corrs, {})
        assert len(findings) == 1
        # 3 log types → score 4 → critical
        assert findings[0]["severity"] == "critical"

    def test_medium_severity(self):
        corrs = [{
            "entity": "1.2.3.4",
            "entity_type": "ip",
            "anomaly_types": ["off_hours_activity"],
            "log_types": ["auth"],
            "total_events": 1,
            "anomalous_events": 1,
        }]
        findings = assess_findings(corrs, {})
        assert len(findings) == 1
        # 1 log type, no critical anomaly type, low volume → medium (base score 2)
        assert findings[0]["severity"] == "medium"

    def test_critical_anomaly_type_boost(self):
        corrs = [{
            "entity": "1.2.3.4",
            "entity_type": "ip",
            "anomaly_types": ["brute_force_attempt"],
            "log_types": ["auth"],
            "total_events": 1,
            "anomalous_events": 1,
        }]
        findings = assess_findings(corrs, {})
        # brute_force_attempt is critical → +1 boost
        assert findings[0]["severity"] in ("high", "critical")

    def test_attack_enrichment(self):
        corrs = [{
            "entity": "1.2.3.4",
            "entity_type": "ip",
            "anomaly_types": ["lolbin_abuse"],
            "log_types": ["auth", "endpoint"],
            "total_events": 2,
            "anomalous_events": 2,
        }]
        attack_lookup = {
            "lolbin_abuse": [
                {"id": "T1218", "name": "System Binary Proxy Execution", "tactic": "defense-evasion"},
            ]
        }
        findings = assess_findings(corrs, attack_lookup)
        assert len(findings[0]["mitre_attack"]) == 1
        assert findings[0]["mitre_attack"][0]["id"] == "T1218"

    def test_graph_context_boost(self):
        corrs = [{
            "entity": "1.2.3.4",
            "entity_type": "ip",
            "anomaly_types": ["off_hours_activity"],
            "log_types": ["auth"],
            "total_events": 1,
            "anomalous_events": 1,
            "graph_community": {"community_id": 1, "anomaly_density": 0.5, "flagged": True},
        }]
        findings = assess_findings(corrs, {})
        # Flagged community → +1 boost
        assert findings[0]["severity"] in ("high", "critical")

    def test_cross_type_label(self):
        corrs = [{
            "entity": "1.2.3.4",
            "entity_type": "ip",
            "anomaly_types": ["lolbin_abuse"],
            "log_types": ["auth", "endpoint"],
            "total_events": 2,
            "anomalous_events": 2,
        }]
        findings = assess_findings(corrs, {})
        assert findings[0]["cross_type"] == "cross-type"

    def test_single_type_label(self):
        corrs = [{
            "entity": "1.2.3.4",
            "entity_type": "ip",
            "anomaly_types": ["lolbin_abuse"],
            "log_types": ["auth"],
            "total_events": 1,
            "anomalous_events": 1,
        }]
        findings = assess_findings(corrs, {})
        assert findings[0]["cross_type"] == "single-type"


# ---------------------------------------------------------------------------
# format_findings
# ---------------------------------------------------------------------------

class TestFormatFindings:
    def test_empty(self):
        assert format_findings([]) == "Confirmed threats: none"

    def test_basic(self):
        findings = [{
            "severity": "high",
            "type": "lolbin_abuse",
            "entity": "1.2.3.4",
            "entity_type": "ip",
            "cross_type": "cross-type",
            "log_types": ["auth", "endpoint"],
            "confidence": 0.7,
            "mitre_attack": [{"id": "T1218", "name": "System Binary Proxy Execution", "tactic": "defense-evasion"}],
        }]
        text = format_findings(findings)
        assert "Confirmed threats: 1" in text
        assert "[HIGH]" in text
        assert "lolbin_abuse" in text
        assert "1.2.3.4" in text
        assert "T1218" in text
        assert "cross-type" in text

    def test_with_graph_context(self):
        findings = [{
            "severity": "critical",
            "type": "lolbin_abuse",
            "entity": "1.2.3.4",
            "entity_type": "ip",
            "cross_type": "cross-type",
            "log_types": ["auth"],
            "confidence": 0.9,
            "mitre_attack": [],
            "graph_community": {"community_id": 1, "anomaly_density": 0.5},
        }]
        text = format_findings(findings)
        assert "Community 1" in text
        assert "density=0.50" in text


# ---------------------------------------------------------------------------
# build_timeline
# ---------------------------------------------------------------------------

class TestBuildTimeline:
    def test_empty(self):
        assert build_timeline([]) == "No anomalies found."

    def test_single_event(self):
        anomalies = [{
            "type": "lolbin_abuse",
            "severity": "high",
            "user": "admin",
            "timestamp": "2024-01-01T12:00:00Z",
            "details": "LOLBIN C:\\Windows\\System32\\certutil.exe with command: -urlcache",
            "mitre_ids": ["T1218"],
        }]
        text = build_timeline(anomalies)
        assert "admin" in text
        assert "1 anomalous event" in text
        assert "T1218" in text

    def test_multiple_users(self):
        anomalies = [
            {"type": "off_hours_activity", "severity": "medium", "user": "alice", "timestamp": "2024-01-01T23:00:00Z", "details": ""},
            {"type": "brute_force_attempt", "severity": "high", "user": "bob", "timestamp": "2024-01-01T10:00:00Z", "details": "50.0% failed"},
        ]
        text = build_timeline(anomalies)
        assert "alice" in text
        assert "bob" in text
        assert "2 phases" in text

    def test_chronological_order(self):
        """Events are sorted chronologically within each user's phase."""
        anomalies = [
            {"type": "off_hours_activity", "severity": "medium", "user": "alice", "timestamp": "2024-01-01T23:00:00Z", "details": ""},
            {"type": "lolbin_abuse", "severity": "high", "user": "alice", "timestamp": "2024-01-01T10:00:00Z", "details": ""},
        ]
        text = build_timeline(anomalies)
        # Both events are for the same user, so they're in one phase.
        # The narrative starts at the earlier event (10:00) and spans to the later (23:00).
        assert "10:00 UTC" in text
        # The duration "13 hours" confirms the span from 10:00 to 23:00
        assert "13 hours" in text

    def test_no_timestamp(self):
        anomalies = [
            {"type": "lolbin_abuse", "severity": "high", "user": "admin", "details": ""},
        ]
        text = build_timeline(anomalies)
        assert "admin" in text


# ---------------------------------------------------------------------------
# _parse_ts, _fmt_ts, _fmt_duration helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_parse_ts_valid(self):
        from datetime import datetime, timezone
        result = _parse_ts({"timestamp": "2024-01-01T12:00:00Z"})
        assert result.year == 2024
        assert result.tzinfo is not None

    def test_parse_ts_missing(self):
        result = _parse_ts({})
        assert result.year == 9999  # datetime.max

    def test_parse_ts_invalid(self):
        result = _parse_ts({"timestamp": "not-a-date"})
        assert result.year == 9999

    def test_fmt_ts(self):
        assert _fmt_ts("2024-01-15T14:30:00Z") == "14:30 UTC on Jan 15"
        assert _fmt_ts("unknown") == "an unknown time"
        assert _fmt_ts("") == "an unknown time"

    def test_fmt_duration(self):
        assert _fmt_duration("2024-01-01T10:00:00Z", "2024-01-01T10:00:45Z") == "45 seconds"
        assert _fmt_duration("2024-01-01T10:00:00Z", "2024-01-01T10:05:00Z") == "5 minutes"
        assert _fmt_duration("2024-01-01T10:00:00Z", "2024-01-01T12:30:00Z") == "2 hours and 30 minutes"
        assert _fmt_duration("2024-01-01T10:00:00Z", "2024-01-01T13:00:00Z") == "3 hours"


# ---------------------------------------------------------------------------
# run_correlation (end-to-end)
# ---------------------------------------------------------------------------

class TestRunCorrelation:
    def test_empty(self):
        """G-1 witness (round 12): the empty path returns the
        CorrelationOutput dataclass — no positional arity left to drift."""
        out = run_correlation([])
        assert out.findings_text == "Confirmed threats: none"
        assert out.timeline_text == "No anomalies found."
        assert out.findings == []
        assert out.correlations == []
        assert out.attack_lookup == {}
        assert out.shown_findings == []

    def test_with_anomalies(self):
        anomalies = [
            {
                "type": "lolbin_abuse",
                "detection_method": "lolbin",
                "severity": "high",
                "user": "admin",
                "source_ip": "1.2.3.4",
                "log_type": "auth",
                "timestamp": "2024-01-01T10:00:00Z",
                "details": "LOLBIN C:\\Windows\\System32\\certutil.exe with command: -urlcache",
                "mitre_ids": ["T1218"],
            },
            {
                "type": "off_hours_activity",
                "detection_method": "off_hours",
                "severity": "medium",
                "user": "admin",
                "source_ip": "1.2.3.4",
                "log_type": "endpoint",
                "timestamp": "2024-01-01T23:00:00Z",
                "details": "Activity during off-hours",
            },
        ]
        out = run_correlation(anomalies)
        findings, timeline = out.findings_text, out.timeline_text
        assert "Confirmed threats:" in findings
        assert len(timeline) > 50  # Should produce a narrative

    def test_with_attack_mapping(self):
        anomalies = [
            {
                "type": "lolbin_abuse",
                "detection_method": "lolbin_abuse",
                "severity": "high",
                "user": "admin",
                "source_ip": "1.2.3.4",
                "log_type": "auth",
                "timestamp": "2024-01-01T10:00:00Z",
                "details": "",
            },
            {
                "type": "brute_force_attempt",
                "detection_method": "brute_force_attempt",
                "severity": "high",
                "user": "admin",
                "source_ip": "1.2.3.4",
                "log_type": "endpoint",
                "timestamp": "2024-01-01T10:05:00Z",
                "details": "",
            },
        ]
        attack_mapping = (
            "lolbin_abuse:\n"
            "  T1218 | System Binary Proxy Execution | defense-evasion\n"
            "brute_force_attempt:\n"
            "  T1110 | Brute Force | credential-access"
        )
        out = run_correlation(anomalies, attack_mapping_text=attack_mapping)
        findings, timeline = out.findings_text, out.timeline_text
        assert "T1218" in findings or "T1110" in findings

    def test_with_graph_context(self):
        anomalies = [
            {
                "type": "lolbin_abuse",
                "detection_method": "lolbin_abuse",
                "severity": "high",
                "user": "admin",
                "source_ip": "1.2.3.4",
                "log_type": "auth",
                "timestamp": "2024-01-01T10:00:00Z",
                "details": "",
            },
            {
                "type": "off_hours_activity",
                "detection_method": "off_hours_activity",
                "severity": "medium",
                "user": "admin",
                "source_ip": "1.2.3.4",
                "log_type": "endpoint",
                "timestamp": "2024-01-01T23:00:00Z",
                "details": "",
            },
        ]
        graph_data = {
            "communities": [{
                "id": 1,
                "anomaly_density": 0.6,
                "flagged": True,
                "types": ["ip", "process"],
                "members": ["1.2.3.4"],
                "neighbors": {"1.2.3.4": ["certutil.exe"]},
            }],
            "chains": [{
                "chain_id": 1,
                "phases": ["initial_access", "execution"],
                "score": 0.8,
                "phase_coverage": 0.5,
                "entities": {"ip": ["1.2.3.4"]},
            }],
        }
        graph_text = f"Context:\nJSON:{json.dumps(graph_data)}"
        out = run_correlation(anomalies, graph_context_text=graph_text)
        findings, timeline = out.findings_text, out.timeline_text
        # Should have graph community and/or temporal chain enrichment
        assert "Community" in findings or "Chain" in findings or "Confirmed threats" in findings


class TestExtractToolNames:
    """Tests for _extract_tool_names — pulling specific tool names from anomaly dicts."""

    def test_tool_display_name_preferred(self):
        """Uses tool_display_name (human-readable) over tool_name."""
        anomalies = [{
            "type": "known_attack_script",
            "detection_method": "attack_script",
            "details": "Known attack script: Cobalt Strike C2 framework (cobaltstrike)",
            "tool_name": "cobaltstrike",
            "tool_display_name": "Cobalt Strike",
        }]
        names = _extract_tool_names(anomalies)
        assert "Cobalt Strike" in names

    def test_falls_back_to_tool_name(self):
        """Falls back to tool_name when tool_display_name is missing."""
        anomalies = [{
            "type": "known_attack_script",
            "detection_method": "attack_script",
            "details": "Known attack script: Cobalt Strike C2 framework (cobaltstrike)",
            "tool_name": "cobaltstrike",
        }]
        names = _extract_tool_names(anomalies)
        assert "cobaltstrike" in names

    def test_falls_back_to_details_parsing(self):
        """Falls back to parsing details when both fields are missing."""
        anomalies = [{
            "type": "known_attack_script",
            "detection_method": "attack_script",
            "details": "Known attack script: Cobalt Strike C2 framework (cobaltstrike)",
        }]
        names = _extract_tool_names(anomalies)
        assert "cobaltstrike" in names

    def test_renamed_tool_name(self):
        """Extracts tool name from renamed_tool anomaly."""
        anomalies = [{
            "type": "renamed_attack_tool",
            "detection_method": "renamed_tool",
            "details": "Renamed attack tool: Rubeus kerberoast (process: rsynctool)",
            "tool_name": "Rubeus",
            "tool_display_name": "Rubeus",
        }]
        names = _extract_tool_names(anomalies)
        assert "Rubeus" in names

    def test_multiple_tools_deduped(self):
        """Multiple anomalies with same display name produce one entry."""
        anomalies = [
            {"type": "known_attack_script", "detection_method": "attack_script",
             "details": "...", "tool_name": "cobaltstrike",
             "tool_display_name": "Cobalt Strike"},
            {"type": "known_attack_script", "detection_method": "attack_script",
             "details": "...", "tool_name": "cobaltstrike",
             "tool_display_name": "Cobalt Strike"},
        ]
        names = _extract_tool_names(anomalies)
        assert len(names) == 1
        assert names[0] == "Cobalt Strike"

    def test_non_attack_anomalies_ignored(self):
        """Non-attack anomalies don't produce tool names."""
        anomalies = [{
            "type": "lolbin_abuse",
            "detection_method": "lolbin",
            "details": "Suspicious LOLBIN usage: powershell -enc",
        }]
        names = _extract_tool_names(anomalies)
        assert names == []

    def test_format_findings_includes_tools(self):
        """format_findings includes [Tools: ...] when tools_detected is present."""
        findings = [{
            "severity": "high",
            "type": "attack_script, integrity_anomaly",
            "entity": "Admin",
            "entity_type": "user",
            "cross_type": "single-type",
            "log_types": ["endpoint"],
            "confidence": 0.9,
            "mitre_attack": [],
            "tools_detected": ["Cobalt Strike", "Rubeus"],
        }]
        text = format_findings(findings)
        # RR-1 (round 10): tool names render as escaped JSON strings
        assert "[Tools: \"Cobalt Strike\", \"Rubeus\"]" in text
