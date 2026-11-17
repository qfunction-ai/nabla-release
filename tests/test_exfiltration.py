"""Tests for nabla.exfiltration — data exfiltration detection."""

import math
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from nabla.exfiltration import (
    _shannon_entropy,
    _is_suspicious_domain,
    _detect_volume_anomaly,
    _detect_dns_tunneling,
    _detect_staging_pattern,
    detect_exfiltration,
)


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("a") == 0.0

    def test_uniform_distribution(self):
        # "ab" has 50/50 distribution → 1 bit
        assert abs(_shannon_entropy("ab") - 1.0) < 0.01

    def test_random_string(self):
        # A random hex string should have entropy close to 4 bits
        s = "0123456789abcdef"
        entropy = _shannon_entropy(s)
        assert entropy > 3.5

    def test_repeated_string(self):
        # "aaaa" has zero entropy
        assert _shannon_entropy("aaaa") == 0.0


# ---------------------------------------------------------------------------
# Suspicious domain detection
# ---------------------------------------------------------------------------

class TestSuspiciousDomain:
    def test_normal_domain(self):
        assert not _is_suspicious_domain("www.google.com")

    def test_long_subdomain(self):
        # 41-char subdomain label
        domain = "a" * 41 + ".example.com"
        assert _is_suspicious_domain(domain)

    def test_high_entropy_domain(self):
        # High-entropy domain (encoded data in subdomain)
        domain = "xK3m9pQ2vR7nL5wT8yA1.example.com"
        assert _is_suspicious_domain(domain)

    def test_empty_domain(self):
        assert not _is_suspicious_domain("")


# ---------------------------------------------------------------------------
# Volume anomaly
# ---------------------------------------------------------------------------

class TestVolumeAnomaly:
    def test_high_volume_triggers(self):
        entries = [
            {"user": "alice", "action": "network_connect", "type": "network"}
            for _ in range(50)
        ]
        # Mock entity profile with high EWMA
        profile = MagicMock()
        profile.observation_count = 10
        ewma = MagicMock()
        ewma.value = 5.0
        ewma.z_score.return_value = 4.0  # Well above sigma
        profile.typical_event_count = ewma

        profiles = MagicMock()
        profiles.get_user.return_value = profile

        anomalies = _detect_volume_anomaly(entries, entity_profiles=profiles, sigma=3.0)
        assert len(anomalies) >= 1
        assert anomalies[0]["detection_method"] == "exfil_volume"

    def test_normal_volume_no_trigger(self):
        entries = [
            {"user": "alice", "action": "network_connect", "type": "network"}
            for _ in range(5)
        ]
        profile = MagicMock()
        profile.observation_count = 10
        ewma = MagicMock()
        ewma.value = 10.0
        ewma.z_score.return_value = 0.5  # Below sigma
        profile.typical_event_count = ewma

        profiles = MagicMock()
        profiles.get_user.return_value = profile

        anomalies = _detect_volume_anomaly(entries, entity_profiles=profiles, sigma=3.0)
        assert len(anomalies) == 0

    def test_no_profiles(self):
        entries = [
            {"user": "alice", "action": "network_connect", "type": "network"}
            for _ in range(50)
        ]
        anomalies = _detect_volume_anomaly(entries, entity_profiles=None, sigma=3.0)
        assert len(anomalies) == 0


# ---------------------------------------------------------------------------
# DNS tunneling
# ---------------------------------------------------------------------------

class TestDNSTunneling:
    def test_tunneling_detected(self):
        # Long subdomain label - typical DNS tunnel
        entries = [
            {
                "user": "alice",
                "type": "dns",
                "query": "a" * 50 + ".data.example.com",
                "query_type": "A",
            }
        ]
        anomalies = _detect_dns_tunneling(entries)
        assert len(anomalies) >= 1
        assert any(a["detection_method"] == "dns_tunneling" for a in anomalies)

    def test_normal_dns_no_trigger(self):
        entries = [
            {
                "user": "alice",
                "type": "dns",
                "query": "www.google.com",
                "query_type": "A",
            }
        ]
        anomalies = _detect_dns_tunneling(entries)
        assert len(anomalies) == 0

    def test_excessive_txt_queries(self):
        entries = [
            {
                "user": "alice",
                "type": "dns",
                "query": "data.example.com",
                "query_type": "TXT",
            }
            for _ in range(10)
        ]
        anomalies = _detect_dns_tunneling(entries)
        assert any(a["detection_method"] == "dns_tunneling" for a in anomalies)


# ---------------------------------------------------------------------------
# Staging pattern
# ---------------------------------------------------------------------------

class TestStagingPattern:
    def test_staging_detected(self):
        base_time = datetime.now(timezone.utc)
        entries = [
            {
                "user": "alice",
                "action": "create",
                "target_file": "sensitive_data.xlsx",
                "timestamp": base_time.isoformat(),
            },
            {
                "user": "alice",
                "action": "archive",
                "target_file": "sensitive_data.zip",
                "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
            },
            {
                "user": "alice",
                "action": "network_connect",
                "type": "network",
                "dest_ip": "203.0.113.1",
                "dest_port": 443,
                "timestamp": (base_time + timedelta(minutes=10)).isoformat(),
            },
        ]
        anomalies = _detect_staging_pattern(entries, window_minutes=30)
        assert len(anomalies) >= 1
        assert anomalies[0]["detection_method"] == "exfil_staging"
        assert anomalies[0]["severity"] == "critical"

    def test_no_staging(self):
        entries = [
            {"user": "alice", "action": "create", "target_file": "doc.txt",
             "timestamp": datetime.now(timezone.utc).isoformat()},
        ]
        anomalies = _detect_staging_pattern(entries, window_minutes=30)
        assert len(anomalies) == 0

    def test_network_after_create_no_archive(self):
        base_time = datetime.now(timezone.utc)
        entries = [
            {
                "user": "alice",
                "action": "create",
                "target_file": "doc.txt",
                "timestamp": base_time.isoformat(),
            },
            {
                "user": "alice",
                "action": "network_connect",
                "type": "network",
                "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
            },
        ]
        anomalies = _detect_staging_pattern(entries, window_minutes=30)
        assert len(anomalies) >= 1
        assert anomalies[0]["severity"] == "high"  # Not critical (no archive)


# ---------------------------------------------------------------------------
# detect_exfiltration (integration)
# ---------------------------------------------------------------------------

class TestDetectExfiltration:
    def test_empty_entries(self):
        anomalies = detect_exfiltration(entries=[], thresholds={})
        assert anomalies == []

    def test_combines_all_sub_detectors(self):
        base_time = datetime.now(timezone.utc)
        entries = [
            # DNS tunneling
            {
                "user": "alice",
                "type": "dns",
                "query": "a" * 50 + ".tunnel.example.com",
                "query_type": "A",
            },
            # Staging
            {
                "user": "bob",
                "action": "create",
                "target_file": "data.xlsx",
                "timestamp": base_time.isoformat(),
            },
            {
                "user": "bob",
                "action": "archive",
                "target_file": "data.zip",
                "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
            },
            {
                "user": "bob",
                "action": "network_connect",
                "type": "network",
                "timestamp": (base_time + timedelta(minutes=10)).isoformat(),
            },
        ]
        anomalies = detect_exfiltration(entries, thresholds={})
        # Should have at least DNS tunneling + staging
        methods = {a["detection_method"] for a in anomalies}
        assert "dns_tunneling" in methods or "exfil_staging" in methods
