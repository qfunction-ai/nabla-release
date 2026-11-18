"""Tests for incident persistence module."""

import json
import os
import tempfile

import pytest

from nabla.incidents import (
    get_incident,
    incident_stats,
    list_incidents,
    save_incidents,
    update_incident,
    VALID_STATUSES,
    VALID_SEVERITIES,
)


def _reload_incidents(monkeypatch, data_dir):
    """Reload incidents module with a fresh data directory."""
    import importlib
    import nabla.config
    import nabla.incidents

    # Reset cached settings
    nabla.config._settings = None
    monkeypatch.setenv("NABLA_DATA_DIR", str(data_dir))
    importlib.reload(nabla.config)
    importlib.reload(nabla.incidents)


@pytest.fixture
def mock_settings(tmp_path, monkeypatch):
    """Mock settings to use temporary data directory."""
    _reload_incidents(monkeypatch, tmp_path)
    return tmp_path


def _sample_findings():
    """Return sample findings for testing."""
    return [
        {
            "severity": "critical",
            "type": "lolbin_abuse, attack_script",
            "entity": "admin_user",
            "entity_type": "user",
            "cross_type": "single-type",
            "log_types": ["auth"],
            "confidence": 0.9,
            "mitre_attack": [
                {"id": "T1218", "name": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
            ],
            "tools_detected": ["Cobalt Strike"],
        },
        {
            "severity": "high",
            "type": "multiple_source_ips, off_hours",
            "entity": "10.0.1.55",
            "entity_type": "ip",
            "cross_type": "cross-type",
            "log_types": ["auth", "endpoint"],
            "confidence": 0.7,
            "mitre_attack": [
                {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
            ],
        },
    ]


class TestSaveIncidents:
    """Tests for save_incidents."""

    def test_creates_incidents_from_findings(self, mock_settings, monkeypatch):
        """save_incidents should create one incident per finding."""
        import nabla.incidents as inc_mod
        findings = _sample_findings()
        count = inc_mod.save_incidents("run-001", findings, supervisor_text="Review text")
        assert count == 2

        incidents = inc_mod.list_incidents(limit=100)
        assert len(incidents) == 2

    def test_incident_fields_populated(self, mock_settings, monkeypatch):
        """Created incidents should have all expected fields."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings(), supervisor_text="Review text")
        incidents = inc_mod.list_incidents(limit=100)
        inc = incidents[0]  # newest first

        assert inc["incident_id"]
        assert inc["run_id"] == "run-001"
        assert inc["created_at"]
        assert inc["updated_at"]
        assert inc["status"] == "new"
        assert inc["severity"] in VALID_SEVERITIES
        assert inc["entity"]
        assert inc["entity_type"]
        assert inc["finding_type"]
        assert inc["confidence"] >= 0
        assert inc["supervisor_review"] == "Review text"
        assert inc["operator_notes"] == ""

    def test_deduplication_active_status(self, mock_settings, monkeypatch):
        """Same entity+type with active status should not create duplicate."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings())
        count = inc_mod.save_incidents("run-002", _sample_findings())
        assert count == 0  # all deduped

        incidents = inc_mod.list_incidents(limit=100)
        assert len(incidents) == 2  # no new ones created

    def test_deduplication_updates_existing(self, mock_settings, monkeypatch):
        """Deduplication should update updated_at and merge MITRE techniques."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings())
        first_updated = inc_mod.list_incidents(limit=100)[0]["updated_at"]

        # Re-save with same findings but additional MITRE technique
        findings = _sample_findings()
        findings[0]["mitre_attack"].append(
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}
        )
        inc_mod.save_incidents("run-002", findings)

        incidents = inc_mod.list_incidents(limit=100)
        inc = [i for i in incidents if i["entity"] == "admin_user"][0]
        assert inc["updated_at"] >= first_updated
        assert len(inc["mitre_attack"]) == 2  # merged

    def test_deduplication_resolved_allows_new(self, mock_settings, monkeypatch):
        """Same entity+type with resolved status should create new incident."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings())

        # Resolve the first incident
        incidents = inc_mod.list_incidents(limit=100)
        for inc in incidents:
            inc_mod.update_incident(inc["incident_id"], status="resolved")

        # Re-save — should create new incidents since old ones are resolved
        count = inc_mod.save_incidents("run-002", _sample_findings())
        assert count == 2

        total = inc_mod.list_incidents(limit=100)
        assert len(total) == 4  # 2 resolved + 2 new

    def test_deduplication_false_positive_allows_new(self, mock_settings, monkeypatch):
        """Same entity+type with false_positive status should create new incident."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings()[:1])

        # Mark as false positive
        inc = inc_mod.list_incidents(limit=100)[0]
        inc_mod.update_incident(inc["incident_id"], status="false_positive")

        # Re-save — should create new since old is false_positive
        count = inc_mod.save_incidents("run-002", _sample_findings()[:1])
        assert count == 1

    def test_severity_escalation_on_dedup(self, mock_settings, monkeypatch):
        """Dedup should escalate severity if new finding is higher."""
        import nabla.incidents as inc_mod
        findings = [{"severity": "medium", "type": "lolbin_abuse",
                     "entity": "user1", "entity_type": "user",
                     "cross_type": "single-type", "log_types": ["auth"],
                     "confidence": 0.6, "mitre_attack": []}]
        inc_mod.save_incidents("run-001", findings)

        # Same finding but critical
        findings[0]["severity"] = "critical"
        inc_mod.save_incidents("run-002", findings)

        inc = inc_mod.list_incidents(limit=100)[0]
        assert inc["severity"] == "critical"

    def test_confidence_update_on_dedup(self, mock_settings, monkeypatch):
        """Dedup should update confidence if new finding is higher."""
        import nabla.incidents as inc_mod
        findings = [{"severity": "high", "type": "lolbin_abuse",
                     "entity": "user1", "entity_type": "user",
                     "cross_type": "single-type", "log_types": ["auth"],
                     "confidence": 0.5, "mitre_attack": []}]
        inc_mod.save_incidents("run-001", findings)

        # Same finding but higher confidence
        findings[0]["confidence"] = 0.9
        inc_mod.save_incidents("run-002", findings)

        inc = inc_mod.list_incidents(limit=100)[0]
        assert inc["confidence"] == 0.9

    def test_empty_findings(self, mock_settings, monkeypatch):
        """save_incidents with empty findings should not create incidents."""
        import nabla.incidents as inc_mod
        count = inc_mod.save_incidents("run-001", [])
        assert count == 0

    def test_evidence_extraction(self, mock_settings, monkeypatch):
        """Evidence text should be extracted per-entity and attached to incidents."""
        import nabla.incidents as inc_mod
        evidence_text = """
--- EVIDENCE ---

  [user] admin_user:
    lolbin_abuse: threshold=0.7, actual=0.95, margin=+0.25
    Counterfactuals:
    if lolbin_abuse were a false positive → severity drops from CRITICAL to HIGH

  [ip] 10.0.1.55:
    multiple_source_ips: threshold=3, actual=5, margin=+2
"""
        findings = _sample_findings()
        inc_mod.save_incidents("run-001", findings, evidence_text=evidence_text)

        incidents = inc_mod.list_incidents(limit=100)
        admin_inc = [i for i in incidents if i["entity"] == "admin_user"][0]
        ip_inc = [i for i in incidents if i["entity"] == "10.0.1.55"][0]

        assert "lolbin_abuse" in admin_inc["evidence"]
        assert "multiple_source_ips" in ip_inc["evidence"]
        # Each incident should only have its own entity's evidence
        assert "multiple_source_ips" not in admin_inc["evidence"]
        assert "lolbin_abuse" not in ip_inc["evidence"]


class TestListIncidents:
    """Tests for list_incidents."""

    def test_filter_by_status(self, mock_settings, monkeypatch):
        """list_incidents should filter by status."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings())
        inc = inc_mod.list_incidents(limit=100)[0]
        inc_mod.update_incident(inc["incident_id"], status="resolved")

        new_incidents = inc_mod.list_incidents(status="new")
        resolved_incidents = inc_mod.list_incidents(status="resolved")

        assert len(new_incidents) == 1
        assert len(resolved_incidents) == 1

    def test_filter_by_severity(self, mock_settings, monkeypatch):
        """list_incidents should filter by severity."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings())

        critical = inc_mod.list_incidents(severity="critical")
        high = inc_mod.list_incidents(severity="high")

        assert len(critical) == 1
        assert len(high) == 1

    def test_newest_first(self, mock_settings, monkeypatch):
        """list_incidents should return newest incidents first."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings()[:1])
        inc_mod.save_incidents("run-002", [_sample_findings()[1]])

        incidents = inc_mod.list_incidents(limit=100)
        assert len(incidents) == 2
        # Second finding was saved later, should be first in list
        assert incidents[0]["entity"] == "10.0.1.55"

    def test_limit(self, mock_settings, monkeypatch):
        """list_incidents should respect the limit parameter."""
        import nabla.incidents as inc_mod
        for i in range(5):
            inc_mod.save_incidents(f"run-{i}", [{
                "severity": "medium", "type": f"test_type_{i}",
                "entity": f"entity_{i}", "entity_type": "user",
                "cross_type": "single-type", "log_types": ["auth"],
                "confidence": 0.5, "mitre_attack": [],
            }])

        incidents = inc_mod.list_incidents(limit=3)
        assert len(incidents) == 3


class TestGetIncident:
    """Tests for get_incident."""

    def test_found(self, mock_settings, monkeypatch):
        """get_incident should return the incident by ID."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings())
        inc = inc_mod.list_incidents(limit=100)[0]
        result = inc_mod.get_incident(inc["incident_id"])
        assert result is not None
        assert result["incident_id"] == inc["incident_id"]

    def test_not_found(self, mock_settings, monkeypatch):
        """get_incident should return None for unknown ID."""
        import nabla.incidents as inc_mod
        result = inc_mod.get_incident("nonexistent-id")
        assert result is None


class TestUpdateIncident:
    """Tests for update_incident."""

    def test_update_status(self, mock_settings, monkeypatch):
        """update_incident should change the status."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings())
        inc = inc_mod.list_incidents(limit=100)[0]

        result = inc_mod.update_incident(inc["incident_id"], status="investigating")
        assert result["status"] == "investigating"

    def test_update_notes(self, mock_settings, monkeypatch):
        """update_incident should append notes."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings())
        inc = inc_mod.list_incidents(limit=100)[0]

        inc_mod.update_incident(inc["incident_id"], notes="Looking into this")
        inc_mod.update_incident(inc["incident_id"], notes="Confirmed false positive")

        result = inc_mod.get_incident(inc["incident_id"])
        assert "Looking into this" in result["operator_notes"]
        assert "Confirmed false positive" in result["operator_notes"]

    def test_update_status_and_notes(self, mock_settings, monkeypatch):
        """update_incident should handle both status and notes."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings())
        inc = inc_mod.list_incidents(limit=100)[0]

        result = inc_mod.update_incident(inc["incident_id"], status="resolved", notes="Fixed")
        assert result["status"] == "resolved"
        assert "Fixed" in result["operator_notes"]

    def test_invalid_status(self, mock_settings, monkeypatch):
        """update_incident should reject invalid status."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings())
        inc = inc_mod.list_incidents(limit=100)[0]

        with pytest.raises(ValueError, match="Invalid status"):
            inc_mod.update_incident(inc["incident_id"], status="invalid_status")

    def test_not_found(self, mock_settings, monkeypatch):
        """update_incident should return None for unknown ID."""
        import nabla.incidents as inc_mod
        result = inc_mod.update_incident("nonexistent-id", status="resolved")
        assert result is None

    def test_updated_at_changes(self, mock_settings, monkeypatch):
        """update_incident should update the updated_at timestamp."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings())
        inc = inc_mod.list_incidents(limit=100)[0]
        original_updated = inc["updated_at"]

        result = inc_mod.update_incident(inc["incident_id"], status="investigating")
        assert result["updated_at"] >= original_updated


class TestIncidentStats:
    """Tests for incident_stats."""

    def test_empty(self, mock_settings, monkeypatch):
        """incident_stats should return zeros when no incidents exist."""
        import nabla.incidents as inc_mod
        stats = inc_mod.incident_stats()
        assert stats["total"] == 0

    def test_counts(self, mock_settings, monkeypatch):
        """incident_stats should count by status and severity."""
        import nabla.incidents as inc_mod
        inc_mod.save_incidents("run-001", _sample_findings())
        # Mark one as resolved
        incidents = inc_mod.list_incidents(limit=100)
        inc_mod.update_incident(incidents[0]["incident_id"], status="resolved")

        stats = inc_mod.incident_stats()
        assert stats["total"] == 2
        assert stats["by_status"]["resolved"] == 1
        assert stats["by_status"]["new"] == 1
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["high"] == 1


class TestCorruptedFile:
    """Tests for corrupted/missing file handling."""

    def test_corrupted_json(self, mock_settings, monkeypatch):
        """Corrupted incidents.json should be handled gracefully."""
        import nabla.incidents as inc_mod
        from nabla.config import get_settings
        path = get_settings().incidents_file
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write("{invalid json")

        incidents = inc_mod.list_incidents()
        assert incidents == []

    def test_missing_file(self, mock_settings, monkeypatch):
        """Missing incidents.json should return empty list."""
        import nabla.incidents as inc_mod
        incidents = inc_mod.list_incidents()
        assert incidents == []


class TestF9ContributingAnomalyIds:
    """F9 (round-3 closeout): the finding dict carries its methods under
    "type" — _finding_methods read a nonexistent "finding_type" key, so
    contributing_anomaly_ids was [] on EVERY incident and no organic
    disposition ever wrote a label. These tests go through the real
    save_incidents against a persisted run record — the hand-crafted
    fixtures that asserted pre-populated ids masked the bug."""

    def _write_run(self, mock_settings, anomalies, run_id="run-f9"):
        import nabla.history as hist
        from nabla.config import get_settings
        settings = get_settings()
        runs_path = settings.runs_file
        os.makedirs(os.path.dirname(runs_path), exist_ok=True)
        with open(runs_path, "w") as f:
            json.dump([{"run_id": run_id, "anomalies": anomalies}], f)

    def test_ids_populated_through_real_save(self, mock_settings, monkeypatch):
        """A finding of type X,Y must link the run's X and Y anomalies."""
        import nabla.incidents as inc_mod
        anomalies = [
            {"anomaly_id": "aaa-f9-1", "entity": "alice", "entity_type": "user",
             "severity": "high", "timestamp": "", "detection_method": "failed_login_ratio",
             "details": "", "categories": [], "mitre_attack": [], "raw_score": 0.6},
            {"anomaly_id": "aaa-f9-2", "entity": "alice", "entity_type": "user",
             "severity": "medium", "timestamp": "", "detection_method": "entity_off_hours",
             "details": "", "categories": [], "mitre_attack": [], "raw_score": None},
            # Different entity: must NOT be linked
            {"anomaly_id": "aaa-f9-3", "entity": "bob", "entity_type": "user",
             "severity": "high", "timestamp": "", "detection_method": "failed_login_ratio",
             "details": "", "categories": [], "mitre_attack": [], "raw_score": 0.7},
        ]
        self._write_run(mock_settings, anomalies)

        finding = {
            "severity": "high", "type": "entity_off_hours, failed_login_ratio",
            "entity": "alice", "entity_type": "user", "cross_type": "single-type",
            "log_types": ["auth"], "confidence": 0.7, "mitre_attack": [],
        }
        count = inc_mod.save_incidents("run-f9", [finding], supervisor_text="s")
        assert count == 1

        inc = inc_mod.list_incidents(limit=10)[0]
        assert sorted(inc["contributing_anomaly_ids"]) == ["aaa-f9-1", "aaa-f9-2"], (
            f"ids must be exactly alice's two methods, got {inc['contributing_anomaly_ids']}")

    def test_disposition_writes_labels_from_real_ids(self, mock_settings, monkeypatch):
        """End-to-end: the linked ids drive real label records (the demo path)."""
        import nabla.incidents as inc_mod
        from nabla.rl.calibration import current_labels
        anomalies = [
            {"anomaly_id": "lbl-f9-1", "entity": "alice", "entity_type": "user",
             "severity": "high", "timestamp": "", "detection_method": "entity_z_score",
             "details": "", "categories": [], "mitre_attack": [], "raw_score": 2.4},
        ]
        self._write_run(mock_settings, anomalies)

        finding = {
            "severity": "high", "type": "entity_z_score",
            "entity": "alice", "entity_type": "user", "cross_type": "single-type",
            "log_types": ["auth"], "confidence": 0.7, "mitre_attack": [],
        }
        inc_mod.save_incidents("run-f9", [finding], supervisor_text="s")
        inc = inc_mod.list_incidents(limit=10)[0]
        assert inc["contributing_anomaly_ids"] == ["lbl-f9-1"]

        updated = inc_mod.update_incident(inc["incident_id"], disposition="false_positive")
        assert updated["disposition"] == "false_positive"

        labels = current_labels()
        assert len(labels) == 1, (
            f"an organic disposition must write exactly one label, got {len(labels)}")
        assert labels[0]["anomaly_id"] == "lbl-f9-1"
        assert labels[0]["detection_method"] == "entity_z_score"
        assert labels[0]["raw_score"] == 2.4
