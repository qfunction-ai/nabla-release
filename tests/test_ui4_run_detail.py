"""UI-4 backend: findings summary persistence + run detail endpoint."""

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from nabla.config import Settings


@pytest.fixture
def client(tmp_path):
    from nabla.server import app
    from nabla.rate_limit import reset_rate_limits

    settings = Settings(
        data_dir=str(tmp_path),
        letta_base_url="http://localhost:9999",
        embedding_endpoint="http://localhost:11434/v1",
        splunk_host="",
        sumologic_host="",
        splunk_validate_url=False,
        sumologic_validate_url=False,
    )
    reset_rate_limits()

    runs = [
        {"run_id": "abcdef12-rest", "started_at": "2026-09-02T10:00:00Z", "success": True,
         "anomaly_count": 5, "findings_count": 2, "step_durations": {"ingestion": 1.2, "anomaly": 0.8},
         "anomalies": [{"entity": "u1", "severity": "high", "detection_method": "brute_force_attempt",
                        "timestamp": "2026-09-02T10:01:00Z", "details": "", "categories": [], "mitre_attack": [], "entity_type": "user"}],
         "findings": [{"entity": "u1", "entity_type": "user", "type": "brute_force",
                       "severity": "high", "confidence": 0.8, "mitre_attack": ["T1110"]}],
         "supervisor_narrative": "Two confirmed threats."},
        {"run_id": "older-run", "started_at": "2026-09-01T10:00:00Z", "success": True,
         "anomaly_count": 0, "findings_count": 0},
    ]
    (tmp_path / "runs.json").write_text(json.dumps(runs))

    with patch("nabla.config.get_settings", return_value=settings), \
         patch("nabla.config._settings", settings):
        from nabla.auth import require_user
        app.dependency_overrides[require_user] = lambda: {"sub": "test", "role": "admin"}
        yield TestClient(app, raise_server_exceptions=False)

    app.dependency_overrides.clear()


class TestRunDetail:
    def test_full_run_detail(self, client):
        resp = client.get("/api/pipeline/runs/abcdef12")
        assert resp.status_code == 200
        body = resp.json()
        assert body["run_id"].startswith("abcdef12")
        assert len(body["findings"]) == 1
        assert body["findings"][0]["mitre_attack"] == ["T1110"]
        assert body["supervisor_narrative"] == "Two confirmed threats."
        assert len(body["anomalies"]) == 1
        assert body["step_durations"]["ingestion"] == 1.2

    def test_old_run_degrades_gracefully(self, client):
        resp = client.get("/api/pipeline/runs/older-run")
        assert resp.status_code == 200
        body = resp.json()
        assert body.get("anomalies") in (None, [])
        assert body.get("findings") in (None, [])
        # R-4: the response model normalizes old records — declared keys
        # are always present, null when the record predates them.
        assert body.get("supervisor_narrative") is None

    def test_unknown_run_404(self, client):
        assert client.get("/api/pipeline/runs/nope").status_code == 404


class TestFindingsSummary:
    def test_projection_and_cap(self):
        from nabla.pipeline.orchestration import FINDINGS_SUMMARY_CAP, _summarize_findings_for_run

        findings = [
            {"entity": f"e{i}", "entity_type": "user", "type": "t", "severity": "high",
             "confidence": 0.9, "mitre_attack": [{"id": f"T10{i}", "name": "x"}]}
            for i in range(FINDINGS_SUMMARY_CAP + 20)
        ]
        out = _summarize_findings_for_run(findings)
        assert len(out) == FINDINGS_SUMMARY_CAP
        assert out[0]["mitre_attack"] == ["T100"]
        assert _summarize_findings_for_run([]) == []
        assert _summarize_findings_for_run(None) == []


class TestPhase1RunContract:
    """Phase 1 (R-4/A3/A4/N7): the run endpoints return the declared
    Pydantic contract — degradations, raw_score vs threshold_in_effect,
    event_ids. The response_model IS the contract: this witnesses that
    the new fields survive the round trip and old records validate."""

    @pytest.fixture
    def client_p1(self, tmp_path):
        from nabla.server import app
        from nabla.rate_limit import reset_rate_limits

        settings = Settings(
            data_dir=str(tmp_path),
            letta_base_url="http://localhost:9999",
            embedding_endpoint="http://localhost:11434/v1",
            splunk_host="",
            sumologic_host="",
            splunk_validate_url=False,
            sumologic_validate_url=False,
        )
        reset_rate_limits()

        runs = [
            # Oldest-first (save_run appends; list_runs returns newest-first)
            # Pre-A22 run: no degradations/layer_counts keys at all
            {"run_id": "olderaaaa-rest", "started_at": "2026-08-01T10:00:00Z",
             "success": True, "anomaly_count": 1, "findings_count": 0},
            # Full-shape run: degradations + scored anomalies with event_ids
            {"run_id": "phase1001-rest", "started_at": "2026-11-20T05:00:00Z",
             "finished_at": "2026-11-20T05:01:00Z", "success": True,
             "anomaly_count": 2, "findings_count": 1,
             "step_durations": {"ingestion": 30.0, "anomaly": 5.0},
             "degradations": ["risk_scores"],
             "layer_counts": {"base": 2, "gcn_lof": 0, "provenance": 0,
                              "temporal": 0, "exfiltration": 0},
             "temporal_stats": {"chains": 1},
             "supervisor_narrative": "Narrative.",
             "anomalies": [
                 {"anomaly_id": "a1", "entity": "helpdeskone", "entity_type": "user",
                  "severity": "high", "timestamp": "2026-11-20T05:00:30Z",
                  "detection_method": "entity_z_score", "details": "z 2.02",
                  "categories": [], "mitre_attack": [],
                  "raw_score": 2.021, "event_ids": ["e1", "e2"],
                  "threshold_in_effect": 2.0},
             ],
             "findings": []},
        ]
        (tmp_path / "runs.json").write_text(json.dumps(runs))

        with patch("nabla.config.get_settings", return_value=settings), \
             patch("nabla.config._settings", settings):
            from nabla.auth import require_user
            app.dependency_overrides[require_user] = lambda: {"sub": "test", "role": "admin"}
            yield TestClient(app, raise_server_exceptions=False)
        app.dependency_overrides.clear()

    def test_degradations_survive_round_trip(self, client_p1):
        """A3: the degraded step is in the response — visible, not silent."""
        resp = client_p1.get("/api/pipeline/runs/phase1001")
        assert resp.status_code == 200
        assert resp.json()["degradations"] == ["risk_scores"]

    def test_score_columns_survive_round_trip(self, client_p1):
        """A4/N10: raw_score + threshold_in_effect on the anomaly."""
        a = resp_anomaly = client_p1.get("/api/pipeline/runs/phase1001").json()["anomalies"][0]
        assert a["raw_score"] == 2.021
        assert a["threshold_in_effect"] == 2.0
        assert a["event_ids"] == ["e1", "e2"]

    def test_layer_counts_and_stats(self, client_p1):
        body = client_p1.get("/api/pipeline/runs/phase1001").json()
        assert body["layer_counts"] == {"base": 2, "gcn_lof": 0, "provenance": 0,
                                        "temporal": 0, "exfiltration": 0}
        assert body["temporal_stats"] == {"chains": 1}

    def test_old_record_validates_with_defaults(self, client_p1):
        """Pre-A22 records must not 500 — defaults fill the missing fields."""
        body = client_p1.get("/api/pipeline/runs/olderaaaa").json()
        assert body["degradations"] == []
        assert body["anomalies"] == []
        assert body["layer_counts"] is None

    def test_no_duration_ms_lie(self, client_p1):
        """R-4: the hand-copied frontend interface declared duration_ms,
        which never existed on run records. The contract must not grow
        it back — duration is derived from started_at/finished_at."""
        body = client_p1.get("/api/pipeline/runs/phase1001").json()
        assert "duration_ms" not in body

    def test_history_response_contract(self, client_p1):
        body = client_p1.get("/api/pipeline/history?limit=10").json()
        assert set(body) == {"runs", "total", "limit", "offset"}
        assert body["total"] == 2
        assert body["runs"][0]["degradations"] == ["risk_scores"]


class TestCompactAnomalyPhase1:
    """The projection itself: event_ids capped, threshold via the shared
    calibration helper, raw_score passthrough."""

    def test_event_ids_capped_at_eight(self):
        from nabla.pipeline.orchestration import _compact_anomaly
        a = _compact_anomaly({
            "anomaly_id": "x", "entity": "u", "event_ids": [f"e{i}" for i in range(20)],
            "raw_score": 1.5,
        })
        assert a["event_ids"] == [f"e{i}" for i in range(8)]

    def test_missing_event_ids_empty_list(self):
        from nabla.pipeline.orchestration import _compact_anomaly
        a = _compact_anomaly({"anomaly_id": "x"})
        assert a["event_ids"] == []

    def test_threshold_in_effect_uses_shared_helper(self, tmp_path):
        from unittest.mock import patch
        settings = Settings(
            data_dir=str(tmp_path),
            letta_base_url="http://localhost:9999",
            embedding_endpoint="http://localhost:11434/v1",
            splunk_host="", sumologic_host="",
            splunk_validate_url=False, sumologic_validate_url=False,
        )
        from nabla.pipeline.orchestration import _compact_anomaly
        with patch("nabla.config.get_settings", return_value=settings), \
             patch("nabla.config._settings", settings):
            a = _compact_anomaly({"anomaly_id": "x", "detection_method": "entity_z_score"})
        # uncalibrated method -> the seeded default, via the shared helper
        assert a["threshold_in_effect"] is not None

    def test_not_calibratable_method_threshold_none(self):
        from nabla.pipeline.orchestration import _compact_anomaly
        a = _compact_anomaly({"anomaly_id": "x", "detection_method": "no_such_method"})
        assert a["threshold_in_effect"] is None
