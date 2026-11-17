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
        assert "anomalies" not in body or body.get("anomalies") in (None, [])
        assert "findings" not in body or body.get("findings") in (None, [])
        assert "supervisor_narrative" not in body

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
