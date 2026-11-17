"""Tests for UI-2 backend: anomaly persistence, history trim, attribution, entity context."""

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from nabla.config import Settings


def _settings(tmp_path, dev_mode=False):
    return Settings(
        data_dir=str(tmp_path),
        letta_base_url="http://localhost:9999",
        dev_mode=dev_mode,
        embedding_endpoint="http://localhost:11434/v1",
        splunk_host="",
        sumologic_host="",
        splunk_validate_url=False,
        sumologic_validate_url=False,
    )


# ---------------------------------------------------------------------------
# History trim
# ---------------------------------------------------------------------------

class TestHistoryTrim:
    def test_save_run_trims_to_cap(self, tmp_path):
        from nabla.history import MAX_RUNS, save_run

        settings = _settings(tmp_path)
        with patch("nabla.config.get_settings", return_value=settings), \
             patch("nabla.config._settings", settings):
            for i in range(MAX_RUNS + 10):
                save_run({"run_id": f"run-{i}", "anomalies": []})

            import nabla.history as h
            runs = h._load_runs(settings.runs_file)
            assert len(runs) == MAX_RUNS
            # Oldest dropped, newest kept
            assert runs[0]["run_id"] == "run-10"
            assert runs[-1]["run_id"] == f"run-{MAX_RUNS + 9}"

    def test_trim_test_smaller_cap(self, tmp_path, monkeypatch):
        import nabla.history as h
        from nabla.history import save_run

        monkeypatch.setattr(h, "MAX_RUNS", 3)
        settings = _settings(tmp_path)
        with patch("nabla.config.get_settings", return_value=settings), \
             patch("nabla.config._settings", settings):
            for i in range(6):
                save_run({"run_id": f"r{i}"})
            runs = h._load_runs(settings.runs_file)
            assert [r["run_id"] for r in runs] == ["r3", "r4", "r5"]


# ---------------------------------------------------------------------------
# Anomaly summary projection
# ---------------------------------------------------------------------------

class TestAnomalySummary:
    def test_compact_projection(self):
        from nabla.pipeline.orchestration import _compact_anomaly

        a = {
            "user": "alice", "entity_type": "user", "severity": "high",
            "timestamp": "2026-09-02T10:00:00Z", "type": "brute_force_attempt",
            "details": "failure ratio 0.9", "categories": ["credential_access"],
            "mitre_attack": [{"id": "T1110", "name": "Brute Force"}],
            "extra_ignored": "noise",
        }
        c = _compact_anomaly(a)
        assert c["entity"] == "alice"
        assert c["detection_method"] == "brute_force_attempt"
        assert c["severity"] == "high"
        assert "extra_ignored" not in c

    def test_summary_caps_and_prioritizes_severity(self):
        from nabla.pipeline.orchestration import ANOMALY_SUMMARY_CAP, _summarize_anomalies_for_run

        class FakeDetection:
            anomalies = [{"severity": "medium", "user": "u"} for _ in range(ANOMALY_SUMMARY_CAP + 10)]
            anomalies[5]["severity"] = "critical"
            gcn_lof_anomalies = []
            provenance_anomalies = []
            temporal_anomalies = []

        out = _summarize_anomalies_for_run(FakeDetection, ANOMALY_SUMMARY_CAP + 10)
        assert len(out) == ANOMALY_SUMMARY_CAP
        # The critical one survived the cap
        assert any(a["severity"] == "critical" for a in out)

    def test_summary_empty_when_no_anomalies(self):
        from nabla.pipeline.orchestration import _summarize_anomalies_for_run

        class FakeDetection:
            anomalies = []
            gcn_lof_anomalies = []
            provenance_anomalies = []
            temporal_anomalies = []

        assert _summarize_anomalies_for_run(FakeDetection, 0) == []


# ---------------------------------------------------------------------------
# Attribution + context endpoints
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    from nabla.server import app
    from nabla.rate_limit import reset_rate_limits

    settings = _settings(tmp_path)
    reset_rate_limits()

    # Seed: two runs with anomalies for alice + bob, one incident for alice
    runs = [
        {"run_id": "r1", "started_at": "2026-09-02T10:00:00Z", "anomalies": [
            {"entity": "alice", "severity": "high", "detection_method": "brute_force_attempt",
             "timestamp": "2026-09-02T10:01:00Z", "details": "ratio 0.9", "categories": [], "mitre_attack": []},
            {"entity": "bob", "severity": "low", "detection_method": "off_hours",
             "timestamp": "2026-09-02T10:02:00Z", "details": "", "categories": [], "mitre_attack": []},
        ]},
        {"run_id": "r2", "started_at": "2026-09-01T10:00:00Z", "anomalies": [
            {"entity": "alice", "severity": "medium", "detection_method": "z_score_spike",
             "timestamp": "2026-09-01T10:01:00Z", "details": "z=2.5", "categories": [], "mitre_attack": []},
        ]},
    ]
    (tmp_path / "runs.json").write_text(json.dumps(runs))
    (tmp_path / "incidents.json").write_text(json.dumps([
        {"incident_id": "inc-1", "entity": "alice", "finding_type": "brute_force",
         "severity": "high", "status": "new", "updated_at": "2026-09-02T10:05:00Z"},
    ]))

    with patch("nabla.config.get_settings", return_value=settings), \
         patch("nabla.config._settings", settings):
        from nabla.auth import require_user
        app.dependency_overrides[require_user] = lambda: {"sub": "test", "role": "admin"}
        yield TestClient(app, raise_server_exceptions=False)

    app.dependency_overrides.clear()


class TestAttributionEndpoint:
    def test_assembles_anomalies_incidents_risk(self, client, tmp_path):
        # Seed a risk score for alice
        from nabla.risk import EntityRiskStore
        from nabla.config import get_settings
        settings = get_settings()
        store = EntityRiskStore(settings.entity_risk_scores_file)
        rs = store.scores.get("alice")
        # Use the store API to write
        from nabla.risk import EntityRiskScore
        score = EntityRiskScore(entity_id="alice", entity_type="user")
        score.overall = 42.0
        score.categories["credential_access"] = 30.0
        store.scores["alice"] = score
        store.save()

        resp = client.get("/api/entities/alice/attribution")
        assert resp.status_code == 200
        body = resp.json()
        assert body["entity_id"] == "alice"
        # 2 anomalies for alice across runs, newest first
        assert len(body["anomalies"]) == 2
        assert body["anomalies"][0]["detection_method"] == "brute_force_attempt"
        assert body["anomalies"][0]["run_id"] == "r1"
        # Incident present
        assert len(body["incidents"]) == 1
        assert body["incidents"][0]["incident_id"] == "inc-1"
        # Risk breakdown
        assert body["risk"]["overall"] == 42.0
        assert body["risk"]["categories"]["credential_access"] == 30.0
        assert body["runs_scanned"] == 2

    def test_unknown_entity_returns_empty_not_error(self, client):
        resp = client.get("/api/entities/ghost/attribution")
        assert resp.status_code == 200
        body = resp.json()
        assert body["anomalies"] == []
        assert body["incidents"] == []
        assert body["risk"] is None


class TestEntityContextEndpoint:
    def test_put_replaces_facts(self, client, tmp_path):
        resp = client.put("/api/entities/deploy_bot/context", json={"facts": ["Runs CI deploys", "Touches build servers"]})
        assert resp.status_code == 200
        assert resp.json()["facts"] == ["Runs CI deploys", "Touches build servers"]

        # Round-trip: the environment document contains it
        doc = json.loads((tmp_path / "env_context.json").read_text()) if (tmp_path / "env_context.json").exists() else \
              json.loads((tmp_path / "environment_context.json").read_text())
        assert doc["entities"]["deploy_bot"] == ["Runs CI deploys", "Touches build servers"]

    def test_empty_facts_removes_entity(self, client, tmp_path):
        client.put("/api/entities/deploy_bot/context", json={"facts": ["x"]})
        resp = client.put("/api/entities/deploy_bot/context", json={"facts": []})
        assert resp.status_code == 200
        assert resp.json()["facts"] == []

    def test_validation_rejects_non_list(self, client):
        assert client.put("/api/entities/x/context", json={"facts": "not-a-list"}).status_code == 400
        assert client.put("/api/entities/x/context", json={"facts": ["", "  "]}).status_code == 400
        assert client.put("/api/entities/x/context", json={}).status_code == 400
