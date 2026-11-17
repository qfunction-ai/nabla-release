"""UI-3 backend: incident list filters (entity, run_id)."""

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

    incidents = [
        {"incident_id": "inc-1", "entity": "regsvr32", "entity_type": "process",
         "finding_type": "lolbin_abuse", "severity": "critical", "status": "new",
         "run_id": "run-a", "updated_at": "2026-09-02T10:00:00Z"},
        {"incident_id": "inc-2", "entity": "deploy_bot", "entity_type": "user",
         "finding_type": "brute_force", "severity": "high", "status": "investigating",
         "run_id": "run-a", "updated_at": "2026-09-02T11:00:00Z"},
        {"incident_id": "inc-3", "entity": "deploy_bot", "entity_type": "user",
         "finding_type": "exfiltration", "severity": "medium", "status": "new",
         "run_id": "run-b", "updated_at": "2026-09-02T12:00:00Z"},
    ]
    (tmp_path / "incidents.json").write_text(json.dumps(incidents))

    with patch("nabla.config.get_settings", return_value=settings), \
         patch("nabla.config._settings", settings):
        from nabla.auth import require_user
        app.dependency_overrides[require_user] = lambda: {"sub": "test", "role": "admin"}
        yield TestClient(app, raise_server_exceptions=False)

    app.dependency_overrides.clear()


class TestIncidentFilters:
    def test_entity_filter(self, client):
        resp = client.get("/api/incidents?entity=deploy_bot")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert all(i["entity"] == "deploy_bot" for i in body["incidents"])

    def test_entity_filter_process_typed(self, client):
        resp = client.get("/api/incidents?entity=regsvr32")
        body = resp.json()
        assert body["total"] == 1
        assert body["incidents"][0]["entity_type"] == "process"

    def test_run_id_filter(self, client):
        resp = client.get("/api/incidents?run_id=run-a")
        body = resp.json()
        assert body["total"] == 2
        assert all(i["run_id"] == "run-a" for i in body["incidents"])

    def test_combined_filters(self, client):
        resp = client.get("/api/incidents?entity=deploy_bot&run_id=run-b")
        body = resp.json()
        assert body["total"] == 1
        assert body["incidents"][0]["incident_id"] == "inc-3"

    def test_no_filter_returns_all(self, client):
        resp = client.get("/api/incidents")
        assert resp.json()["total"] == 3
