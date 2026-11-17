"""Shared fixtures for tests.

Integration tests require a running Letta server.
Set NABLA_INTEGRATION=1 to enable them.

API route tests use FastAPI TestClient with mocked dependencies.
"""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Integration test markers
# ---------------------------------------------------------------------------

def pytest_configure(config):
    """Register the 'integration' marker."""
    config.addinivalue_line("markers", "integration: requires running Letta server (NABLA_INTEGRATION=1)")


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless NABLA_INTEGRATION=1 is set."""
    if os.environ.get("NABLA_INTEGRATION") != "1":
        skip = pytest.mark.skip(reason="NABLA_INTEGRATION=1 not set")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip)


# ---------------------------------------------------------------------------
# Integration test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def letta_client():
    """Create a real Letta client for integration tests."""
    from nabla.client import get_client, reset_client
    reset_client()
    client = get_client()
    yield client
    reset_client()


@pytest.fixture
def bootstrap_system(letta_client):
    """Bootstrap the Nabla system, yield agent IDs, then tear down.

    Guarantees cleanup even if tests fail.
    """
    from nabla.agents.bootstrap import bootstrap, teardown

    agents = bootstrap(letta_client)
    yield agents

    teardown(letta_client)


# ---------------------------------------------------------------------------
# API route test fixtures
# ---------------------------------------------------------------------------

def _write_minimal_state(temp_data_dir: str) -> None:
    """Write minimal JSON state files so API endpoints don't crash."""
    defaults = {
        "system_state.json": {"phase": "baseline", "first_ingestion_at": None, "detection_since": None},
        "entity_profiles.json": {"users": {}, "hosts": {}, "ips": {}},
        "rl_state.json": {"thresholds": {}, "bandit": {}},
        "incidents.json": [],
        "runs.json": [],
        "watchlists.json": {},
        "environment_context.json": {},
        "ingestion_state.json": {},
    }
    for fname, content in defaults.items():
        path = os.path.join(temp_data_dir, fname)
        if not os.path.exists(path):
            with open(path, "w") as f:
                json.dump(content, f)
    os.makedirs(os.path.join(temp_data_dir, "uploads"), exist_ok=True)


@pytest.fixture
def temp_data_dir():
    """Create a temporary data directory for test state files.

    Also redirects the Phase 3 calibration/feedback store paths so tests
    never touch the real /data (the stores derive paths from settings at
    call time, so patch at the module level).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        from nabla.rl import calibration
        from pathlib import Path as _P
        orig_fb = calibration.feedback_store_path
        orig_cal = calibration.calibration_store_path
        calibration.feedback_store_path = lambda: _P(tmpdir) / "labels.jsonl"
        calibration.calibration_store_path = lambda: _P(tmpdir) / "cal.json"
        try:
            yield tmpdir
        finally:
            calibration.feedback_store_path = orig_fb
            calibration.calibration_store_path = orig_cal


@pytest.fixture
def mock_settings(temp_data_dir):
    """Return a Settings instance pointing at temp_data_dir."""
    from nabla.config import Settings

    return Settings(
        data_dir=temp_data_dir,
        letta_base_url="http://localhost:9999",
        setup_token="",
        dev_mode=True,
        embedding_endpoint="http://localhost:11434/v1",
        splunk_host="",
        sumologic_host="",
        splunk_validate_url=False,
        sumologic_validate_url=False,
    )


@pytest.fixture
def mock_letta_client():
    """Return a mocked Letta client with health() returning ok."""
    client = MagicMock()
    client.health.return_value = MagicMock(status="ok", version="0.16.7")
    client.agents.list.return_value = []
    client.agents.messages.create.return_value = MagicMock()
    return client


@pytest.fixture
def app_client(mock_settings, mock_letta_client, temp_data_dir):
    """Return a TestClient for the Nabla API with mocked dependencies.

    Patches nabla.config.get_settings and nabla.client.get_client at the
    source, so all downstream imports resolve correctly. Overrides the
    require_token auth dependency with a no-op.
    """
    from nabla.server import app
    from nabla.auth import require_user
    from nabla.rate_limit import reset_rate_limits

    _write_minimal_state(temp_data_dir)

    # Reset rate limits to prevent interference between tests
    reset_rate_limits()

    # Override auth dependency at the FastAPI level
    app.dependency_overrides[require_user] = lambda: {"sub": "test", "role": "admin"}

    # Patch at the source modules
    with patch("nabla.config.get_settings", return_value=mock_settings), \
         patch("nabla.config._settings", mock_settings), \
         patch("nabla.client.get_client", return_value=mock_letta_client), \
         patch("nabla.client._client", mock_letta_client):

        client = TestClient(app, raise_server_exceptions=False)
        yield client

    # Clean up dependency overrides
    app.dependency_overrides.clear()


# (authed_client fixture removed 2026-09-01 — unused; the Bearer setup-token
# model it exercised is replaced by cookie-session auth, tested in
# tests/test_auth_users.py)
