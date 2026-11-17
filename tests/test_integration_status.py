"""Integration tests for the status endpoint."""

import pytest


@pytest.mark.integration
def test_get_status_after_bootstrap(bootstrap_system):
    """get_status should return blocks and agents after bootstrap."""
    from nabla.pipeline import get_status

    status = get_status()

    assert "blocks" in status
    assert "agents" in status
    assert len(status["agents"]) >= 1

    block_labels = set(status["blocks"].keys())
    assert "ingestion_status" in block_labels
    assert "anomaly_queue" in block_labels
    assert "threat_findings" in block_labels


@pytest.mark.integration
def test_get_status_no_agents(letta_client):
    """get_status should return error when no agents exist."""
    from nabla.pipeline import get_status
    from nabla.agents.bootstrap import teardown

    teardown(letta_client)

    status = get_status()
    assert "error" in status
    assert "bootstrap" in status["error"].lower()
