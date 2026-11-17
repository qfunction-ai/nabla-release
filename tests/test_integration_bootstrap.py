"""Integration tests for the bootstrap/teardown lifecycle."""

import pytest


@pytest.mark.integration
def test_bootstrap_creates_agents(letta_client):
    """Bootstrap should create 1 agent (supervisor) with correct name prefix."""
    from nabla.agents.bootstrap import bootstrap, teardown

    try:
        agents = bootstrap(letta_client)
        assert len(agents) == 1
        assert "supervisor" in agents

        # Verify agent exists on the server
        all_agents = letta_client.agents.list(limit=100)
        nabla_names = {a.name for a in all_agents if a.name and a.name.startswith("nabla-")}
        assert "nabla-supervisor" in nabla_names
    finally:
        teardown(letta_client)


@pytest.mark.integration
def test_bootstrap_creates_shared_blocks(letta_client):
    """Bootstrap should create all shared blocks."""
    from nabla.agents.bootstrap import bootstrap, teardown

    try:
        agents = bootstrap(letta_client)

        # Check blocks via the supervisor agent
        blocks = letta_client.agents.blocks.list(agent_id=agents["supervisor"])
        block_labels = {b.label for b in blocks}
        assert "ingestion_status" in block_labels
        assert "anomaly_queue" in block_labels
        assert "threat_findings" in block_labels
        assert "rl_thresholds" in block_labels
        assert "lolbin_db" in block_labels
        assert "attack_mapping" in block_labels
    finally:
        teardown(letta_client)


@pytest.mark.integration
def test_teardown_removes_all(letta_client):
    """Teardown should delete all Nabla agents and blocks."""
    from nabla.agents.bootstrap import bootstrap, teardown

    bootstrap(letta_client)
    deleted = teardown(letta_client)
    # 1 agent + up to 9 blocks = up to 10
    # (blocks may already be gone if a prior test's teardown ran)
    assert deleted >= 1

    # Verify no nabla agents remain
    all_agents = letta_client.agents.list(limit=100)
    nabla_agents = [a for a in all_agents if a.name and a.name.startswith("nabla-")]
    assert len(nabla_agents) == 0

    # Verify no nabla shared blocks remain
    from nabla.blocks import SHARED_BLOCKS
    for label in SHARED_BLOCKS:
        blocks = letta_client.blocks.list(label=label, limit=100)
        nabla_blocks = [b for b in blocks if b.label == label]
        assert len(nabla_blocks) == 0, f"Block '{label}' still exists after teardown"


@pytest.mark.integration
def test_bootstrap_idempotent(letta_client):
    """Running bootstrap twice should find existing agents/blocks, not create duplicates."""
    from nabla.agents.bootstrap import bootstrap, teardown
    from nabla.agents.registry import find_all_agents

    try:
        bootstrap(letta_client)
        # Second bootstrap should find existing blocks and create new agents
        # (agents are always recreated since they're unique by name)
        bootstrap(letta_client)

        # Should still have exactly 1 nabla agent
        found = find_all_agents(letta_client)
        assert len(found) == 1
    finally:
        teardown(letta_client)


@pytest.mark.integration
def test_bootstrap_lolbin_db_populated(letta_client):
    """The lolbin_db block should be populated with real data after bootstrap (if APIs reachable)."""
    from nabla.agents.bootstrap import bootstrap, teardown

    try:
        agents = bootstrap(letta_client)

        # Read the lolbin_db block via the supervisor agent
        blocks = letta_client.agents.blocks.list(agent_id=agents["supervisor"])
        for b in blocks:
            if b.label == "lolbin_db":
                value = b.value or ""
                # If APIs were reachable, the block should have real data
                # If APIs were unreachable, the block keeps the placeholder
                if "not loaded" not in value:
                    assert "=== WINDOWS LOLBINS ===" in value or "=== UNIX GTFOBINS ===" in value, \
                        f"lolbin_db block has unexpected content: {value[:200]}"
                break
    finally:
        teardown(letta_client)


@pytest.mark.integration
def test_bootstrap_attack_mapping_populated(letta_client):
    """The attack_mapping block should be populated with ATT&CK data after bootstrap (if STIX bundle reachable)."""
    from nabla.agents.bootstrap import bootstrap, teardown

    try:
        agents = bootstrap(letta_client)

        # Read the attack_mapping block via the supervisor agent
        blocks = letta_client.agents.blocks.list(agent_id=agents["supervisor"])
        for b in blocks:
            if b.label == "attack_mapping":
                value = b.value or ""
                if "not loaded" not in value:
                    # Should have at least one technique ID
                    assert "T1" in value, \
                        f"attack_mapping block has unexpected content: {value[:200]}"
                break
    finally:
        teardown(letta_client)
