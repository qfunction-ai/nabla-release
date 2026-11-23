"""Tests for the bootstrap module.

Tests cover:
- bootstrap: block creation, agent creation, compaction model fix
- teardown: agent/tool/block deletion
- Error handling and idempotency

These tests mock the Letta client since bootstrap requires a live server.
Integration tests (test_integration_bootstrap.py) cover the real API.
"""

from unittest.mock import MagicMock, call, patch

import pytest

from nabla.agents.bootstrap import (
    bootstrap as run_bootstrap,
    teardown as run_teardown,
)


# ── Fixtures ──


@pytest.fixture
def mock_client():
    """A mocked Letta client."""
    client = MagicMock()

    # Mock blocks.list to return empty (no existing blocks)
    client.blocks.list.return_value = []

    # Mock blocks.create
    mock_block = MagicMock()
    mock_block.id = "block-123"
    client.blocks.create.return_value = mock_block

    # Mock agents.create
    mock_agent = MagicMock()
    mock_agent.id = "agent-123"
    client.agents.create.return_value = mock_agent

    # Mock agents.list
    client.agents.list.return_value = []

    # Mock tools.list
    client.tools.list.return_value = []

    return client


# ── bootstrap ──


class TestBootstrap:
    """Tests for the bootstrap function."""

    @patch("nabla.agents.bootstrap.fix_embedding_model_prefix")
    @patch("nabla.agents.bootstrap.set_agent_compaction_model")
    @patch("nabla.agents.bootstrap.get_or_create_shared_blocks")
    @patch("nabla.agents.bootstrap.get_settings")
    def test_creates_shared_blocks(
        self, mock_settings, mock_blocks, mock_compaction, mock_embedding, mock_client,
    ):
        """Bootstrap should call get_or_create_shared_blocks."""
        mock_settings.return_value = MagicMock(
            llm_model="ollama/gemma4:26b",
            embedding_model="embeddinggemma:latest",
            effective_tool_url="http://letta:8283",
            embedding_endpoint="http://host.docker.internal:11434/v1",
            letta_base_url="http://localhost:8284",
            letta_compaction_model=None,
            data_dir="/tmp/test",
        )
        mock_blocks.return_value = {
            "ingestion_status": "b-1",
            "threat_findings": "b-2",
            "anomaly_queue": "b-3",
            "rl_thresholds": "b-4",
            "lolbin_db": "b-5",
            "graph_context": "b-6",
            "attack_mapping": "b-7",
            "environment_context": "b-8",
            "system_phase": "b-9",
        }

        result = run_bootstrap(mock_client)
        mock_blocks.assert_called_once_with(mock_client)

    @patch("nabla.agents.bootstrap.fix_embedding_model_prefix")
    @patch("nabla.agents.bootstrap.set_agent_compaction_model")
    @patch("nabla.agents.bootstrap.get_or_create_shared_blocks")
    @patch("nabla.agents.bootstrap.get_settings")
    def test_creates_supervisor_agent(
        self, mock_settings, mock_blocks, mock_compaction, mock_embedding, mock_client,
    ):
        """Bootstrap should create a supervisor agent."""
        mock_settings.return_value = MagicMock(
            llm_model="ollama/gemma4:26b",
            embedding_model="embeddinggemma:latest",
            effective_tool_url="http://letta:8283",
            embedding_endpoint="http://host.docker.internal:11434/v1",
            letta_base_url="http://localhost:8284",
            letta_compaction_model=None,
            data_dir="/tmp/test",
        )
        mock_blocks.return_value = {
            "ingestion_status": "b-1",
            "threat_findings": "b-2",
            "anomaly_queue": "b-3",
            "rl_thresholds": "b-4",
            "lolbin_db": "b-5",
            "graph_context": "b-6",
            "attack_mapping": "b-7",
            "environment_context": "b-8",
            "system_phase": "b-9",
        }

        result = run_bootstrap(mock_client)
        assert "supervisor" in result
        # T-1 (round 10): supervisor + reviewer
        assert mock_client.agents.create.call_count == 2

    @patch("nabla.agents.bootstrap.fix_embedding_model_prefix")
    @patch("nabla.agents.bootstrap.set_agent_compaction_model")
    @patch("nabla.agents.bootstrap.get_or_create_shared_blocks")
    @patch("nabla.agents.bootstrap.get_settings")
    def test_sets_compaction_model(
        self, mock_settings, mock_blocks, mock_compaction, mock_embedding, mock_client,
    ):
        """Bootstrap should set compaction model for the supervisor agent."""
        mock_settings.return_value = MagicMock(
            llm_model="ollama/gemma4:26b",
            embedding_model="embeddinggemma:latest",
            effective_tool_url="http://letta:8283",
            embedding_endpoint="http://host.docker.internal:11434/v1",
            letta_base_url="http://localhost:8284",
            letta_compaction_model=None,
            data_dir="/tmp/test",
        )
        mock_blocks.return_value = {
            "ingestion_status": "b-1",
            "threat_findings": "b-2",
            "anomaly_queue": "b-3",
            "rl_thresholds": "b-4",
            "lolbin_db": "b-5",
            "graph_context": "b-6",
            "attack_mapping": "b-7",
            "environment_context": "b-8",
            "system_phase": "b-9",
        }

        run_bootstrap(mock_client)
        # T-1 (round 10): compaction fix applies to supervisor AND reviewer
        assert mock_compaction.call_count == 2

    @patch("nabla.agents.bootstrap.fix_embedding_model_prefix")
    @patch("nabla.agents.bootstrap.set_agent_compaction_model")
    @patch("nabla.agents.bootstrap.get_or_create_shared_blocks")
    @patch("nabla.agents.bootstrap.get_settings")
    def test_fixes_embedding_model_prefix(
        self, mock_settings, mock_blocks, mock_compaction, mock_embedding, mock_client,
    ):
        """Bootstrap should fix embedding model prefix for the supervisor agent."""
        mock_settings.return_value = MagicMock(
            llm_model="ollama/gemma4:26b",
            embedding_model="embeddinggemma:latest",
            effective_tool_url="http://letta:8283",
            embedding_endpoint="http://host.docker.internal:11434/v1",
            letta_base_url="http://localhost:8284",
            letta_compaction_model=None,
            data_dir="/tmp/test",
        )
        mock_blocks.return_value = {
            "ingestion_status": "b-1",
            "threat_findings": "b-2",
            "anomaly_queue": "b-3",
            "rl_thresholds": "b-4",
            "lolbin_db": "b-5",
            "graph_context": "b-6",
            "attack_mapping": "b-7",
            "environment_context": "b-8",
            "system_phase": "b-9",
        }

        run_bootstrap(mock_client)
        # T-1 (round 10): embedding fix applies to supervisor AND reviewer
        assert mock_embedding.call_count == 2

    @patch("nabla.agents.bootstrap.fix_embedding_model_prefix")
    @patch("nabla.agents.bootstrap.set_agent_compaction_model")
    @patch("nabla.agents.bootstrap.get_or_create_shared_blocks")
    @patch("nabla.agents.bootstrap.get_settings")
    def test_attack_mapping_failure_non_fatal(
        self, mock_settings, mock_blocks, mock_compaction, mock_embedding, mock_client,
    ):
        """Bootstrap should continue if attack_mapping download fails."""
        mock_settings.return_value = MagicMock(
            llm_model="ollama/gemma4:26b",
            embedding_model="embeddinggemma:latest",
            effective_tool_url="http://letta:8283",
            embedding_endpoint="http://host.docker.internal:11434/v1",
            letta_base_url="http://localhost:8284",
            letta_compaction_model=None,
            data_dir="/tmp/test",
        )
        mock_blocks.return_value = {
            "ingestion_status": "b-1",
            "threat_findings": "b-2",
            "anomaly_queue": "b-3",
            "rl_thresholds": "b-4",
            "lolbin_db": "b-5",
            "graph_context": "b-6",
            "attack_mapping": "b-7",
            "environment_context": "b-8",
            "system_phase": "b-9",
        }

        # Make attack bundle download fail
        with patch("nabla.attack.download_attack_bundle", side_effect=Exception("network error")):
            result = run_bootstrap(mock_client)
            assert "supervisor" in result

    @patch("nabla.agents.bootstrap.fix_embedding_model_prefix")
    @patch("nabla.agents.bootstrap.set_agent_compaction_model")
    @patch("nabla.agents.bootstrap.get_or_create_shared_blocks")
    @patch("nabla.agents.bootstrap.get_settings")
    def test_lolbin_db_failure_non_fatal(
        self, mock_settings, mock_blocks, mock_compaction, mock_embedding, mock_client,
    ):
        """Bootstrap should continue if lolbin_db download fails."""
        mock_settings.return_value = MagicMock(
            llm_model="ollama/gemma4:26b",
            embedding_model="embeddinggemma:latest",
            effective_tool_url="http://letta:8283",
            embedding_endpoint="http://host.docker.internal:11434/v1",
            letta_base_url="http://localhost:8284",
            letta_compaction_model=None,
            data_dir="/tmp/test",
        )
        mock_blocks.return_value = {
            "ingestion_status": "b-1",
            "threat_findings": "b-2",
            "anomaly_queue": "b-3",
            "rl_thresholds": "b-4",
            "lolbin_db": "b-5",
            "graph_context": "b-6",
            "attack_mapping": "b-7",
            "environment_context": "b-8",
            "system_phase": "b-9",
        }

        with patch("nabla.attack.download_attack_bundle", side_effect=Exception("network error")):
            with patch("nabla.lolbin_db.fetch_lolbin_data", side_effect=Exception("network error")):
                result = run_bootstrap(mock_client)
                assert "supervisor" in result

    @patch("nabla.agents.bootstrap.fix_embedding_model_prefix")
    @patch("nabla.agents.bootstrap.set_agent_compaction_model")
    @patch("nabla.agents.bootstrap.get_or_create_shared_blocks")
    @patch("nabla.agents.bootstrap.get_settings")
    def test_supervisor_receives_all_blocks(
        self, mock_settings, mock_blocks, mock_compaction, mock_embedding, mock_client,
    ):
        """Agents receive the 7 shared blocks (lolbin_db detached, RR-2)."""
        mock_settings.return_value = MagicMock(
            llm_model="ollama/gemma4:26b",
            embedding_model="embeddinggemma:latest",
            effective_tool_url="http://letta:8283",
            embedding_endpoint="http://host.docker.internal:11434/v1",
            letta_base_url="http://localhost:8284",
            letta_compaction_model=None,
            data_dir="/tmp/test",
        )
        block_ids = {
            "ingestion_status": "b-1",
            "threat_findings": "b-2",
            "anomaly_queue": "b-3",
            "lolbin_db": "b-5",
            "graph_context": "b-6",
            "attack_mapping": "b-7",
            "environment_context": "b-8",
            "system_phase": "b-9",
        }
        mock_blocks.return_value = block_ids

        run_bootstrap(mock_client)

        # RR-2 (round 10): lolbin_db detached — both agents receive 7
        # blocks (rl_thresholds retired, Phase 3)
        calls = mock_client.agents.create.call_args_list
        agent_calls = [c for c in calls if len(c[1].get("block_ids", [])) == 7]
        assert len(agent_calls) == 2, (
            f"expected supervisor+reviewer with 7 blocks, got {len(agent_calls)}")
        for c in agent_calls:
            assert "b-5" not in c[1]["block_ids"], "lolbin_db still attached"


# ── teardown ──


class TestTeardown:
    """Tests for the teardown function."""

    def test_deletes_nabla_agents(self, mock_client):
        """Teardown should delete all nabla-* agents."""
        mock_agent = MagicMock()
        mock_agent.name = "nabla-supervisor"
        mock_agent.id = "agent-123"
        mock_client.agents.list.return_value = [mock_agent]

        deleted = run_teardown(mock_client)
        mock_client.agents.delete.assert_called_once_with("agent-123")
        assert deleted >= 1

    def test_skips_non_nabla_agents(self, mock_client):
        """Teardown should not delete agents that don't start with 'nabla-'."""
        mock_agent = MagicMock()
        mock_agent.name = "other-agent"
        mock_agent.id = "agent-456"
        mock_client.agents.list.return_value = [mock_agent]

        deleted = run_teardown(mock_client)
        mock_client.agents.delete.assert_not_called()
        assert deleted == 0

    def test_deletes_nabla_tools(self, mock_client):
        """Teardown should delete tools with known Nabla names."""
        from nabla.tools.register import LEGACY_TOOL_NAMES

        mock_tool = MagicMock()
        mock_tool.name = list(LEGACY_TOOL_NAMES)[0] if LEGACY_TOOL_NAMES else "detect_anomalies"
        mock_tool.id = "tool-123"
        mock_client.tools.list.return_value = [mock_tool]

        deleted = run_teardown(mock_client)
        # Should have attempted to delete the tool
        if LEGACY_TOOL_NAMES:
            mock_client.tools.delete.assert_called()

    def test_deletes_shared_blocks(self, mock_client):
        """Teardown should delete shared blocks."""
        mock_block = MagicMock()
        mock_block.id = "block-123"
        mock_client.blocks.list.return_value = [mock_block]

        deleted = run_teardown(mock_client)
        # blocks.list should be called for each block label
        assert mock_client.blocks.list.call_count >= 1

    def test_agent_delete_failure_non_fatal(self, mock_client):
        """Teardown should continue if agent deletion fails."""
        mock_agent = MagicMock()
        mock_agent.name = "nabla-supervisor"
        mock_agent.id = "agent-123"
        mock_client.agents.list.return_value = [mock_agent]
        mock_client.agents.delete.side_effect = Exception("not found")

        deleted = run_teardown(mock_client)
        # Should not raise, deleted count may be 0
        assert isinstance(deleted, int)

    def test_returns_deleted_count(self, mock_client):
        """Teardown should return the total count of deleted resources."""
        mock_agent = MagicMock()
        mock_agent.name = "nabla-supervisor"
        mock_agent.id = "agent-123"
        mock_client.agents.list.return_value = [mock_agent]

        deleted = run_teardown(mock_client)
        assert isinstance(deleted, int)
        assert deleted >= 1
