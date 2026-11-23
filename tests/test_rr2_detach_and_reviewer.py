"""Round 10 Phase 2 RED witnesses: lolbin detach + reviewer split (T-1, T-5, V-1).

RR-2: lolbin_db (45K chars of LOLBAS signatures) rides BOTH agents'
context windows but only the detection code reads it — a pure waste of
~11K tokens per supervisor call, and the direct cause of the round-9
CONTEXT_WINDOW_EXCEEDED once the real DB landed.

T-1: the pipeline review and the chat conversation share ONE agent, so
every chat turn is history the reviewer sees and every review is context
the chat drags around. The fix: a second agent (nabla-reviewer) with the
same persona/model/blocks, whose messages reset before every review
call. Chat keeps the supervisor and its history.

T-5: blocks.find_shared_blocks uses limit=1 and blindly takes the first
match — a duplicate-label block silently shadows the real one. The new
exact-lookup helper must fail LOUDLY on >1 match.

V-1: threat_findings growth is capped with a recorded degradation, not
silent truncation.
"""

from unittest.mock import MagicMock, patch

import pytest

from nabla.agents.bootstrap import bootstrap as run_bootstrap
from nabla.degradations import collect_degradations


# ── T-5: exact block lookup ─────────────────────────────────────


class TestExactBlockLookup:
    def test_single_match_returns_id(self):
        from nabla.blocks import find_block_by_label_exact
        client = MagicMock()
        b = MagicMock(); b.id = "b-1"
        client.blocks.list.return_value = [b]
        assert find_block_by_label_exact(client, "lolbin_db") == "b-1"

    def test_zero_matches_returns_none(self):
        from nabla.blocks import find_block_by_label_exact
        client = MagicMock()
        client.blocks.list.return_value = []
        assert find_block_by_label_exact(client, "lolbin_db") is None

    def test_duplicate_labels_fail_loudly(self):
        # T-5: the old find_shared_blocks silently took the first of
        # >1 same-label blocks. The replacement must raise — a silent
        # shadow block is exactly the failure mode this fixes.
        from nabla.blocks import find_block_by_label_exact
        client = MagicMock()
        b1 = MagicMock(); b1.id = "b-1"
        b2 = MagicMock(); b2.id = "b-2"
        client.blocks.list.return_value = [b1, b2]
        with pytest.raises(RuntimeError, match="lolbin_db"):
            find_block_by_label_exact(client, "lolbin_db")

    def test_read_helper_retrieves_value(self):
        from nabla.blocks import read_shared_block_value
        client = MagicMock()
        b = MagicMock(); b.id = "b-1"; b.value = "LOLBIN sigs"
        client.blocks.list.return_value = [b]
        client.blocks.retrieve.return_value = b
        assert read_shared_block_value(client, "lolbin_db") == "LOLBIN sigs"
        client.blocks.retrieve.assert_called_once_with(block_id="b-1")


# ── RR-2 + T-1: bootstrap split ──────────────────────────────────


def _mock_settings():
    return MagicMock(
        llm_model="ollama/gemma4:26b",
        embedding_model="embeddinggemma:latest",
        effective_tool_url="http://letta:8283",
        embedding_endpoint="http://host.docker.internal:11434/v1",
        letta_base_url="http://localhost:8284",
        letta_compaction_model=None,
        data_dir="/tmp/test",
        supervisor_context_window=65536,
        review_context_window=65536,
    )


def _mock_blocks():
    return {
        "ingestion_status": "b-1",
        "threat_findings": "b-2",
        "anomaly_queue": "b-3",
        "lolbin_db": "b-5",
        "graph_context": "b-6",
        "attack_mapping": "b-7",
        "environment_context": "b-8",
        "system_phase": "b-9",
    }


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.blocks.list.return_value = []
    mock_block = MagicMock(); mock_block.id = "block-123"
    client.blocks.create.return_value = mock_block
    mock_agent = MagicMock(); mock_agent.id = "agent-123"
    client.agents.create.return_value = mock_agent
    client.agents.list.return_value = []
    client.tools.list.return_value = []
    return client


class TestBootstrapSplit:
    @patch("nabla.agents.bootstrap.fix_embedding_model_prefix")
    @patch("nabla.agents.bootstrap.set_agent_compaction_model")
    @patch("nabla.agents.bootstrap.get_or_create_shared_blocks")
    @patch("nabla.agents.bootstrap.get_settings")
    def test_supervisor_blocks_exclude_lolbin(
        self, mock_settings, mock_blocks, mock_compaction, mock_embedding, mock_client,
    ):
        """RR-2: the supervisor (chat) agent must not carry lolbin_db."""
        mock_settings.return_value = _mock_settings()
        mock_blocks.return_value = _mock_blocks()
        run_bootstrap(mock_client)
        sup_calls = [
            c for c in mock_client.agents.create.call_args_list
            if c.kwargs.get("name") == "nabla-supervisor"
        ]
        assert sup_calls, "no supervisor create call"
        assert "b-5" not in sup_calls[0].kwargs.get("block_ids", []), (
            "supervisor still carries lolbin_db — RR-2 detach not applied")

    @patch("nabla.agents.bootstrap.fix_embedding_model_prefix")
    @patch("nabla.agents.bootstrap.set_agent_compaction_model")
    @patch("nabla.agents.bootstrap.get_or_create_shared_blocks")
    @patch("nabla.agents.bootstrap.get_settings")
    def test_reviewer_agent_created(
        self, mock_settings, mock_blocks, mock_compaction, mock_embedding, mock_client,
    ):
        """T-1: bootstrap creates a separate nabla-reviewer agent."""
        mock_settings.return_value = _mock_settings()
        mock_blocks.return_value = _mock_blocks()
        result = run_bootstrap(mock_client)
        assert "reviewer" in result, f"no reviewer role: {result}"
        rev_calls = [
            c for c in mock_client.agents.create.call_args_list
            if c.kwargs.get("name") == "nabla-reviewer"
        ]
        assert rev_calls, "no nabla-reviewer create call"
        # reviewer shares the supervisor's block list MINUS lolbin_db
        assert "b-5" not in rev_calls[0].kwargs.get("block_ids", [])

    @patch("nabla.agents.bootstrap.fix_embedding_model_prefix")
    @patch("nabla.agents.bootstrap.set_agent_compaction_model")
    @patch("nabla.agents.bootstrap.get_or_create_shared_blocks")
    @patch("nabla.agents.bootstrap.get_settings")
    def test_both_agents_get_workarounds(
        self, mock_settings, mock_blocks, mock_compaction, mock_embedding, mock_client,
    ):
        """The compaction-model and embedding-prefix fixes apply to both agents."""
        mock_settings.return_value = _mock_settings()
        mock_blocks.return_value = _mock_blocks()
        result = run_bootstrap(mock_client)
        fixed_ids = {c.args[0] for c in mock_compaction.call_args_list}
        assert result["supervisor"] in fixed_ids and result["reviewer"] in fixed_ids, (
            f"compaction fix missed an agent: {fixed_ids}")


# ── T-1: reviewer reset before every review call ────────────────


class TestReviewerReset:
    def test_review_uses_reviewer_and_resets_first(self):
        """run_supervisor must reset the reviewer's messages, then call it."""
        from nabla.pipeline.supervisor import run_supervisor
        client = MagicMock()
        resp = MagicMock()
        client.agents.messages.create.return_value = resp
        agents = {"supervisor": "sup-id", "reviewer": "rev-id"}
        run_supervisor(
            client, agents,
            findings_count=2,
            findings_text="[HIGH] lolbin by user bob",
            phase="detection",
        )
        reset_ids = [
            c.kwargs.get("agent_id") for c in
            client.agents.messages.reset.call_args_list
        ]
        assert reset_ids == ["rev-id"], f"reset not called on reviewer: {reset_ids}"
        create_ids = [
            c.kwargs.get("agent_id") for c in
            client.agents.messages.create.call_args_list
        ]
        assert create_ids == ["rev-id"], f"review call not on reviewer: {create_ids}"

    def test_reviewer_missing_falls_back_loudly(self):
        """Old stacks have no reviewer — fall back to the supervisor with a warning."""
        from nabla.pipeline.supervisor import run_supervisor
        client = MagicMock()
        client.agents.messages.create.return_value = MagicMock()
        agents = {"supervisor": "sup-id"}
        run_supervisor(
            client, agents,
            findings_count=2,
            findings_text="[HIGH] lolbin by user bob",
            phase="detection",
        )
        create_ids = [
            c.kwargs.get("agent_id") for c in
            client.agents.messages.create.call_args_list
        ]
        assert create_ids == ["sup-id"], "fallback to supervisor broken"


# ── V-1: findings cap is loud ───────────────────────────────────


class TestFindingsCap:
    """RR-2 cap, relocated F-1 (round 11): the cap fires ONCE, upstream in
    _cap_findings_for_review — format_findings renders exactly what it is
    given and never caps. The header admits the cap on its face."""

    def test_cap_renders_marker_and_degradation(self):
        from nabla.correlation import (
            format_findings, MAX_BLOCK_FINDINGS, _cap_findings_for_review,
        )
        findings = [
            {
                "finding_id": f"f-{i}", "entity": f"user{i}", "entity_type": "user",
                "severity": "high", "type": "lolbin", "confidence": 0.9,
                "anomaly_ids": ["anom-%03d" % i], "cross_type": "",
                "mitre_attack": [], "tools_detected": ["certutil"],
            }
            for i in range(MAX_BLOCK_FINDINGS + 7)
        ]
        with collect_degradations(sink := []) as s:
            shown, full = _cap_findings_for_review(findings)
        assert s.count("threat_findings_capped") == 1, f"degradations: {s}"
        assert len(shown) == MAX_BLOCK_FINDINGS
        assert len(full) == MAX_BLOCK_FINDINGS + 7, "the FULL list must survive"
        out = format_findings(shown, true_count=len(full))
        # the header carries the TRUE count and admits the cap on its face
        assert f"Confirmed threats: {MAX_BLOCK_FINDINGS + 7}" in out
        assert f"(top {MAX_BLOCK_FINDINGS} shown)" in out
        finding_lines = [l for l in out.split("\n") if l.startswith("[HIGH]")]
        assert len(finding_lines) == MAX_BLOCK_FINDINGS

    def test_format_findings_never_caps(self):
        """The cap site is upstream — format_findings must render ALL of
        whatever it is given (the F-1 relocation contract)."""
        from nabla.correlation import format_findings, MAX_BLOCK_FINDINGS
        findings = [
            {
                "finding_id": f"f-{i}", "entity": f"user{i}", "entity_type": "user",
                "severity": "high", "type": "lolbin", "confidence": 0.9,
                "anomaly_ids": ["anom-%03d" % i], "cross_type": "",
                "mitre_attack": [], "tools_detected": ["certutil"],
            }
            for i in range(MAX_BLOCK_FINDINGS + 7)
        ]
        with collect_degradations(sink := []) as s:
            out = format_findings(findings)
        assert s.count("threat_findings_capped") == 0, f"degradations: {s}"
        finding_lines = [l for l in out.split("\n") if l.startswith("[HIGH]")]
        assert len(finding_lines) == MAX_BLOCK_FINDINGS + 7
