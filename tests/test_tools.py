"""Tests for tool registration and agent configuration."""

import warnings


def test_no_tools_registered():
    """The supervisor agent has no tools — it reads blocks directly from its context window.

    This eliminates redundant LLM inference steps (each tool call requires a full
    inference pass). The supervisor's blocks are already in its context, so tools
    that just re-read blocks are unnecessary overhead.
    """
    from nabla.tools.register import LEGACY_TOOL_NAMES
    # LEGACY_TOOL_NAMES exists for teardown cleanup only; no active tools
    assert isinstance(LEGACY_TOOL_NAMES, set)


def test_supervisor_no_tool_ids():
    """The supervisor create function should not accept tool_ids."""
    import inspect
    from nabla.agents.supervisor import create_supervisor
    sig = inspect.signature(create_supervisor)
    assert "tool_ids" not in sig.parameters, (
        "supervisor create_supervisor should not accept tool_ids parameter"
    )


def test_supervisor_no_tool_rules():
    """The supervisor should not have tool rules (no tools = no rules)."""
    import nabla.agents.supervisor as supervisor_mod
    assert not hasattr(supervisor_mod, "TOOL_RULES"), (
        "supervisor module should not define TOOL_RULES"
    )


def test_supervisor_context_window_passed():
    """Round 9 (Phase-5 exit gate, found live): without an explicit
    context_window_limit the fork resolved the supervisor's llm_config to
    32768, and the round-8 lolbin fix (the real 246-entry DB in the
    lolbin_db block) pushed the system prompt past the window on large
    incidents — CONTEXT_WINDOW_EXCEEDED killed the supervisor call. The
    creation call must carry the window (the fork honors it verbatim and
    forwards it to Ollama as num_ctx)."""
    from unittest.mock import MagicMock
    from nabla.agents.supervisor import create_supervisor

    client = MagicMock()
    client.agents.create.return_value = MagicMock(id="agent-x")
    create_supervisor(
        client=client,
        model="gemma4:26b",
        embedding="embeddinggemma",
        block_ids=["b1"],
        letta_base_url="http://x",
        embedding_endpoint="http://y",
        context_window_limit=65536,
    )
    kwargs = client.agents.create.call_args.kwargs
    assert kwargs.get("context_window_limit") == 65536, (
        "context_window_limit must reach agents.create — the fork's "
        "caller-wins path is the only knob that changes the agent's "
        "llm_config.context_window"
    )
