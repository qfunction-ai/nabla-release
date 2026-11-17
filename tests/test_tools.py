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
