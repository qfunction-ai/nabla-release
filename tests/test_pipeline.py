"""Tests for pipeline utility functions."""

import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from nabla.pipeline import (
    _resolve_log_types,
    _extract_count,
    _resolve_source,
    _extract_assistant_message,
    _read_baseline_host_procs,
    _extract_host_processes_from_entries,
    get_status,
    _filter_watchlist_by_groups,
    _load_environment_context,
    _auto_detect_network_ranges,
    _auto_detect_new_accounts,
    _format_env_context_block,
)

# Relative timestamps so account-grace fixtures never expire with the
# calendar (see _auto_detect_new_accounts: filters against now() - grace_days).
RECENT_TS = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
OLD_TS = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_resolve_log_types_all():
    """'all' returns all 4 types."""
    types = _resolve_log_types("all")
    assert types == ["auth", "network", "dns", "endpoint"]


def test_resolve_log_types_single():
    """Single type string returns a list with one element."""
    types = _resolve_log_types("dns")
    assert types == ["dns"]


def test_resolve_log_types_list():
    """List of types passes through."""
    types = _resolve_log_types(["auth", "dns"])
    assert types == ["auth", "dns"]


def test_resolve_log_types_list_with_all():
    """'all' in a list expands to all types."""
    types = _resolve_log_types(["auth", "all"])
    assert types == ["auth", "network", "dns", "endpoint"]


def test_extract_count_anomalies():
    """Extract anomaly count from response text."""
    assert _extract_count("Updated anomaly_queue with 21 anomalies") == 21
    assert _extract_count("Detected 5 anomalies") == 5


def test_extract_count_findings():
    """Extract findings count from response text."""
    assert _extract_count("Recorded 21 threat findings") == 21


def test_extract_count_none():
    """No count found returns None."""
    assert _extract_count("No anomalies detected") is None
    assert _extract_count("") is None


def test_resolve_source_synthetic():
    assert _resolve_source("synthetic") == "synthetic"


def test_resolve_source_splunk():
    assert _resolve_source("splunk") == "splunk"


def test_resolve_source_auto_no_splunk():
    """Auto resolves to synthetic when no Splunk host configured."""
    # Clear any cached settings
    import nabla.config
    nabla.config._settings = None
    # Ensure no Splunk host in env
    old = os.environ.pop("NABLA_SPLUNK_HOST", None)
    try:
        assert _resolve_source("auto") == "synthetic"
    finally:
        if old is not None:
            os.environ["NABLA_SPLUNK_HOST"] = old
        nabla.config._settings = None


def test_resolve_source_auto_with_splunk():
    """Auto resolves to splunk when Splunk host is configured."""
    import nabla.config
    nabla.config._settings = None
    os.environ["NABLA_SPLUNK_HOST"] = "https://splunk.example.com:8089"
    try:
        assert _resolve_source("auto") == "splunk"
    finally:
        del os.environ["NABLA_SPLUNK_HOST"]
        nabla.config._settings = None


def test_resolve_source_unknown():
    """Unknown source raises ValueError."""
    try:
        _resolve_source("nonexistent")
    except ValueError as e:
        assert "nonexistent" in str(e)
    else:
        assert False, "Expected ValueError"


# ---------------------------------------------------------------------------
# _extract_assistant_message
# ---------------------------------------------------------------------------


def test_extract_assistant_message_with_assistant_msg():
    """Returns the first assistant_message content."""
    msg1 = MagicMock()
    msg1.message_type = "assistant_message"
    msg1.content = "Hello from assistant"
    msg2 = MagicMock()
    msg2.message_type = "tool_return_message"
    msg2.tool_return = "tool result"

    response = MagicMock()
    response.messages = [msg2, msg1]

    assert _extract_assistant_message(response) == "Hello from assistant"


def test_extract_assistant_message_fallback_to_tool_return():
    """Falls back to last tool_return when no assistant message present."""
    msg1 = MagicMock()
    msg1.message_type = "tool_return_message"
    msg1.tool_return = "first result"
    msg2 = MagicMock()
    msg2.message_type = "tool_return_message"
    msg2.tool_return = "last result"

    response = MagicMock()
    response.messages = [msg1, msg2]

    assert _extract_assistant_message(response) == "last result"


def test_extract_assistant_message_empty_assistant_content_skipped():
    """Skips assistant messages with empty content, falls back to tool return."""
    msg1 = MagicMock()
    msg1.message_type = "assistant_message"
    msg1.content = ""
    msg2 = MagicMock()
    msg2.message_type = "tool_return_message"
    msg2.tool_return = "fallback"

    response = MagicMock()
    response.messages = [msg1, msg2]

    assert _extract_assistant_message(response) == "fallback"


def test_extract_assistant_message_no_tool_return_attr():
    """Skips tool_return messages that lack the tool_return attribute."""
    msg = MagicMock()
    msg.message_type = "tool_return_message"
    # Remove the tool_return attribute so hasattr returns False
    del msg.tool_return

    response = MagicMock()
    response.messages = [msg]

    assert _extract_assistant_message(response) == ""


def test_extract_assistant_message_empty_messages():
    """Returns empty string when there are no messages."""
    response = MagicMock()
    response.messages = []

    assert _extract_assistant_message(response) == ""


def test_extract_assistant_message_tool_return_empty_skipped():
    """Skips tool_return messages with empty/falsy tool_return value."""
    msg1 = MagicMock()
    msg1.message_type = "tool_return_message"
    msg1.tool_return = ""
    msg2 = MagicMock()
    msg2.message_type = "tool_return_message"
    msg2.tool_return = "actual result"

    response = MagicMock()
    response.messages = [msg1, msg2]

    assert _extract_assistant_message(response) == "actual result"


# ---------------------------------------------------------------------------
# _read_baseline_host_procs
# ---------------------------------------------------------------------------


def test_read_baseline_host_procs_basic():
    """Parses baseline JSONL file and returns host → sorted process list."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({
            "snapshot_type": "baseline",
            "host_processes": {
                "HOST-A": ["svchost", "explorer"],
                "HOST-B": ["chrome"],
            },
        }) + "\n")
        path = f.name

    mock_settings = MagicMock()
    mock_settings.baseline_snapshots_file = path
    try:
        with patch("nabla.config.get_settings", return_value=mock_settings):
            result = _read_baseline_host_procs()
        assert result == {"HOST-A": ["explorer", "svchost"], "HOST-B": ["chrome"]}
    finally:
        os.unlink(path)


def test_read_baseline_host_procs_merges_multiple_lines():
    """Merges process sets across multiple JSONL lines."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({
            "snapshot_type": "baseline",
            "host_processes": {"HOST-A": ["svchost"]},
        }) + "\n")
        f.write(json.dumps({
            "snapshot_type": "baseline",
            "host_processes": {"HOST-A": ["explorer"], "HOST-B": ["chrome"]},
        }) + "\n")
        path = f.name

    mock_settings = MagicMock()
    mock_settings.baseline_snapshots_file = path
    try:
        with patch("nabla.config.get_settings", return_value=mock_settings):
            result = _read_baseline_host_procs()
        assert result == {"HOST-A": ["explorer", "svchost"], "HOST-B": ["chrome"]}
    finally:
        os.unlink(path)


def test_read_baseline_host_procs_skips_non_baseline():
    """Ignores JSONL lines that are not baseline snapshots."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({
            "snapshot_type": "other",
            "host_processes": {"HOST-A": ["svchost"]},
        }) + "\n")
        path = f.name

    mock_settings = MagicMock()
    mock_settings.baseline_snapshots_file = path
    try:
        with patch("nabla.config.get_settings", return_value=mock_settings):
            result = _read_baseline_host_procs()
        assert result == {}
    finally:
        os.unlink(path)


def test_read_baseline_host_procs_skips_no_host_processes_key():
    """Ignores baseline lines missing the host_processes key."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({
            "snapshot_type": "baseline",
            "other_data": "value",
        }) + "\n")
        path = f.name

    mock_settings = MagicMock()
    mock_settings.baseline_snapshots_file = path
    try:
        with patch("nabla.config.get_settings", return_value=mock_settings):
            result = _read_baseline_host_procs()
        assert result == {}
    finally:
        os.unlink(path)


def test_read_baseline_host_procs_handles_json_decode_error():
    """Gracefully handles invalid JSON in a line."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write("not valid json{{\n")
        f.write(json.dumps({
            "snapshot_type": "baseline",
            "host_processes": {"HOST-A": ["svchost"]},
        }) + "\n")
        path = f.name

    mock_settings = MagicMock()
    mock_settings.baseline_snapshots_file = path
    try:
        with patch("nabla.config.get_settings", return_value=mock_settings):
            result = _read_baseline_host_procs()
        assert result == {"HOST-A": ["svchost"]}
    finally:
        os.unlink(path)


def test_read_baseline_host_procs_handles_empty_file():
    """Returns empty dict for empty or missing file."""
    mock_settings = MagicMock()
    mock_settings.baseline_snapshots_file = "/nonexistent/path.jsonl"
    with patch("nabla.config.get_settings", return_value=mock_settings):
        result = _read_baseline_host_procs()
    assert result == {}


def test_read_baseline_host_procs_handles_exception():
    """Returns empty dict when an exception occurs."""
    mock_settings = MagicMock()
    mock_settings.baseline_snapshots_file = "/nonexistent/path.jsonl"
    with patch("nabla.config.get_settings", return_value=mock_settings):
        result = _read_baseline_host_procs()
    assert result == {}


# ---------------------------------------------------------------------------
# _extract_host_processes_from_entries
# ---------------------------------------------------------------------------


def test_extract_host_processes_basic():
    """Extracts and normalizes process names from endpoint entries."""
    entries = [
        {"type": "endpoint", "host": "WS-01", "process": "svchost.exe"},
        {"type": "endpoint", "host": "WS-01", "process": "Explorer.EXE"},
        {"type": "endpoint", "host": "WS-02", "process": "chrome.exe"},
    ]
    result = _extract_host_processes_from_entries(entries)
    assert result == {
        "WS-01": ["explorer", "svchost"],
        "WS-02": ["chrome"],
    }


def test_extract_host_processes_uses_image_field():
    """Falls back to 'Image' field when 'process' is absent."""
    entries = [
        {"type": "endpoint", "host": "SRV-01", "Image": "C:\\Windows\\cmd.exe"},
    ]
    result = _extract_host_processes_from_entries(entries)
    assert result == {"SRV-01": ["c:\\windows\\cmd"]}


def test_extract_host_processes_strips_exe_and_lowercases():
    """Strips .exe suffix and lowercases process names."""
    entries = [
        {"type": "endpoint", "host": "H1", "process": "SVCHOST.EXE"},
    ]
    result = _extract_host_processes_from_entries(entries)
    assert result == {"H1": ["svchost"]}


def test_extract_host_processes_deduplicates():
    """Deduplicates process names per host."""
    entries = [
        {"type": "endpoint", "host": "H1", "process": "svchost.exe"},
        {"type": "endpoint", "host": "H1", "process": "SVCHOST.EXE"},
    ]
    result = _extract_host_processes_from_entries(entries)
    assert result == {"H1": ["svchost"]}


def test_extract_host_processes_skips_non_endpoint():
    """Skips entries that are not type 'endpoint'."""
    entries = [
        {"type": "auth", "host": "H1", "process": "sshd"},
    ]
    result = _extract_host_processes_from_entries(entries)
    assert result == {}


def test_extract_host_processes_skips_empty_host_or_proc():
    """Skips entries with empty host or empty process."""
    entries = [
        {"type": "endpoint", "host": "", "process": "svchost.exe"},
        {"type": "endpoint", "host": "H1", "process": ""},
        {"type": "endpoint", "host": "H1", "process": None},
    ]
    result = _extract_host_processes_from_entries(entries)
    assert result == {}


def test_extract_host_processes_empty_list():
    """Returns empty dict for empty entries list."""
    assert _extract_host_processes_from_entries([]) == {}


# ---------------------------------------------------------------------------
# get_status
# ---------------------------------------------------------------------------


def test_get_status_returns_blocks_and_agents():
    """Returns blocks dict and agent list when supervisor exists."""
    block1 = MagicMock()
    block1.label = "anomaly_queue"
    block1.value = "5 anomalies"
    block2 = MagicMock()
    block2.label = "rl_thresholds"
    block2.value = "auth=0.7"

    agent1 = MagicMock()
    agent1.id = "agent-1"
    agent1.name = "nabla-supervisor"
    agent3 = MagicMock()
    agent3.id = "agent-3"
    agent3.name = "other-agent"

    client = MagicMock()
    client.agents.blocks.list.return_value = [block1, block2]
    client.agents.list.return_value = [agent1, agent3]

    with patch("nabla.pipeline.status.find_all_agents", return_value={"supervisor": "sup-123"}), \
         patch("nabla.config.get_settings") as mock_settings, \
         patch("nabla.system_state.load_system_state", return_value={"phase": "detection", "first_ingestion_at": None}), \
         patch("nabla.system_state.baseline_days_remaining", return_value=None):
        mock_settings.return_value.agent_list_limit = 100
        result = get_status(client)

    assert result["blocks"]["anomaly_queue"] == "5 anomalies"
    assert result["blocks"]["rl_thresholds"] == "auth=0.7"
    assert result["blocks"]["system_phase"] == "detection"
    assert len(result["agents"]) == 1
    assert result["agents"][0]["role"] == "supervisor"


def test_get_status_no_supervisor():
    """Returns error dict when supervisor agent not found."""
    client = MagicMock()

    with patch("nabla.pipeline.status.find_all_agents", return_value={}):
        result = get_status(client)

    assert "error" in result
    assert "Supervisor agent not found" in result["error"]


def test_get_status_no_nabla_agents_in_list():
    """Returns empty agents list when no nabla- prefixed agents exist."""
    block = MagicMock()
    block.label = "anomaly_queue"
    block.value = "empty"

    other_agent = MagicMock()
    other_agent.id = "agent-99"
    other_agent.name = "some-other-agent"

    client = MagicMock()
    client.agents.blocks.list.return_value = [block]
    client.agents.list.return_value = [other_agent]

    with patch("nabla.pipeline.status.find_all_agents", return_value={"supervisor": "sup-123"}), \
         patch("nabla.config.get_settings") as mock_settings, \
         patch("nabla.system_state.load_system_state", return_value={"phase": "baseline", "first_ingestion_at": None}), \
         patch("nabla.system_state.baseline_days_remaining", return_value=None):
        mock_settings.return_value.agent_list_limit = 100
        result = get_status(client)

    assert result["blocks"]["anomaly_queue"] == "empty"
    assert result["blocks"]["system_phase"] == "baseline"
    assert result["agents"] == []


def test_get_status_creates_client_if_none():
    """Creates a client via get_client when none is provided."""
    mock_client = MagicMock()
    block = MagicMock()
    block.label = "test"
    block.value = "val"
    mock_client.agents.blocks.list.return_value = [block]
    mock_client.agents.list.return_value = []

    with patch("nabla.client.get_client", return_value=mock_client), \
         patch("nabla.pipeline.status.find_all_agents", return_value={"supervisor": "sup-123"}), \
         patch("nabla.config.get_settings") as mock_settings, \
         patch("nabla.system_state.load_system_state", return_value={"phase": "detection", "first_ingestion_at": None}), \
         patch("nabla.system_state.baseline_days_remaining", return_value=None):
        mock_settings.return_value.agent_list_limit = 100
        result = get_status()

    assert "blocks" in result


# ---------------------------------------------------------------------------
# _filter_watchlist_by_groups
# ---------------------------------------------------------------------------


def _make_watchlist_data():
    """Sample watchlist data for testing."""
    return {
        "high_value_users": ["admin", "root"],
        "critical_systems": ["dc01", "web01"],
        "watched_ips": ["10.0.0.1", "192.168.1.1"],
        "custom_groups": {
            "vip_network_ips": ["172.16.0.0/16"],
            "db_servers": ["db01", "db02"],
            "contractors": ["contractor1", "contractor2"],
        },
    }


def test_filter_watchlist_high_value_users():
    """Filters high_value_users group into users list."""
    with patch("nabla.watchlist.load_watchlist", return_value=_make_watchlist_data()):
        result = _filter_watchlist_by_groups("/fake/path", ["high_value_users"])
    assert result.users == ["admin", "root"]
    assert result.hosts == []
    assert result.ips == []


def test_filter_watchlist_critical_systems():
    """Filters critical_systems group into hosts list."""
    with patch("nabla.watchlist.load_watchlist", return_value=_make_watchlist_data()):
        result = _filter_watchlist_by_groups("/fake/path", ["critical_systems"])
    assert result.hosts == ["dc01", "web01"]
    assert result.users == []
    assert result.ips == []


def test_filter_watchlist_watched_ips():
    """Filters watched_ips group into ips list."""
    with patch("nabla.watchlist.load_watchlist", return_value=_make_watchlist_data()):
        result = _filter_watchlist_by_groups("/fake/path", ["watched_ips"])
    assert result.ips == ["10.0.0.1", "192.168.1.1"]
    assert result.users == []
    assert result.hosts == []


def test_filter_watchlist_custom_ip_group():
    """Infers ip type from custom group name containing 'ip' or 'network'."""
    with patch("nabla.watchlist.load_watchlist", return_value=_make_watchlist_data()):
        result = _filter_watchlist_by_groups("/fake/path", ["vip_network_ips"])
    assert result.ips == ["172.16.0.0/16"]
    assert result.users == []
    assert result.hosts == []


def test_filter_watchlist_custom_host_group():
    """Infers host type from custom group name containing 'host', 'system', or 'server'."""
    with patch("nabla.watchlist.load_watchlist", return_value=_make_watchlist_data()):
        result = _filter_watchlist_by_groups("/fake/path", ["db_servers"])
    assert result.hosts == ["db01", "db02"]
    assert result.users == []
    assert result.ips == []


def test_filter_watchlist_custom_user_group():
    """Infers user type for custom group names that don't match ip/host patterns."""
    with patch("nabla.watchlist.load_watchlist", return_value=_make_watchlist_data()):
        result = _filter_watchlist_by_groups("/fake/path", ["contractors"])
    assert result.users == ["contractor1", "contractor2"]
    assert result.hosts == []
    assert result.ips == []


def test_filter_watchlist_multiple_groups():
    """Combines multiple groups across categories."""
    with patch("nabla.watchlist.load_watchlist", return_value=_make_watchlist_data()):
        result = _filter_watchlist_by_groups(
            "/fake/path", ["high_value_users", "critical_systems", "watched_ips"]
        )
    assert result.users == ["admin", "root"]
    assert result.hosts == ["dc01", "web01"]
    assert result.ips == ["10.0.0.1", "192.168.1.1"]


def test_filter_watchlist_deduplicates():
    """Deduplicates entities when same value appears in multiple groups."""
    data = _make_watchlist_data()
    data["custom_groups"]["more_users"] = ["admin", "newuser"]

    with patch("nabla.watchlist.load_watchlist", return_value=data):
        result = _filter_watchlist_by_groups(
            "/fake/path", ["high_value_users", "more_users"]
        )
    assert result.users == ["admin", "root", "newuser"]


def test_filter_watchlist_unknown_group_ignored():
    """Unknown group names that aren't in data are silently ignored."""
    with patch("nabla.watchlist.load_watchlist", return_value=_make_watchlist_data()):
        result = _filter_watchlist_by_groups("/fake/path", ["nonexistent_group"])
    assert result.users == []
    assert result.hosts == []
    assert result.ips == []


def test_filter_watchlist_empty_groups():
    """Empty groups list returns empty Watchlist."""
    with patch("nabla.watchlist.load_watchlist", return_value=_make_watchlist_data()):
        result = _filter_watchlist_by_groups("/fake/path", [])
    assert result.users == []
    assert result.hosts == []
    assert result.ips == []


# ---------------------------------------------------------------------------
# Supervisor LLM skip on zero findings
# ---------------------------------------------------------------------------


def test_supervisor_skips_llm_on_zero_findings():
    """When findings_count == 0, the LLM is never called and a
    deterministic template is returned instead."""
    client = MagicMock()

    # Simulate the supervisor step with findings_count == 0
    findings_count = 0
    findings_text = "Confirmed threats: 0\nNo threats detected."

    # This is the logic from pipeline.py Step 4
    if findings_count == 0:
        supervisor_text = (
            "No confirmed threats detected. All anomaly detection "
            "methods returned below-threshold results. "
            "Continued monitoring is recommended."
        )
    else:
        supervisor_response = client.agents.messages.create(
            agent_id="sup-123",
            messages=[{"role": "user", "content": "review prompt"}],
        )
        supervisor_text = "LLM response"

    # The LLM should never have been called
    client.agents.messages.create.assert_not_called()

    # The result should be the deterministic template
    assert "No confirmed threats detected" in supervisor_text
    assert "below-threshold" in supervisor_text


def test_supervisor_calls_llm_on_findings():
    """When findings_count > 0, the LLM IS called for review."""
    client = MagicMock()
    msg = MagicMock()
    msg.message_type = "assistant_message"
    msg.content = "I reviewed the threats."
    response = MagicMock()
    response.messages = [msg]
    client.agents.messages.create.return_value = response

    findings_count = 3
    findings_text = "Confirmed threats: 3\nFinding 1, 2, 3"

    if findings_count == 0:
        supervisor_text = "No confirmed threats detected."
    else:
        supervisor_response = client.agents.messages.create(
            agent_id="sup-123",
            messages=[{"role": "user", "content": "review prompt"}],
        )
        supervisor_text = _extract_assistant_message(supervisor_response)

    # The LLM should have been called
    client.agents.messages.create.assert_called_once()
    assert supervisor_text == "I reviewed the threats."


# --- Environment context helpers ---

class TestLoadEnvironmentContext:
    """Tests for _load_environment_context."""

    def test_missing_file_returns_defaults(self):
        """Missing file returns empty defaults."""
        ctx = _load_environment_context("/nonexistent/path.json")
        assert ctx["environment"] == []
        assert ctx["entities"] == {}
        assert ctx["network_ranges"] == []
        assert ctx["new_accounts"] == set()
        assert ctx["service_accounts"] == set()
        assert ctx["admin_accounts"] == set()
        assert ctx["benign_patterns"] == []

    def test_valid_file_loads(self):
        """Valid JSON file loads correctly."""
        import tempfile
        data = {
            "environment": ["Only one forest in the domain"],
            "entities": {
                "joindomain": ["Exclusively used to join computers to the domain"],
            },
            "network_ranges": ["10.0.0.0/8"],
            "new_accounts": ["jrivera", "joindomain"],
            "service_accounts": ["svc_backup"],
            "admin_accounts": ["admin"],
            "benign_patterns": ["certutil downloading known installer"],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            ctx = _load_environment_context(path)
            assert ctx["environment"] == ["Only one forest in the domain"]
            assert ctx["entities"] == {"joindomain": ["Exclusively used to join computers to the domain"]}
            assert ctx["network_ranges"] == ["10.0.0.0/8"]
            assert ctx["new_accounts"] == {"jrivera", "joindomain"}
            assert ctx["service_accounts"] == {"svc_backup"}
            assert ctx["admin_accounts"] == {"admin"}
            assert ctx["benign_patterns"] == ["certutil downloading known installer"]
        finally:
            os.unlink(path)

    def test_invalid_json_returns_defaults(self):
        """Invalid JSON file returns defaults."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json")
            path = f.name
        try:
            ctx = _load_environment_context(path)
            assert ctx["new_accounts"] == set()
        finally:
            os.unlink(path)


class TestAutoDetectNetworkRanges:
    """Tests for _auto_detect_network_ranges."""

    def test_detects_private_subnets(self):
        """Detects /24 subnets from private IPs."""
        entries = [
            {"source_ip": "172.31.94.24"},
            {"source_ip": "172.31.94.100"},
            {"source_ip": "10.0.1.5"},
            {"source_ip": "8.8.8.8"},  # Public, should be ignored
        ]
        ranges = _auto_detect_network_ranges(entries)
        assert "172.31.94.0/24" in ranges
        assert "10.0.1.0/24" in ranges
        # Public IP should not produce a range
        assert not any("8.8" in r for r in ranges)

    def test_empty_entries(self):
        """Empty entries list returns empty ranges."""
        assert _auto_detect_network_ranges([]) == []

    def test_no_private_ips(self):
        """All public IPs returns empty ranges."""
        entries = [{"source_ip": "8.8.8.8"}, {"source_ip": "1.2.3.4"}]
        assert _auto_detect_network_ranges(entries) == []

    def test_ipv6_private(self):
        """IPv6 unique-local addresses are detected."""
        entries = [{"source_ip": "fd00::1"}]
        ranges = _auto_detect_network_ranges(entries)
        assert len(ranges) == 1  # fd00::/64

    def test_unparseable_ip_is_skipped_not_fatal(self):
        """One malformed IP must not poison the rest of the batch (F7).

        Regression: the 2026-09 silent-swallow sweep replaced this handler's
        `continue` with a bare `pass`, leaving `addr` unbound. A single bad IP
        then raised UnboundLocalError, which aborted the entire
        environment-context block write — auto-ranges, new accounts, and
        per-entity run stats all silently kept their previous values.
        """
        entries = [{"source_ip": "-"}, {"source_ip": "172.31.94.24"}]
        ranges = _auto_detect_network_ranges(entries)
        assert "172.31.94.0/24" in ranges

    def test_placeholder_only_entries_yield_no_ranges(self):
        """A batch of nothing but placeholders is empty, not an error."""
        assert _auto_detect_network_ranges([{"source_ip": "-"}]) == []
        assert _auto_detect_network_ranges([{"source_ip": "-"}, {"source_ip": ""}]) == []

    def test_unparseable_ip_after_valid_one(self):
        """Order must not matter — a bad IP trailing a good one is still skipped."""
        entries = [{"source_ip": "10.0.1.5"}, {"source_ip": "not-an-ip"}]
        assert _auto_detect_network_ranges(entries) == ["10.0.1.0/24"]


class TestEnvironmentContextBlockWriteSurvivesBadInput:
    """F7 end to end: the block write must not be aborted by one bad IP.

    The unit tests above pin the helper. This pins the consequence — that the
    supervisor's block actually gets written when the batch contains a
    placeholder IP, which is the thing that was silently not happening.
    """

    def _write(self, all_entries, tmp_path, monkeypatch):
        from nabla.pipeline.detection import DetectionResult, _write_environment_context_block

        monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))
        client = MagicMock()
        result = DetectionResult(
            env_context={"environment": [], "entities": {}},
            anomalous_entities=set(),
        )
        _write_environment_context_block(client, {"supervisor": "agent-1"}, result, all_entries=all_entries)
        return client, result

    def test_block_written_when_batch_has_placeholder_ip(self, tmp_path, monkeypatch):
        """A `-` source_ip must not stop the block write."""
        client, result = self._write(
            [{"source_ip": "-", "user": "alice"}, {"source_ip": "172.31.94.24", "user": "bob"}],
            tmp_path,
            monkeypatch,
        )
        assert client.agents.blocks.update.called, "environment_context block was never written"
        assert "172.31.94.0/24" in result.auto_ranges

    def test_block_written_for_clean_batch(self, tmp_path, monkeypatch):
        """The happy path still works — the guard did not break the normal case."""
        client, result = self._write(
            [{"source_ip": "10.0.1.5", "user": "alice"}],
            tmp_path,
            monkeypatch,
        )
        assert client.agents.blocks.update.called
        assert result.auto_ranges == ["10.0.1.0/24"]


class TestFormatEnvContextBlock:
    """Tests for _format_env_context_block."""

    def test_empty_context(self):
        """Empty context with no auto-ranges produces minimal block."""
        ctx = {
            "environment": [],
            "entities": {},
            "network_ranges": [],
            "new_accounts": set(),
            "service_accounts": set(),
            "admin_accounts": set(),
            "benign_patterns": [],
        }
        text = _format_env_context_block(ctx, [])
        assert "ENVIRONMENT CONTEXT" in text
        assert "--- JSON ---" in text

    def test_environment_facts_section(self):
        """Environment facts appear in the block."""
        ctx = {
            "environment": ["Only one forest in the domain", "New AD objects created by domain admins only"],
            "entities": {},
            "network_ranges": [],
            "new_accounts": set(),
            "service_accounts": set(),
            "admin_accounts": set(),
            "benign_patterns": [],
        }
        text = _format_env_context_block(ctx, [])
        assert "Environment Facts" in text
        assert "Only one forest in the domain" in text
        assert "New AD objects created by domain admins only" in text

    def test_entity_context_for_anomalous_entities(self):
        """Entity context only appears for anomalous entities."""
        ctx = {
            "environment": [],
            "entities": {
                "joindomain": ["Exclusively joins computers to domain"],
                "admin": ["Expected privileged activity"],
            },
            "network_ranges": [],
            "new_accounts": set(),
            "service_accounts": set(),
            "admin_accounts": set(),
            "benign_patterns": [],
        }
        # Only joindomain is anomalous
        text = _format_env_context_block(ctx, [], anomalous_entities={"joindomain"})
        assert "joindomain" in text
        assert "Exclusively joins computers to domain" in text
        # admin should NOT appear in entity context section
        entity_section = text.split("--- Entity Context")[1].split("---")[0] if "--- Entity Context" in text else ""
        assert "admin" not in entity_section or "Expected privileged" not in entity_section

    def test_entity_context_omitted_when_no_anomalous_entities(self):
        """Entity context section omitted when no anomalous entities match."""
        ctx = {
            "environment": [],
            "entities": {"joindomain": ["Exclusively joins computers to domain"]},
            "network_ranges": [],
            "new_accounts": set(),
            "service_accounts": set(),
            "admin_accounts": set(),
            "benign_patterns": [],
        }
        text = _format_env_context_block(ctx, [], anomalous_entities={"admin"})
        assert "Entity Context" not in text

    def test_new_accounts_in_block(self):
        """New accounts appear in the formatted block."""
        ctx = {
            "environment": [],
            "entities": {},
            "network_ranges": [],
            "new_accounts": {"jrivera", "joindomain"},
            "service_accounts": set(),
            "admin_accounts": set(),
            "benign_patterns": [],
        }
        text = _format_env_context_block(ctx, [])
        assert "jrivera" in text
        assert "joindomain" in text
        assert "grace period" in text.lower()

    def test_auto_new_accounts_with_dates(self):
        """Auto-detected new accounts show creation dates."""
        ctx = {
            "environment": [],
            "entities": {},
            "network_ranges": [],
            "new_accounts": set(),
            "service_accounts": set(),
            "admin_accounts": set(),
            "benign_patterns": [],
        }
        auto_new = {"svc-new": "2026-04-28T10:00:00Z"}
        text = _format_env_context_block(ctx, [], auto_new_accounts=auto_new)
        assert "svc-new" in text
        assert "2026-04-28" in text

    def test_auto_ranges_merged(self):
        """Auto-detected ranges are merged with configured ranges."""
        ctx = {
            "environment": [],
            "entities": {},
            "network_ranges": ["10.0.0.0/8"],
            "new_accounts": set(),
            "service_accounts": set(),
            "admin_accounts": set(),
            "benign_patterns": [],
        }
        text = _format_env_context_block(ctx, ["172.31.94.0/24"])
        assert "10.0.0.0/8" in text
        assert "172.31.94.0/24" in text
        # JSON section should have both
        json_section = text.split("--- JSON ---")[1]
        data = json.loads(json_section.strip())
        assert "10.0.0.0/8" in data["network_ranges"]
        assert "172.31.94.0/24" in data["network_ranges"]

    def test_json_includes_environment_and_entities(self):
        """JSON section includes environment and entities fields."""
        ctx = {
            "environment": ["Only one forest"],
            "entities": {"joindomain": ["Joins computers to domain"]},
            "network_ranges": [],
            "new_accounts": set(),
            "service_accounts": set(),
            "admin_accounts": set(),
            "benign_patterns": [],
        }
        text = _format_env_context_block(ctx, [], anomalous_entities={"joindomain"})
        json_section = text.split("--- JSON ---")[1]
        data = json.loads(json_section.strip())
        assert data["environment"] == ["Only one forest"]
        assert "joindomain" in data["entities"]
        assert data["entities"]["joindomain"] == ["Joins computers to domain"]


class TestAutoDetectNewAccounts:
    """Tests for _auto_detect_new_accounts."""

    def test_detects_account_created_action(self):
        """Detects entries with action='account_created'."""
        entries = [
            {"action": "account_created", "user": "newuser1", "timestamp": RECENT_TS},
            {"action": "login", "user": "admin", "timestamp": RECENT_TS},
        ]
        result = _auto_detect_new_accounts(entries, grace_days=30)
        assert "newuser1" in result
        assert "admin" not in result

    def test_detects_event_code_4720(self):
        """Detects entries with event_code='4720'."""
        entries = [
            {"event_code": "4720", "user": "newuser2", "timestamp": RECENT_TS},
        ]
        result = _auto_detect_new_accounts(entries, grace_days=30)
        assert "newuser2" in result

    def test_grace_period_filters_old_accounts(self):
        """Accounts created beyond grace period are excluded."""
        entries = [
            {"action": "account_created", "user": "olduser", "timestamp": OLD_TS},
        ]
        result = _auto_detect_new_accounts(entries, grace_days=30)
        assert "olduser" not in result

    def test_entity_profiles_account_created_at(self):
        """Also checks entity profiles for account_created_at."""
        from nabla.baselines import EntityProfileStore, UserProfile
        import tempfile

        profile = UserProfile(entity_id="profileuser", account_created_at=RECENT_TS)
        store = EntityProfileStore.__new__(EntityProfileStore)
        store.path = "/tmp/nonexistent_profiles.json"
        store.users = {"profileuser": profile}
        store.hosts = {}
        store.ips = {}

        entries = []
        result = _auto_detect_new_accounts(entries, entity_profiles=store, grace_days=30)
        assert "profileuser" in result

    def test_empty_entries(self):
        """Empty entries returns empty dict."""
        result = _auto_detect_new_accounts([], grace_days=30)
        assert result == {}

    def test_no_user_skipped(self):
        """Entries without user field are skipped."""
        entries = [
            {"action": "account_created", "timestamp": RECENT_TS},
        ]
        result = _auto_detect_new_accounts(entries, grace_days=30)
        assert result == {}

    def test_no_timestamp_not_added(self):
        """Account creation without timestamp is not added (no date to check)."""
        entries = [
            {"action": "account_created", "user": "notsuser"},
        ]
        result = _auto_detect_new_accounts(entries, grace_days=30)
        # No timestamp → can't be added to created_accounts
        assert "notsuser" not in result
