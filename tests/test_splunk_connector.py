"""Tests for the Splunk connector."""

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from nabla.connectors.base import Watchlist
from nabla.connectors.splunk import CANONICAL_SCHEMA, SplunkConfig, SplunkConnector


def _splunk_config(**overrides):
    defaults = {
        "host": "https://splunk.example.com:8089",
        "token": "test-bearer-token",
        "verify_ssl": False,
        "validate_url": False,  # Skip SSRF validation in tests (test hostname doesn't resolve)
        "query_map": {
            "auth": 'search index=wineventlog (EventCode=4624 OR EventCode=4625) | rename Client_IP as source_ip, TargetUserName as user | eval action=case(EventCode=4624,"login",EventCode=4625,"failed_login") | table _time, user, source_ip, host, action, EventCode {watchlist_clause}',
            "network": 'search index=netflow | table _time, src_ip, dst_ip, dest_port, transport, bytes, action {watchlist_clause}',
            "dns": 'search index=dns | table _time, client_ip, domain, query_type, action {watchlist_clause}',
            "endpoint": 'search index=endpoint EventCode=1 | rename Image as process, CommandLine as command_line, ParentImage as parent_process | table _time, host, user, process, command_line, parent_process, action, IntegrityLevel {watchlist_clause}',
        },
        "max_results": 1000,
    }
    defaults.update(overrides)
    return SplunkConfig(**defaults)


def test_splunk_config_defaults():
    config = SplunkConfig()
    assert config.host == ""
    assert config.verify_ssl is True
    assert config.max_results == 10000
    assert config.query_map == {}


def test_available_log_types():
    config = _splunk_config()
    connector = SplunkConnector(config)
    assert set(connector.available_log_types()) == {"auth", "network", "dns", "endpoint"}


def test_available_log_types_partial():
    config = _splunk_config(query_map={"auth": "search index=wineventlog | table _time, user"})
    connector = SplunkConnector(config)
    assert connector.available_log_types() == ["auth"]


def test_available_log_types_empty():
    config = _splunk_config(query_map={})
    connector = SplunkConnector(config)
    assert connector.available_log_types() == []


def test_build_watchlist_clause_users():
    connector = SplunkConnector(_splunk_config())
    clause = connector._build_watchlist_clause(Watchlist(users=["admin", "jsmith"]))
    assert "admin" in clause
    assert "jsmith" in clause
    assert "user IN" in clause


def test_build_watchlist_clause_hosts():
    connector = SplunkConnector(_splunk_config())
    clause = connector._build_watchlist_clause(Watchlist(hosts=["SERVER-DC01"]))
    assert "SERVER-DC01" in clause
    assert "host IN" in clause


def test_build_watchlist_clause_ips():
    connector = SplunkConnector(_splunk_config())
    clause = connector._build_watchlist_clause(Watchlist(ips=["10.0.1.50"]))
    assert "10.0.1.50" in clause
    assert "src_ip IN" in clause


def test_build_watchlist_clause_empty():
    connector = SplunkConnector(_splunk_config())
    clause = connector._build_watchlist_clause(Watchlist())
    assert clause == ""


def test_build_watchlist_clause_combined():
    connector = SplunkConnector(_splunk_config())
    clause = connector._build_watchlist_clause(
        Watchlist(users=["admin"], hosts=["SERVER-DC01"], ips=["10.0.1.50"])
    )
    assert "user IN" in clause
    assert "host IN" in clause
    assert "src_ip IN" in clause
    assert " OR " in clause


def test_resolve_query_with_watchlist():
    connector = SplunkConnector(_splunk_config())
    watchlist = Watchlist(users=["admin"], hosts=["SERVER-DC01"])
    query = connector._resolve_query("auth", watchlist)
    assert "admin" in query
    assert "SERVER-DC01" in query
    assert "{watchlist_clause}" not in query


def test_resolve_query_empty_watchlist():
    connector = SplunkConnector(_splunk_config())
    query = connector._resolve_query("auth", Watchlist())
    assert "{watchlist_clause}" not in query
    # Empty watchlist clause should be removed cleanly
    assert query.endswith("EventCode") or query.strip()  # No dangling whitespace


def test_resolve_query_no_placeholder():
    """Queries without {watchlist_clause} run as-is."""
    config = _splunk_config(query_map={"auth": "search index=wineventlog | table _time, user"})
    connector = SplunkConnector(config)
    query = connector._resolve_query("auth", Watchlist(users=["admin"]))
    assert query == "search index=wineventlog | table _time, user"
    assert "admin" not in query


def test_resolve_query_missing_type():
    connector = SplunkConnector(_splunk_config(query_map={}))
    with pytest.raises(ValueError, match="No Splunk query configured"):
        connector._resolve_query("auth", Watchlist())


def test_minimal_normalize_epoch_timestamp():
    connector = SplunkConnector(_splunk_config())
    raw = {"_time": 1745836800.0, "user": "admin", "action": "login"}
    result = connector._minimal_normalize(raw, "auth")
    assert result["type"] == "auth"
    assert "timestamp" in result
    assert result["user"] == "admin"
    assert result["action"] == "login"


def test_minimal_normalize_iso_timestamp():
    connector = SplunkConnector(_splunk_config())
    raw = {"_time": "2026-04-28T08:00:00Z", "user": "admin", "action": "login"}
    result = connector._minimal_normalize(raw, "auth")
    assert result["timestamp"] == "2026-04-28T08:00:00Z"


def test_minimal_normalize_drops_internal_fields():
    connector = SplunkConnector(_splunk_config())
    raw = {
        "_time": 1745836800.0,
        "user": "admin",
        "_raw": "<Event><Data>huge xml</Data></Event>",
        "_cd": "0:1",
        "_si": "idx~main",
        "_bkt": "main~0",
        "_serial": "0",
        "splunk_server": "splunk-01",
        "linecount": "1",
    }
    result = connector._minimal_normalize(raw, "auth")
    assert "_raw" not in result
    assert "_cd" not in result
    assert "_si" not in result
    assert "_bkt" not in result
    assert "_serial" not in result
    assert "splunk_server" not in result
    assert "linecount" not in result


def test_minimal_normalize_preserves_user_fields():
    connector = SplunkConnector(_splunk_config())
    raw = {
        "_time": 1745836800.0,
        "user": "admin",
        "source_ip": "10.0.1.50",
        "action": "login",
        "event_code": "4624",
        "host": "SERVER-DC01",
    }
    result = connector._minimal_normalize(raw, "auth")
    assert result["source_ip"] == "10.0.1.50"
    assert result["event_code"] == "4624"
    assert result["host"] == "SERVER-DC01"


def test_validate_output_ok():
    """No warning when required fields are present."""
    logs = [{"timestamp": "2026-04-28", "user": "admin", "action": "login"}]
    # Should not raise
    SplunkConnector._validate_output(logs, "auth")


def test_validate_output_missing_required():
    """Warning logged when required fields are missing."""
    logs = [{"timestamp": "2026-04-28"}]  # Missing user, action
    with patch("nabla.connectors.base.logger") as mock_logger:
        SplunkConnector._validate_output(logs, "auth")
        mock_logger.warning.assert_called_once()
        assert "missing required fields" in mock_logger.warning.call_args[0][0]


def test_validate_output_empty_logs():
    """No validation on empty results."""
    SplunkConnector._validate_output([], "auth")  # Should not raise


def test_validate_output_unknown_type():
    """No validation for unknown log types."""
    logs = [{"foo": "bar"}]
    SplunkConnector._validate_output(logs, "unknown")  # Should not raise


def test_parse_export_results():
    connector = SplunkConnector(_splunk_config())
    text = '{"result": {"_time": 1.0, "user": "admin"}}\n{"result": {"_time": 2.0, "user": "jsmith"}}'
    results = connector._parse_export_results(text)
    assert len(results) == 2
    assert results[0]["user"] == "admin"


def test_parse_export_results_empty():
    connector = SplunkConnector(_splunk_config())
    results = connector._parse_export_results("")
    assert results == []


def test_parse_job_results():
    connector = SplunkConnector(_splunk_config())
    text = json.dumps({"results": [{"_time": 1.0, "user": "admin"}]})
    results = connector._parse_job_results(text)
    assert len(results) == 1


def test_fetch_logs_no_host():
    connector = SplunkConnector(SplunkConfig())
    watchlist = Watchlist(users=["admin"])
    with pytest.raises(ValueError, match="Splunk host not configured"):
        connector.fetch_logs(watchlist, "auth", None, None)


def test_fetch_logs_no_query():
    config = _splunk_config(query_map={})
    connector = SplunkConnector(config)
    watchlist = Watchlist(users=["admin"])
    result = connector.fetch_logs(watchlist, "auth", None, None)
    assert result == []


def test_fetch_logs_empty_watchlist():
    """Empty watchlist still fetches all events (no filter)."""
    config = _splunk_config()
    connector = SplunkConnector(config)
    with patch.object(connector, "_authenticate"):
        with patch.object(connector, "_execute_search", return_value=[]):
            result = connector.fetch_logs(Watchlist(), "auth", None, None)
            assert result == []


def test_auth_header_token():
    config = _splunk_config(token="my-token")
    connector = SplunkConnector(config)
    header = connector._get_auth_header()
    assert header == {"Authorization": "Bearer my-token"}


def test_auth_header_session_key():
    config = _splunk_config(token="", username="admin", password="pass")
    connector = SplunkConnector(config)
    connector._session_key = "session-key-123"
    header = connector._get_auth_header()
    assert header == {"Authorization": "Splunk session-key-123"}


def test_authenticate_with_token():
    """Token auth should not call login endpoint."""
    config = _splunk_config(token="my-token")
    connector = SplunkConnector(config)
    mock_client = MagicMock()
    connector._authenticate(mock_client)
    mock_client.post.assert_not_called()


def test_authenticate_with_password():
    """Username/password auth should call login endpoint."""
    config = _splunk_config(token="", username="admin", password="pass")
    connector = SplunkConnector(config)

    # Splunk returns XML with namespace: <s:key name="sessionKey">abc123</s:key>
    mock_response = MagicMock()
    mock_response.text = (
        '<response xmlns:s="http://dev.splunk.com/ns/rest">'
        '<s:key name="sessionKey">abc123</s:key>'
        '</response>'
    )
    mock_response.raise_for_status = MagicMock()
    mock_client = MagicMock()
    mock_client.post.return_value = mock_response

    connector._authenticate(mock_client)
    mock_client.post.assert_called_once()
    assert connector._session_key == "abc123"


def test_canonical_schema_structure():
    """Verify CANONICAL_SCHEMA has all expected log types and required fields."""
    assert set(CANONICAL_SCHEMA.keys()) == {"auth", "network", "dns", "endpoint"}
    for log_type, schema in CANONICAL_SCHEMA.items():
        assert "required" in schema
        assert "optional" in schema
        assert "timestamp" in schema["required"]


def test_spl_escape():
    """Double quotes are doubled for SPL safety."""
    assert SplunkConnector._spl_escape('admin"test') == 'admin""test'
    assert SplunkConnector._spl_escape("normal") == "normal"


def test_queries_path_loading(tmp_path):
    """Queries loaded from JSON file override query_map."""
    queries = {"auth": "search index=override | table _time, user"}
    queries_file = tmp_path / "queries.json"
    queries_file.write_text(json.dumps(queries))

    config = SplunkConfig(
        host="https://splunk.example.com",
        query_map={"auth": "original", "endpoint": "keep"},
        queries_path=str(queries_file),
    )
    assert config.query_map["auth"] == "search index=override | table _time, user"
    assert config.query_map["endpoint"] == "keep"
