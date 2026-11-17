"""Tests for connector base, registry, and synthetic connector."""

import json
import os
import tempfile

from nabla.connectors.base import ConnectorConfig, Watchlist
from nabla.connectors.synthetic import SyntheticConnector
from nabla.connectors.sumologic import SumoConfig, SumoLogicConnector


def test_watchlist_empty():
    w = Watchlist()
    assert w.is_empty is True


def test_watchlist_not_empty():
    w = Watchlist(users=["admin"])
    assert w.is_empty is False


def test_watchlist_from_dict():
    data = {"users": ["admin", "jsmith"], "hosts": ["SERVER-DC01"], "ips": ["10.0.1.50"]}
    w = Watchlist.from_dict(data)
    assert w.users == ["admin", "jsmith"]
    assert w.hosts == ["SERVER-DC01"]
    assert w.ips == ["10.0.1.50"]


def test_watchlist_from_dict_empty():
    w = Watchlist.from_dict({})
    assert w.is_empty is True


def test_synthetic_connector_fetch():
    config = ConnectorConfig()
    connector = SyntheticConnector(config)
    connector.set_count(5)
    logs = connector.fetch_logs(Watchlist(), "auth", None, None)
    assert isinstance(logs, list)
    assert len(logs) > 0
    assert all(log["type"] == "auth" for log in logs)


def test_synthetic_connector_all_types():
    config = ConnectorConfig()
    connector = SyntheticConnector(config)
    connector.set_count(3)
    for log_type in connector.available_log_types():
        logs = connector.fetch_logs(Watchlist(), log_type, None, None)
        assert isinstance(logs, list)


def test_synthetic_connector_ignores_watchlist():
    """Synthetic connector ignores watchlist — generates all logs regardless."""
    config = ConnectorConfig()
    connector = SyntheticConnector(config)
    connector.set_count(5)
    empty_watchlist = Watchlist()
    logs = connector.fetch_logs(empty_watchlist, "auth", None, None)
    assert len(logs) > 0


def test_connector_config_defaults():
    config = ConnectorConfig()
    assert config.max_results == 10000
    assert "auth" in config.log_types


# --- SumoLogic connector tests ---

def test_sumologic_config_defaults():
    config = SumoConfig()
    assert config.host == ""
    assert config.access_id == ""
    assert config.access_key == ""
    assert config.verify_ssl is True
    assert config.validate_url is True
    assert config.max_results == 10_000
    assert config.poll_interval == 5.0
    assert config.poll_timeout == 300.0


def test_sumologic_config_from_file():
    """Credentials loaded from file with correct permissions."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"access_id": "testId", "access_key": "testKey"}, f)
        f.flush()
        os.chmod(f.name, 0o600)
        path = f.name

    try:
        config = SumoConfig(credentials_path=path)
        assert config.access_id == "testId"
        assert config.access_key == "testKey"
    finally:
        os.unlink(path)


def test_sumologic_config_from_file_permissive_rejected():
    """Credentials file with permissive permissions is rejected."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"access_id": "testId", "access_key": "testKey"}, f)
        f.flush()
        os.chmod(f.name, 0o644)  # World-readable
        path = f.name

    try:
        config = SumoConfig(credentials_path=path)
        assert config.access_id == ""  # Not loaded
        assert config.access_key == ""
    finally:
        os.unlink(path)


def test_sumologic_config_queries_from_file():
    """Queries loaded from JSON file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"auth": "query for auth", "dns": "query for dns"}, f)
        f.flush()
        path = f.name

    try:
        config = SumoConfig(queries_path=path)
        assert config.query_map["auth"] == "query for auth"
        assert config.query_map["dns"] == "query for dns"
    finally:
        os.unlink(path)


def test_sumologic_watchlist_clause_users():
    config = SumoConfig()
    connector = SumoLogicConnector(config)
    watchlist = Watchlist(users=["admin", "jsmith"])
    clause = connector._build_watchlist_clause(watchlist)
    # Single-type clause is wrapped in parens
    assert 'user IN ("admin", "jsmith")' in clause


def test_sumologic_watchlist_clause_hosts():
    config = SumoConfig()
    connector = SumoLogicConnector(config)
    watchlist = Watchlist(hosts=["DC01", "WEB01"])
    clause = connector._build_watchlist_clause(watchlist)
    assert '_sourceHost IN ("DC01", "WEB01")' in clause


def test_sumologic_watchlist_clause_ips():
    config = SumoConfig()
    connector = SumoLogicConnector(config)
    watchlist = Watchlist(ips=["10.0.1.50"])
    clause = connector._build_watchlist_clause(watchlist)
    assert '_sourceIP IN ("10.0.1.50")' in clause


def test_sumologic_watchlist_clause_combined():
    config = SumoConfig()
    connector = SumoLogicConnector(config)
    watchlist = Watchlist(users=["admin"], hosts=["DC01"], ips=["10.0.1.50"])
    clause = connector._build_watchlist_clause(watchlist)
    assert "user IN" in clause
    assert "_sourceHost IN" in clause
    assert "_sourceIP IN" in clause
    assert " OR " in clause


def test_sumologic_watchlist_clause_empty():
    config = SumoConfig()
    connector = SumoLogicConnector(config)
    clause = connector._build_watchlist_clause(Watchlist())
    assert clause == ""


def test_sumologic_watchlist_escape_quotes():
    """Double quotes in entity values are escaped."""
    config = SumoConfig()
    connector = SumoLogicConnector(config)
    watchlist = Watchlist(users=['user"with"quotes'])
    clause = connector._build_watchlist_clause(watchlist)
    assert 'user""with""quotes' in clause


def test_sumologic_resolve_query():
    config = SumoConfig(query_map={"auth": "index=auth {watchlist_clause}"})
    connector = SumoLogicConnector(config)
    query = connector._resolve_query("auth", Watchlist(users=["admin"]))
    assert 'user IN ("admin")' in query


def test_sumologic_resolve_query_no_placeholder():
    """Query without {watchlist_clause} runs as-is."""
    config = SumoConfig(query_map={"auth": "index=auth user=admin"})
    connector = SumoLogicConnector(config)
    query = connector._resolve_query("auth", Watchlist(users=["admin"]))
    assert query == "index=auth user=admin"


def test_sumologic_resolve_query_missing_type():
    config = SumoConfig(query_map={"auth": "some query"})
    connector = SumoLogicConnector(config)
    try:
        connector._resolve_query("dns", Watchlist())
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "dns" in str(e)


def test_sumologic_normalize_messagetime():
    """_messagetime (epoch ms) → ISO timestamp."""
    raw = {"_messagetime": 1704067200000}  # 2024-01-01T00:00:00 UTC
    result = SumoLogicConnector._minimal_normalize(raw, "auth")
    assert "2024-01-01" in result["timestamp"]
    assert result["type"] == "auth"


def test_sumologic_normalize_source_host():
    """_sourceHost maps to host."""
    raw = {"_messagetime": 1704067200000, "_sourceHost": "DC01"}
    result = SumoLogicConnector._minimal_normalize(raw, "auth")
    assert result["host"] == "DC01"


def test_sumologic_normalize_source_category():
    """_sourceCategory maps to source."""
    raw = {"_messagetime": 1704067200000, "_sourceCategory": "auth_logs"}
    result = SumoLogicConnector._minimal_normalize(raw, "auth")
    assert result["source"] == "auth_logs"


def test_sumologic_normalize_drops_internal_fields():
    """SumoLogic internal fields are dropped."""
    raw = {
        "_messagetime": 1704067200000,
        "_messageid": "12345",
        "_sourceid": "67890",
        "_receipttime": "1704067201000",
        "_collectorId": "999",
        "_blockid": "-1",
        "_size": "549",
        "_format": "plain",
        "_messagecount": "100",
        "_raw": "raw log line",
        "_collector": "local",
        "_source": "service",
        "user": "admin",
    }
    result = SumoLogicConnector._minimal_normalize(raw, "auth")
    assert "_messageid" not in result
    assert "_sourceid" not in result
    assert "_receipttime" not in result
    assert "_collectorId" not in result
    assert "_blockid" not in result
    assert "_size" not in result
    assert "_format" not in result
    assert "_messagecount" not in result
    assert "_raw" not in result
    assert "_collector" not in result
    assert "_source" not in result
    assert result["user"] == "admin"


def test_sumologic_normalize_preserves_canonical_fields():
    """User-provided canonical fields are preserved."""
    raw = {
        "_messagetime": 1704067200000,
        "user": "admin",
        "action": "login",
        "source_ip": "10.0.1.50",
    }
    result = SumoLogicConnector._minimal_normalize(raw, "auth")
    assert result["user"] == "admin"
    assert result["action"] == "login"
    assert result["source_ip"] == "10.0.1.50"


def test_sumologic_available_log_types():
    config = SumoConfig(query_map={"auth": "query", "dns": "query", "endpoint": ""})
    connector = SumoLogicConnector(config)
    types = connector.available_log_types()
    assert "auth" in types
    assert "dns" in types
    assert "endpoint" not in types  # Empty query not counted


def test_sumologic_no_host_raises():
    """fetch_logs raises ValueError when host not configured."""
    config = SumoConfig(access_id="id", access_key="key")
    connector = SumoLogicConnector(config)
    try:
        connector.fetch_logs(Watchlist(), "auth", None, None)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "host" in str(e).lower()


def test_sumologic_no_credentials_raises():
    """fetch_logs raises ValueError when access_id/access_key not configured."""
    config = SumoConfig(host="https://api.sumologic.com/api")
    connector = SumoLogicConnector(config)
    try:
        connector.fetch_logs(Watchlist(), "auth", None, None)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "access_id" in str(e)


def test_sumologic_no_query_skips():
    """fetch_logs returns empty list when no query configured for log type."""
    config = SumoConfig(
        host="https://api.sumologic.com/api",
        access_id="id",
        access_key="key",
        validate_url=False,
    )
    connector = SumoLogicConnector(config)
    logs = connector.fetch_logs(Watchlist(), "auth", None, None)
    assert logs == []


def test_sumologic_validate_output_missing_required():
    """_validate_output logs warning for missing required fields."""
    # This just verifies the method doesn't crash — the warning is logged
    # not returned. We can't easily test log output, but we can verify
    # it doesn't raise.
    logs = [{"timestamp": "2024-01-01T00:00:00+00:00"}]  # Missing user, action
    SumoLogicConnector._validate_output(logs, "auth")  # Should not raise


def test_sumologic_validate_output_empty():
    """_validate_output handles empty log list."""
    SumoLogicConnector._validate_output([], "auth")  # Should not raise


def test_sumologic_escape_query_value():
    assert SumoLogicConnector._escape_query_value('simple') == "simple"
    assert SumoLogicConnector._escape_query_value('val"ue') == 'val""ue'
    assert SumoLogicConnector._escape_query_value('"quoted"') == '""quoted""'


def test_sumologic_normalize_timestamp_string():
    """String timestamp is preserved as-is."""
    raw = {"timestamp": "2024-01-01T12:00:00Z", "user": "admin"}
    result = SumoLogicConnector._minimal_normalize(raw, "auth")
    assert result["timestamp"] == "2024-01-01T12:00:00Z"


def test_sumologic_normalize_no_timestamp():
    """Missing timestamp defaults to current time."""
    raw = {"user": "admin"}
    result = SumoLogicConnector._minimal_normalize(raw, "auth")
    assert "timestamp" in result
    assert "202" in result["timestamp"]  # Starts with 202x


def test_sumologic_config_nonexistent_credentials_path():
    """Non-existent credentials path is silently skipped."""
    config = SumoConfig(credentials_path="/nonexistent/path/creds.json")
    assert config.access_id == ""
    assert config.access_key == ""


def test_sumologic_config_nonexistent_queries_path():
    """Non-existent queries path is silently skipped."""
    config = SumoConfig(queries_path="/nonexistent/path/queries.json")
    assert len(config.query_map) == 0


def test_sumologic_normalize_windows_event_4624():
    """Windows Event 4624 (successful logon) normalizes to canonical auth fields."""
    raw = {
        "_raw": json.dumps({
            "event_id": {"id": 4624},
            "system_time": "2026-04-30T19:46:55.789Z",
            "computer": "WIN-DC01.corp.example",
            "event_data": {
                "TargetUserName": "admin",
                "TargetDomainName": "QFUNCTION",
                "IpAddress": "10.0.1.50",
                "LogonType": "10",
            },
            "keywords": ["Audit Success"],
            "message": "An account was successfully logged on.",
        }),
        "_messagetime": 1777578015000,
        "_sourceHost": "WIN-DC01",
    }
    result = SumoLogicConnector._minimal_normalize(raw, "auth")
    assert result["type"] == "auth"
    assert result["timestamp"] == "2026-04-30T19:46:55.789Z"
    assert result["host"] == "WIN-DC01"
    assert result["user"] == "admin"
    assert result["source_ip"] == "10.0.1.50"
    assert result["action"] == "login"
    assert result["event_code"] == "4624"
    assert result["logon_type"] == "10"
    assert result["result"] == "Audit Success"


def test_sumologic_normalize_windows_event_4625():
    """Windows Event 4625 (failed logon) normalizes to login_failed."""
    raw = {
        "_raw": json.dumps({
            "event_id": {"id": 4625},
            "system_time": "2026-04-30T20:00:00.000Z",
            "computer": "DC01.corp.local",
            "event_data": {
                "TargetUserName": "attacker",
                "IpAddress": "192.168.1.100",
                "LogonType": "3",
            },
            "keywords": ["Audit Failure"],
            "message": "An account failed to log on.",
        }),
        "_messagetime": 1777578000000,
    }
    result = SumoLogicConnector._minimal_normalize(raw, "auth")
    assert result["action"] == "login_failed"
    assert result["user"] == "attacker"
    assert result["source_ip"] == "192.168.1.100"
    assert result["result"] == "Audit Failure"


def test_sumologic_normalize_windows_event_machine_account():
    """Machine accounts (ending in $) are excluded from user field."""
    raw = {
        "_raw": json.dumps({
            "event_id": {"id": 4634},
            "system_time": "2026-04-30T19:00:00.000Z",
            "computer": "WIN-DC01.corp.example",
            "event_data": {
                "TargetUserName": "WIN-DC01$",
                "TargetDomainName": "QFUNCTION",
            },
            "keywords": ["Audit Success"],
        }),
        "_messagetime": 1777578000000,
    }
    result = SumoLogicConnector._minimal_normalize(raw, "auth")
    assert "user" not in result  # Machine account excluded


def test_sumologic_normalize_windows_event_strips_domain():
    """Domain prefix is stripped from user (QFUNCTION\\admin → admin)."""
    raw = {
        "_raw": json.dumps({
            "event_id": {"id": 4624},
            "system_time": "2026-04-30T19:00:00.000Z",
            "computer": "DC01",
            "event_data": {
                "TargetUserName": "QFUNCTION\\jsmith",
                "IpAddress": "10.0.1.50",
            },
            "keywords": ["Audit Success"],
        }),
        "_messagetime": 1777578000000,
    }
    result = SumoLogicConnector._minimal_normalize(raw, "auth")
    assert result["user"] == "jsmith"


def test_sumologic_normalize_non_json_raw_fallback():
    """Non-JSON _raw falls back to field-by-field mapping."""
    raw = {
        "_raw": "Apr 30 19:40:49 some log line",
        "_messagetime": 1777578049000,
        "_sourceHost": "myhost",
        "_sourceCategory": "linux/auth",
        "user": "admin",
        "action": "login",
    }
    result = SumoLogicConnector._minimal_normalize(raw, "auth")
    assert result["type"] == "auth"
    assert "2026-04-30" in result["timestamp"]
    assert result["host"] == "myhost"
    assert result["source"] == "linux/auth"
    assert result["user"] == "admin"


def test_sumologic_normalize_endpoint_sysmon():
    """Sysmon endpoint event extracts process info."""
    raw = {
        "_raw": json.dumps({
            "event_id": {"id": 1},
            "system_time": "2026-04-30T19:00:00.000Z",
            "computer": "WIN-DC01",
            "event_data": {
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "User": "DOMAIN\\admin",
            },
        }),
        "_messagetime": 1777578000000,
    }
    result = SumoLogicConnector._minimal_normalize(raw, "endpoint")
    assert result["type"] == "endpoint"
    assert result["process"] == "cmd.exe"
    assert result["command_line"] == "cmd.exe /c whoami"
    assert result["parent_process"] == "explorer.exe"


# --- Linux Sysmon XML normalization tests ---

_LINUX_SYSMON_EVENT1 = (
    'Apr 30 19:51:24 ip-172-31-41-107 sysmon[16983]: '
    '<Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/>'
    '<EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode>'
    '<Keywords>0x8000000000000000</Keywords>'
    '<TimeCreated SystemTime="2026-04-30T19:51:24.560903000Z"/>'
    '<EventRecordID>3277</EventRecordID><Correlation/>'
    '<Execution ProcessID="16983" ThreadID="16983"/>'
    '<Channel>Linux-Sysmon/Operational</Channel>'
    '<Computer>ip-172-31-41-107.ec2.internal</Computer>'
    '<Security UserId="0"/></System>'
    '<EventData>'
    '<Data Name="RuleName">-</Data>'
    '<Data Name="UtcTime">2026-04-30 19:51:24.512</Data>'
    '<Data Name="ProcessGuid">{ec27717d-b2bc-69f3-0580-ceec0a560000}</Data>'
    '<Data Name="ProcessId">19785</Data>'
    '<Data Name="Image">/usr/libexec/nm-cloud-setup</Data>'
    '<Data Name="CommandLine">/usr/libexec/nm-cloud-setup</Data>'
    '<Data Name="User">root</Data>'
    '<Data Name="IntegrityLevel">no level</Data>'
    '<Data Name="ParentProcessGuid">{00000000-0000-0000-0000-000000000000}</Data>'
    '<Data Name="ParentProcessId">1</Data>'
    '<Data Name="ParentImage">-</Data>'
    '<Data Name="ParentCommandLine">-</Data>'
    '<Data Name="ParentUser">-</Data>'
    '</EventData></Event>'
)

_LINUX_SYSMON_EVENT5 = (
    'Apr 30 19:57:37 ip-172-31-41-107 sysmon[16983]: '
    '<Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/>'
    '<EventID>5</EventID><Version>3</Version><Level>4</Level><Task>5</Task><Opcode>0</Opcode>'
    '<Keywords>0x8000000000000000</Keywords>'
    '<TimeCreated SystemTime="2026-04-30T19:57:37.447732000Z"/>'
    '<EventRecordID>3334</EventRecordID><Correlation/>'
    '<Execution ProcessID="16983" ThreadID="16983"/>'
    '<Channel>Linux-Sysmon/Operational</Channel>'
    '<Computer>ip-172-31-41-107.ec2.internal</Computer>'
    '<Security UserId="0"/></System>'
    '<EventData>'
    '<Data Name="RuleName">-</Data>'
    '<Data Name="UtcTime">2026-04-30 19:57:37.451</Data>'
    '<Data Name="ProcessGuid">{ec27717d-73a9-69f3-b103-4482d5550000}</Data>'
    '<Data Name="ProcessId">17139</Data>'
    '<Data Name="Image">/usr/bin/gpg-agent</Data>'
    '<Data Name="User">root</Data>'
    '</EventData></Event>'
)


def test_sumologic_normalize_linux_sysmon_event1():
    """Linux Sysmon Event 1 (Process Create) normalizes to endpoint fields."""
    raw = {"_raw": _LINUX_SYSMON_EVENT1, "_messagetime": 1777578084000}
    result = SumoLogicConnector._minimal_normalize(raw, "endpoint")
    assert result["type"] == "endpoint"
    assert result["event_code"] == "1"
    assert result["action"] == "process_create"
    assert result["timestamp"] == "2026-04-30T19:51:24.560903000Z"
    assert result["host"] == "ip-172-31-41-107"
    assert result["process"] == "nm-cloud-setup"
    assert result["command_line"] == "/usr/libexec/nm-cloud-setup"
    assert result["user"] == "root"


def test_sumologic_normalize_linux_sysmon_event5():
    """Linux Sysmon Event 5 (Process Terminate) normalizes correctly."""
    raw = {"_raw": _LINUX_SYSMON_EVENT5, "_messagetime": 1777578157000}
    result = SumoLogicConnector._minimal_normalize(raw, "endpoint")
    assert result["type"] == "endpoint"
    assert result["event_code"] == "5"
    assert result["action"] == "process_terminate"
    assert result["host"] == "ip-172-31-41-107"
    assert result["process"] == "gpg-agent"
    assert result["user"] == "root"


def test_sumologic_normalize_linux_sysmon_strips_domain():
    """Computer field with domain suffix gets stripped."""
    xml = (
        '<Event><System><Provider Name="Linux-Sysmon"/>'
        '<EventID>1</EventID>'
        '<TimeCreated SystemTime="2026-04-30T19:00:00.000Z"/>'
        '<Computer>myhost.ec2.internal</Computer>'
        '</System>'
        '<EventData>'
        '<Data Name="Image">/usr/bin/ls</Data>'
        '<Data Name="User">admin</Data>'
        '</EventData></Event>'
    )
    raw = {"_raw": xml, "_messagetime": 1777578000000}
    result = SumoLogicConnector._minimal_normalize(raw, "endpoint")
    assert result["host"] == "myhost"


def test_sumologic_normalize_linux_sysmon_no_integrity_level():
    """'no level' integrity level is excluded."""
    raw = {"_raw": _LINUX_SYSMON_EVENT1, "_messagetime": 1777578084000}
    result = SumoLogicConnector._minimal_normalize(raw, "endpoint")
    assert "integrity_level" not in result
