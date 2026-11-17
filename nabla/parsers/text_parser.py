"""Syslog-style plain text log parser.

Parses common syslog formats using regex. Best-effort — syslog format
varies widely across implementations. Handles:
- RFC 3164 (BSD syslog): "Jan 15 10:00:00 host process[pid]: message"
- RFC 5424 (structured): "1 2024-01-15T10:00:00Z host app proc pid msgid - data"
- Simple key-value: "timestamp=2024-01-01 user=alice action=login_success"
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from nabla.log import get_logger

logger = get_logger("parsers.text")

# RFC 3164: "Jan 15 10:00:00 hostname process[pid]: message"
RFC3164_RE = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)"
)

# RFC 5424: "1 2024-01-15T10:00:00.000Z hostname app proc pid msgid - data"
RFC5424_RE = re.compile(
    r"(?P<priority>\d+)\s+"
    r"(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<proc>\S+)\s+"
    r"(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured>\S+)\s*"
    r"(?P<message>.*)"
)

# Key-value: "key=value key2=value2 ..."
KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')

# Common auth patterns in syslog messages
AUTH_PATTERNS = [
    (re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)", re.I),
     {"action": "login_failure", "user_field": 1, "source_ip_field": 2}),
    (re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)", re.I),
     {"action": "login_success", "user_field": 1, "source_ip_field": 2}),
    (re.compile(r"session opened for user (\S+)", re.I),
     {"action": "session_open", "user_field": 1}),
    (re.compile(r"session closed for user (\S+)", re.I),
     {"action": "session_close", "user_field": 1}),
    (re.compile(r"disconnected from (\S+)", re.I),
     {"action": "disconnect", "source_ip_field": 1}),
]


def _parse_rfc3164_timestamp(ts_str: str, year: int | None = None) -> str:
    """Convert RFC 3164 timestamp to ISO format.

    Args:
        ts_str: Timestamp like "Jan 15 10:00:00".
        year: Year to use (defaults to current year).

    Returns:
        ISO format timestamp string.
    """
    if year is None:
        year = datetime.now().year
    try:
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        dt = dt.replace(year=year, tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        return ts_str


def _parse_auth_message(message: str) -> dict[str, str]:
    """Extract auth-related fields from a syslog message.

    Args:
        message: The syslog message text.

    Returns:
        Dict with extracted fields (action, user, source_ip, etc.).
    """
    result: dict[str, str] = {}
    for pattern, fields in AUTH_PATTERNS:
        match = pattern.search(message)
        if match:
            result["action"] = fields["action"]
            if "user_field" in fields:
                result["user"] = match.group(fields["user_field"])
            if "source_ip_field" in fields:
                result["source_ip"] = match.group(fields["source_ip_field"])
            break
    return result


def _parse_kv_message(message: str) -> dict[str, str]:
    """Extract key-value pairs from a message.

    Args:
        message: Message containing key=value pairs.

    Returns:
        Dict of extracted key-value pairs.
    """
    result: dict[str, str] = {}
    for match in KV_RE.finditer(message):
        key, value = match.group(1), match.group(2)
        # Strip surrounding quotes
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        result[key] = value
    return result


def parse_text(
    path: Path,
    max_entries: int = 100_000,
    encoding: str = "utf-8",
) -> list[dict]:
    """Parse a syslog-style plain text log file.

    Tries RFC 5424 first, then RFC 3164, then key-value format.
    Each line becomes one dict.

    Args:
        path: Path to the text log file.
        max_entries: Maximum number of entries to parse.
        encoding: File encoding.

    Returns:
        List of dicts (one per log line).

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If no lines could be parsed.
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    entries: list[dict] = []
    current_year = datetime.now().year

    with open(path, "r", encoding=encoding, errors="replace") as f:
        for i, line in enumerate(f, 1):
            if len(entries) >= max_entries:
                logger.warning(
                    "Text file exceeded %d entries, truncating at line %d.",
                    max_entries, i,
                )
                break

            line = line.strip()
            if not line:
                continue

            entry = _parse_line(line, current_year)
            if entry:
                entries.append(entry)

    if not entries:
        raise ValueError(f"Could not parse any log entries from: {path}")

    logger.info("Parsed %d entries from text file: %s", len(entries), path)
    return entries


def _parse_line(line: str, current_year: int) -> dict | None:
    """Parse a single log line into a dict.

    Args:
        line: A single line of text.
        current_year: Year to use for RFC 3164 timestamps.

    Returns:
        Parsed dict, or None if the line couldn't be parsed.
    """
    # Try RFC 5424 first
    match = RFC5424_RE.match(line)
    if match:
        entry = {
            "timestamp": match.group("timestamp"),
            "host": match.group("host"),
            "process": match.group("app"),
            "pid": match.group("pid"),
            "message": match.group("message"),
        }
        # Try to extract KV pairs from message
        kv = _parse_kv_message(entry["message"])
        entry.update(kv)
        # Try auth pattern extraction
        auth = _parse_auth_message(entry["message"])
        entry.update(auth)
        return entry

    # Try RFC 3164
    match = RFC3164_RE.match(line)
    if match:
        entry = {
            "timestamp": _parse_rfc3164_timestamp(match.group("timestamp"), current_year),
            "host": match.group("host"),
            "process": match.group("process"),
            "message": match.group("message"),
        }
        if match.group("pid"):
            entry["pid"] = match.group("pid")
        # Try auth pattern extraction
        auth = _parse_auth_message(entry["message"])
        entry.update(auth)
        return entry

    # Try key-value format (entire line is key=value pairs)
    kv = _parse_kv_message(line)
    if kv:
        return kv

    # Fallback: store entire line as message
    return {"message": line}
