"""Log file parsers — parse CSV, JSON, JSONL, XML, and syslog text files.

Public API:
- parse_file(path, format_hint, max_entries) → list[dict]  (raw column names)
- normalize_entries(raw_entries, log_type, column_map) → list[dict]  (canonical schema)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from nabla.log import get_logger
from nabla.parsers.field_map import (
    auto_detect_fields,
    apply_column_map,
    infer_log_type,
)

logger = get_logger("parsers")

# Supported format names
FORMATS = ("csv", "json", "jsonl", "xml", "text", "syslog")


def detect_format(path: Path) -> str:
    """Detect file format from extension and content heuristics.

    Args:
        path: Path to the log file.

    Returns:
        Format name: "csv", "json", "jsonl", "xml", or "text".
    """
    suffix = path.suffix.lower()

    # Extension-based detection — only unambiguous extensions return immediately.
    # Ambiguous extensions (.txt, .log, .syslog) fall through to content heuristics
    # because these files may contain XML, JSON, CSV, or syslog text.
    unambiguous_ext = {
        ".csv": "csv",
        ".tsv": "csv",
        ".json": "json",
        ".jsonl": "jsonl",
        ".xml": "xml",
    }

    if suffix in unambiguous_ext:
        return unambiguous_ext[suffix]

    # Content heuristics — read first 1KB
    try:
        content = path.read_text(encoding="utf-8", errors="replace")[:1024].strip()
    except (OSError, IOError):
        return "text"

    if content.startswith("<?xml") or content.startswith("<Event") or content.startswith("<Events"):
        return "xml"
    if content.startswith("[") or content.startswith("{"):
        # Could be JSON array or JSONL
        if content.startswith("["):
            return "json"
        return "jsonl"

    return "text"


def parse_file(
    path: str | Path,
    format_hint: str | None = None,
    max_entries: int = 100_000,
    encoding: str = "utf-8",
) -> list[dict]:
    """Parse a log file into a list of raw dicts.

    Dispatches to the appropriate format-specific parser.
    Auto-detects format if not specified.

    Args:
        path: Path to the log file.
        format_hint: Format name ("csv", "json", "jsonl", "xml", "text").
            If None, auto-detected from file extension and content.
        max_entries: Maximum number of entries to parse.
        encoding: File encoding.

    Returns:
        List of dicts with raw column names from the file.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the format is unknown or parsing fails.
    """
    path = Path(path).resolve()

    # Path traversal protection — reject paths outside allowed directories.
    # Allowed: /data (Docker volume), /tmp, and system temp directories.
    from nabla.utils import get_allowed_dirs, path_is_allowed

    _ALLOWED_DIRS = get_allowed_dirs()

    if not path_is_allowed(path):
        # Only enforce path restriction for files that actually exist.
        # Non-existent paths will fail with FileNotFoundError naturally.
        if path.exists():
            raise ValueError(
                f"File path '{path}' is outside allowed directories. "
                f"Log files must be under /data or /tmp."
            )

    # Reject symlinks that point outside allowed directories
    if path.is_symlink() and path.exists():
        target = path.resolve()
        if not path_is_allowed(target):
            raise ValueError(
                f"Symlink '{path}' points to '{target}' which is outside allowed directories."
            )

    if format_hint is not None:
        fmt = format_hint.lower()
        if fmt == "syslog":
            fmt = "text"
        if fmt not in FORMATS:
            raise ValueError(
                f"Unknown format: {format_hint!r}. "
                f"Supported formats: {', '.join(FORMATS)}"
            )
    else:
        fmt = detect_format(path)

    logger.info("Parsing file %s (format=%s)", path, fmt)

    if fmt == "csv":
        from nabla.parsers.csv_parser import parse_csv
        return parse_csv(path, max_entries=max_entries, encoding=encoding)
    elif fmt in ("json", "jsonl"):
        from nabla.parsers.json_parser import parse_json
        return parse_json(path, max_entries=max_entries, encoding=encoding)
    elif fmt == "xml":
        from nabla.parsers.xml_parser import parse_xml
        return parse_xml(path, max_entries=max_entries, encoding=encoding)
    elif fmt == "text":
        from nabla.parsers.text_parser import parse_text
        return parse_text(path, max_entries=max_entries, encoding=encoding)
    else:
        raise ValueError(f"Unsupported format: {fmt}")


def normalize_entries(
    raw_entries: list[dict],
    log_type: str | None = None,
    column_map: dict[str, str] | None = None,
) -> list[dict]:
    """Normalize raw log entries to Nabla's canonical schema.

    Applies auto-detection of field names, then user-provided column
    mapping overrides, then sets the log type.

    Args:
        raw_entries: List of dicts with raw column names.
        log_type: Log type ("auth", "network", "dns", "endpoint").
            If None, inferred from field names.
        column_map: User-provided mapping (canonical → raw column name).
            Overrides auto-detected mappings.

    Returns:
        List of dicts in Nabla's canonical schema.
    """
    if not raw_entries:
        return []

    # Auto-detect field mapping from ALL column names across entries.
    # Sysmon XML has different fields per event type (e.g. EventID 1 has
    # CommandLine, EventID 11 has TargetFilename). Using only the first
    # entry's columns misses fields from other event types.
    all_columns: set[str] = set()
    for entry in raw_entries:
        all_columns.update(entry.keys())
    auto_map = auto_detect_fields(list(all_columns))

    # Apply user overrides
    if column_map:
        field_map = apply_column_map(auto_map, column_map)
    else:
        field_map = auto_map

    # Invert the mapping: raw column name → canonical field name
    raw_to_canonical: dict[str, str] = {}
    for canonical, raw_col in field_map.items():
        raw_to_canonical[raw_col] = canonical

    # Normalize each entry
    normalized: list[dict] = []
    for raw in raw_entries:
        entry: dict = {}

        # Map raw fields to canonical names
        for raw_key, raw_value in raw.items():
            canonical = raw_to_canonical.get(raw_key)
            if canonical:
                entry[canonical] = raw_value
            else:
                # Keep unmapped fields as-is (might be useful for detection)
                entry[raw_key] = raw_value

        # Set log type
        if log_type:
            entry["type"] = log_type
        elif "type" not in entry:
            entry["type"] = "auth"

        # Normalize timestamp — convert epoch to ISO if needed
        ts = entry.get("timestamp", "")
        if ts:
            entry["timestamp"] = _normalize_timestamp(ts)

        normalized.append(entry)

    # Infer log type if not specified
    if not log_type:
        inferred = infer_log_type(normalized)
        for entry in normalized:
            entry["type"] = inferred
        logger.info("Inferred log type: %s", inferred)

    logger.info(
        "Normalized %d entries (type=%s, %d fields mapped)",
        len(normalized),
        log_type or "auto",
        len(field_map),
    )
    return normalized


def _normalize_timestamp(ts: str) -> str:
    """Normalize a timestamp string to ISO format.

    Handles:
    - ISO strings (pass through)
    - Epoch integers/floats (convert to ISO)
    - Empty strings (return current time)

    Args:
        ts: Timestamp string.

    Returns:
        ISO format timestamp string.
    """
    if not ts:
        return datetime.now(timezone.utc).isoformat()

    # Already ISO-like
    if "T" in ts or "-" in ts:
        return ts

    # Try epoch
    try:
        epoch = float(ts)
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        pass  # silent by design: unparseable timestamp in parse (2026-09 sweep)

    # Return as-is if we can't parse it
    return ts
