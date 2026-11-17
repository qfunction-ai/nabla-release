"""JSON and JSONL log file parser.

Reads JSON arrays ([{...}, {...}]) or JSON Lines (one JSON object per line).
"""

from __future__ import annotations

import json
from pathlib import Path

from nabla.log import get_logger

logger = get_logger("parsers.json")


def parse_json(
    path: Path,
    max_entries: int = 100_000,
    encoding: str = "utf-8",
) -> list[dict]:
    """Parse a JSON or JSONL file into a list of dicts.

    Tries JSON array format first. If that fails, falls back to JSONL
    (one JSON object per line).

    Args:
        path: Path to the JSON/JSONL file.
        max_entries: Maximum number of entries to parse.
        encoding: File encoding.

    Returns:
        List of dicts (one per log entry).

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the file cannot be parsed as JSON or JSONL.
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    content = path.read_text(encoding=encoding, errors="replace")

    # Try JSON array format first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            entries = [item for item in data if isinstance(item, dict)]
            if len(entries) > max_entries:
                logger.warning(
                    "JSON file has %d entries, truncating to %d.",
                    len(entries), max_entries,
                )
                entries = entries[:max_entries]
            logger.info("Parsed %d entries from JSON array: %s", len(entries), path)
            return entries
        elif isinstance(data, dict):
            # Single object — wrap in list
            logger.info("Parsed 1 entry from JSON object: %s", path)
            return [data]
    except json.JSONDecodeError:
        pass  # silent by design: unparseable JSON line skipped (2026-09 sweep)

    # Fall back to JSONL
    entries: list[dict] = []
    for i, line in enumerate(content.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                entries.append(obj)
        except json.JSONDecodeError as e:
            logger.debug("Skipping invalid JSONL line %d: %s", i + 1, e)
            continue

        if len(entries) >= max_entries:
            logger.warning(
                "JSONL file exceeded %d entries, truncating.",
                max_entries,
            )
            break

    if not entries:
        raise ValueError(f"Could not parse any JSON entries from: {path}")

    logger.info("Parsed %d entries from JSONL file: %s", len(entries), path)
    return entries
