"""CSV/TSV log file parser.

Reads CSV or TSV files using Python's csv.DictReader.
Auto-detects delimiter (comma vs tab) from the first line.
"""

from __future__ import annotations

import csv
from pathlib import Path

from nabla.log import get_logger

logger = get_logger("parsers.csv")


def detect_delimiter(first_line: str) -> str:
    """Detect delimiter from the first line of a CSV/TSV file.

    Args:
        first_line: The first line of the file.

    Returns:
        Detected delimiter character (comma or tab).
    """
    # Use csv.Sniffer for robust detection
    try:
        dialect = csv.Sniffer().sniff(first_line, delimiters=",\t;|")
        return dialect.delimiter
    except csv.Error:
        pass  # silent by design: unparseable CSV skipped (2026-09 sweep)

    # Fallback: count commas vs tabs
    commas = first_line.count(",")
    tabs = first_line.count("\t")
    if tabs > commas:
        return "\t"
    return ","


def parse_csv(
    path: Path,
    max_entries: int = 100_000,
    encoding: str = "utf-8",
    delimiter: str | None = None,
) -> list[dict]:
    """Parse a CSV or TSV file into a list of dicts.

    Args:
        path: Path to the CSV/TSV file.
        max_entries: Maximum number of entries to parse.
        encoding: File encoding.
        delimiter: Delimiter character. If None, auto-detected.

    Returns:
        List of dicts (one per row, keys from header row).

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the file is empty or has no header.
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "r", encoding=encoding, errors="replace") as f:
        # Read first line for delimiter detection
        first_line = f.readline()
        if not first_line.strip():
            raise ValueError(f"File is empty: {path}")

        if delimiter is None:
            delimiter = detect_delimiter(first_line)

        # Rewind and parse
        f.seek(0)
        reader = csv.DictReader(f, delimiter=delimiter)

        if reader.fieldnames is None:
            raise ValueError(f"No header row found in: {path}")

        entries: list[dict] = []
        for i, row in enumerate(reader):
            if i >= max_entries:
                logger.warning(
                    "CSV file exceeded %d entries, truncating. "
                    "Remaining rows will be skipped.",
                    max_entries,
                )
                break
            # Skip empty rows
            if not any(row.values()):
                continue
            # Strip whitespace from keys and values
            cleaned = {
                k.strip(): (v.strip() if isinstance(v, str) else v)
                for k, v in row.items()
                if k is not None
            }
            entries.append(cleaned)

    logger.info("Parsed %d entries from CSV file: %s", len(entries), path)
    return entries
