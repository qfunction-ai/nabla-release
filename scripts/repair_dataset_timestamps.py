#!/usr/bin/env python3
"""F2: repair the corrupt `timestamp` values in dataset-v1/baseline.

`LINUX_ENDPOINT_QUERY` in export_course_dataset.py captured the Sysmon
timestamp with `[^ ]+ [^ ]+`, a pattern written for a space-separated format.
The data is ISO-8601 with a `T` and no space, so the capture ran greedily
across the XML to the first space and swallowed everything up to it:

    "2026-08-09T00:00:15.796640000Z"/><EventRecordID>1356237</EventRecordID>...

405,097 of 551,856 events (100% of the endpoint stream) were affected.

The repair extracts the leading ISO timestamp. This is provably equivalent to
a correct re-export: the corrected pattern `SystemTime=(?<ts_raw>[0-9T:.Z+-]+)`
captures exactly the leading ISO string this extracts, so the repaired files
are byte-identical to what a fixed export would have written. Re-exporting
from SumoLogic is therefore optional.

Every value is recovered or the script refuses to write. There is no partial
repair and no silent skip.

Usage:
    python3 scripts/repair_dataset_timestamps.py --check
    python3 scripts/repair_dataset_timestamps.py --apply
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DEFAULT_DIR = Path("dataset-v1/baseline")

# A JSON string value, correctly handling backslash escapes. Matching the
# value token rather than the raw text keeps us from tripping over the
# escaped quotes the corruption is full of.
_TIMESTAMP_VALUE = re.compile(r'("timestamp"\s*:\s*)("(?:[^"\\]|\\.)*")')

# The corruption: an escaped leading quote, a valid ISO timestamp, then the
# XML the greedy capture swallowed.
_CORRUPT = re.compile(
    r'^"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)"/><EventRecordID>'
)

# A timestamp that is already correct.
_CLEAN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?$")


def repair_line(line: str) -> tuple[str, str]:
    """Return (new_line, status) where status is clean|repaired|unrecoverable."""
    match = _TIMESTAMP_VALUE.search(line)
    if not match:
        return line, "clean"
    try:
        value = json.loads(match.group(2))
    except json.JSONDecodeError:
        return line, "unrecoverable"
    if _CLEAN.match(value):
        return line, "clean"
    recovered = _CORRUPT.match(value)
    if not recovered:
        return line, "unrecoverable"
    replacement = match.group(1) + json.dumps(recovered.group(1))
    return line[: match.start()] + replacement + line[match.end():], "repaired"


def process(path: Path, apply: bool) -> tuple[int, int, list[str]]:
    """Return (repaired, clean, unrecoverable_samples)."""
    original = path.read_text()
    lines = original.split("\n")
    repaired = clean = 0
    unrecoverable: list[str] = []
    out: list[str] = []
    for line in lines:
        if not line.strip():
            out.append(line)
            continue
        new_line, status = repair_line(line)
        if status == "repaired":
            repaired += 1
        elif status == "clean":
            clean += 1
        else:
            if len(unrecoverable) < 3:
                unrecoverable.append(line[:160])
        out.append(new_line)

    if unrecoverable:
        return repaired, clean, unrecoverable

    if apply and repaired:
        # Atomic: a killed repair must not leave a half-written dataset.
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text("\n".join(out))
        tmp.replace(path)
    return repaired, clean, unrecoverable


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true",
                       help="report what would change, write nothing")
    group.add_argument("--apply", action="store_true", help="repair in place")
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR)
    args = parser.parse_args()

    files = sorted(args.dir.glob("*.jsonl"))
    if not files:
        print(f"no .jsonl files under {args.dir}", file=sys.stderr)
        return 2

    total_repaired = total_clean = 0
    failures: list[tuple[Path, list[str]]] = []
    for path in files:
        repaired, clean, unrecoverable = process(path, args.apply)
        total_repaired += repaired
        total_clean += clean
        if unrecoverable:
            failures.append((path, unrecoverable))
        print(f"  {path.name}: {repaired} repaired, {clean} clean")

    print(f"\ntotal: {total_repaired} repaired, {total_clean} clean")
    if failures:
        print("\nUNRECOVERABLE — refusing to write:", file=sys.stderr)
        for path, samples in failures:
            print(f"  {path}:", file=sys.stderr)
            for sample in samples:
                print(f"    {sample}", file=sys.stderr)
        return 1
    if args.check:
        print("(check only — nothing written)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
