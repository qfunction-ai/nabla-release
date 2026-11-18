"""Atomic file write and safe JSON read utilities for concurrent persistence."""

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from datetime import date, datetime
from typing import Any

from nabla.log import get_logger

logger = get_logger("persistence")


def _json_default(obj: Any) -> Any:
    """Serialize the types the stores legitimately hold; reject everything else.

    F1: this was `default=str`, which silently turned any object the encoder
    could not handle into its repr string. A profile field that was never
    declared in its class's `_EWMA_FIELDS` therefore persisted as
    `"EWMAProfile(value=0.0, ...)"` and reloaded as that string, which killed
    the `exfil_volume` detector for an entire round without a single error.

    A type we do not know how to serialize is a bug, not a formatting choice.
    Raising here fails at write time, in the run that introduced it, instead
    of corrupting state that a later run reads back.
    """
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    raise TypeError(
        f"{type(obj).__name__} is not JSON-serializable "
        f"(value: {obj!r:.120}). Declare it in the owning store's field lists "
        f"or convert it explicitly — do not let it persist as a repr string."
    )


@contextmanager
def file_lock(filepath: str):
    """Acquire an exclusive POSIX file lock for the given data file.

    Creates a <filepath>.lock file and acquires fcntl.LOCK_EX on it.
    This prevents concurrent processes from corrupting read-modify-write
    sequences (e.g., history saves, RL state updates).

    Usage:
        with file_lock("/data/runs.json"):
            runs = load_runs()
            runs.append(new_run)
            save_runs(runs)
    """
    lock_path = filepath + ".lock"
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def atomic_write_json(filepath: str, data: dict, indent: int = 2) -> None:
    """Write JSON data to a file atomically using write-then-rename.

    Writes to a temp file in the same directory, then renames over the
    target. This prevents partial writes and race conditions from
    concurrent readers.

    Args:
        filepath: Target file path.
        data: Dict to serialize as JSON.
        indent: JSON indentation level.
    """
    dir_path = os.path.dirname(filepath) or "."
    os.makedirs(dir_path, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
    try:
        # Set restrictive permissions on temp file before writing.
        # os.replace() preserves the target file's permissions, not the
        # temp file's, so we set them here to ensure the final file is
        # owner-readable only (0600). This prevents world-readable
        # state files (RL state, run history) leaking sensitive data.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=indent, default=_json_default)
        os.replace(tmp_path, filepath)
    except Exception:
        # Clean up temp file on any failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass  # silent by design: best-effort fsync (2026-09 sweep)
        raise


def ensure_data_path(filepath: str) -> str | None:
    """Ensure parent directory exists for a data file path.

    Creates the parent directory if it doesn't exist. Returns the filepath
    on success, or None if the directory cannot be created (e.g., read-only
    filesystem).

    Args:
        filepath: Path to a data file.

    Returns:
        The filepath, or None on OSError.
    """
    try:
        parent = os.path.dirname(filepath) or "."
        os.makedirs(parent, exist_ok=True)
        return filepath
    except OSError:
        return None


def load_json_safe(filepath: str, default: Any = None) -> Any:
    """Load JSON from a file with error handling.

    Returns `default` (empty dict by default) if the file doesn't exist,
    is corrupted, or can't be read. Logs warnings on failures.

    Args:
        filepath: Path to JSON file.
        default: Value to return on failure (default: empty dict).

    Returns:
        Parsed JSON data, or `default` on any error.
    """
    if default is None:
        default = {}
    if not os.path.exists(filepath):
        return default
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError, ValueError) as e:
        logger.warning("Failed to load JSON from %s: %s", filepath, e)
        return default
