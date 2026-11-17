"""Pipeline run history — persistent JSON file storage."""

import os
import uuid
from datetime import datetime, timezone
from typing import Any

from nabla.persistence import ensure_data_path, load_json_safe


def _runs_file() -> str | None:
    """Return the runs file path, or None if the data dir is not writable."""
    from nabla.config import get_settings
    return ensure_data_path(get_settings().runs_file)


def _load_runs(path: str) -> list[dict[str, Any]]:
    """Load all runs from the JSON file."""
    return load_json_safe(path, default=[])



def _save_runs(path: str, runs: list[dict[str, Any]]) -> None:
    """Write runs to the JSON file atomically."""
    from nabla.persistence import atomic_write_json
    try:
        atomic_write_json(path, runs)
    except OSError:
        from nabla.log import get_logger
        get_logger("history").warning("Cannot write runs file %s (read-only data dir)", path)


def new_run(
    log_types: list[str], log_count: int, source: str = "synthetic",
    watchlist_groups: list[str] | None = None, operator: str = "",
) -> dict[str, Any]:
    """Create a new run record with a unique ID and start time.

    Args:
        operator: Identity of the operator who triggered the run (for audit trail).
    """
    return {
        "run_id": str(uuid.uuid4()),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "source": source,
        "operator": operator or os.getenv("NABLA_OPERATOR", ""),
        "watchlist_groups": watchlist_groups,
        "log_types": log_types,
        "log_count": log_count,
        "anomaly_count": None,
        "findings_count": None,
        "step_durations": None,
        "success": False,
        "error": None,
    }


def complete_run(
    run: dict[str, Any],
    anomaly_count: int | None = None,
    findings_count: int | None = None,
    step_durations: dict[str, float] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Mark a run as completed with results."""
    run["finished_at"] = datetime.now(timezone.utc).isoformat()
    run["anomaly_count"] = anomaly_count
    run["findings_count"] = findings_count
    if step_durations is not None:
        run["step_durations"] = {k: round(v, 2) for k, v in step_durations.items()}
    run["success"] = error is None
    run["error"] = error
    return run


# Write-side history cap (UI-2): keep the newest N run records. With the
# bounded anomaly summaries (~100KB/run) this caps runs.json at ~20MB.
# Before UI-2 there was NO trimming — reads were limited, writes were not.
MAX_RUNS = 200


def save_run(run: dict[str, Any]) -> None:
    """Append a run record to the history file, trimming to MAX_RUNS.

    Uses file locking to prevent data loss from concurrent writes.
    Oldest runs are dropped once the cap is exceeded.
    """
    from nabla.persistence import file_lock

    path = _runs_file()
    if path is None:
        return

    with file_lock(path):
        runs = _load_runs(path)
        runs.append(run)
        if len(runs) > MAX_RUNS:
            runs = runs[-MAX_RUNS:]
        _save_runs(path, runs)


def list_runs(limit: int = 20) -> list[dict[str, Any]]:
    """Return the most recent runs, newest first."""
    path = _runs_file()
    if path is None:
        return []
    runs = _load_runs(path)
    return list(reversed(runs))[:limit]
