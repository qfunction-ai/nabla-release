"""Incremental ingestion state tracking.

Tracks the last ingestion timestamp per connector so subsequent
runs only fetch new events.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from nabla.log import get_logger
from nabla.persistence import load_json_safe

logger = get_logger("ingestion_state")


def load_state(path: str) -> dict:
    """Load ingestion state from a JSON file. Returns empty dict if missing or corrupted."""
    return load_json_safe(path)


def save_state(path: str, data: dict) -> None:
    """Save ingestion state to a JSON file atomically."""
    from nabla.persistence import atomic_write_json
    atomic_write_json(path, data)
    logger.debug("Saved ingestion state to %s", path)


def get_last_ingestion(path: str, connector: str, log_type: str | None = None) -> str | None:
    """Get the last ingestion timestamp for a connector, optionally per log type.

    Args:
        path: Path to the ingestion state JSON file.
        connector: Connector name (e.g. 'sumologic', 'splunk').
        log_type: Optional log type (e.g. 'auth', 'endpoint'). If provided,
            returns the per-type timestamp. If None, returns the connector-level
            timestamp (backward compatible).

    Returns:
        ISO timestamp string or None if never ingested.
    """
    data = load_state(path)
    entry = data.get(connector, {})
    if log_type:
        return entry.get("log_types", {}).get(log_type, {}).get("last_ingestion")
    return entry.get("last_ingestion")


def update_last_ingestion(path: str, connector: str, total_ingested: int = 0, log_type: str | None = None) -> None:
    """Update the last ingestion timestamp for a connector to now.

    Args:
        path: Path to the ingestion state JSON file.
        connector: Connector name (e.g. 'sumologic', 'splunk').
        total_ingested: Number of logs ingested in this run.
        log_type: Optional log type. If provided, updates the per-type
            timestamp in addition to the connector-level timestamp.
    """
    from nabla.persistence import file_lock

    with file_lock(path):
        data = load_state(path)
        now = datetime.now(timezone.utc).isoformat()

        if connector not in data:
            data[connector] = {}

        data[connector]["last_ingestion"] = now
        data[connector]["total_ingested"] = data[connector].get("total_ingested", 0) + total_ingested

        if log_type:
            if "log_types" not in data[connector]:
                data[connector]["log_types"] = {}
            if log_type not in data[connector]["log_types"]:
                data[connector]["log_types"][log_type] = {}
            data[connector]["log_types"][log_type]["last_ingestion"] = now
            data[connector]["log_types"][log_type]["total_ingested"] = (
                data[connector]["log_types"][log_type].get("total_ingested", 0) + total_ingested
            )

        save_state(path, data)
        logger.info("Updated ingestion state for '%s'%s: last_ingestion=%s, total=%d",
                    connector, f"/{log_type}" if log_type else "", now, total_ingested)


def reset_state(path: str, connector: str | None = None) -> None:
    """Reset ingestion state. If connector is None, reset all."""
    if connector:
        data = load_state(path)
        data.pop(connector, None)
        save_state(path, data)
        logger.info("Reset ingestion state for '%s'", connector)
    else:
        if os.path.exists(path):
            try:
                os.remove(path)
                logger.info("Reset all ingestion state (removed %s)", path)
            except OSError:
                logger.warning("Failed to remove ingestion state file %s", path)
