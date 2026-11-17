"""Pipeline ingestion — fetch and store logs from connectors, files, or synthetic generators."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from letta_client import Letta

from nabla.log import get_logger
from nabla.pipeline.helpers import (
    _extract_host_processes_from_entries,
    _read_supervisor_blocks,
    _resolve_log_types,
    _resolve_source,
    _filter_watchlist_by_groups,
)

if TYPE_CHECKING:
    from nabla.connectors.base import Watchlist

logger = get_logger("pipeline.ingestion")


@dataclass
class IngestionResult:
    """Result from the ingestion step."""
    entries: list[dict] = field(default_factory=list)
    total_normal: int = 0
    total_anomalous: int = 0
    total_ingested: int = 0
    type_summaries: list[str] = field(default_factory=list)
    siem_entries_ingested: int = 0
    effective_source: str = "synthetic"


def run_ingestion(
    client: Letta,
    agents: dict[str, str],
    settings,
    log_types: list[str] | str,
    log_count: int,
    source: str,
    watchlist_groups: list[str] | None = None,
    reset_ingestion: bool = False,
    file_path: str | None = None,
    file_format: str | None = None,
    column_map: dict[str, str] | None = None,
) -> IngestionResult:
    """Step 1: Log Ingestion — fetch logs from connectors, files, or synthetic generators.

    Args:
        client: Letta client instance.
        agents: Dict mapping role → agent_id.
        settings: Application settings.
        log_types: Log type(s) to ingest.
        log_count: Number of log entries per type (synthetic only).
        source: Ingestion source — "auto", "synthetic", "splunk", "sumologic", "file".
        watchlist_groups: Watchlist groups to target (None = all groups).
        reset_ingestion: Reset ingestion state for full re-pull.
        file_path: Path to log file (required when source="file").
        file_format: Format hint for file parsing.
        column_map: User-provided field mapping.

    Returns:
        IngestionResult with all entries and counts.
    """
    from nabla.ingest import generate_synthetic_logs, ingest_logs
    from nabla.lolbin_db import parse_lolbin_block
    from nabla.watchlist import get_all_entities
    from nabla.connectors.base import Watchlist, ConnectorConfig
    from nabla.connectors.synthetic import SyntheticConnector

    effective_source = _resolve_source(source)
    logger.info("Pipeline source: %s (requested=%s)", effective_source, source)

    # Load watchlist for SIEM connectors
    watchlist_dict = get_all_entities(settings.effective_watchlist_path)
    watchlist = Watchlist.from_dict(watchlist_dict)

    if watchlist_groups:
        watchlist = _filter_watchlist_by_groups(settings.effective_watchlist_path, watchlist_groups)

    # Get connector
    connector = None
    if effective_source == "splunk":
        from nabla.connectors.splunk import SplunkConnector
        connector = SplunkConnector(settings.splunk_config())
    elif effective_source == "sumologic":
        from nabla.connectors.sumologic import SumoLogicConnector
        connector = SumoLogicConnector(settings.sumologic_config())
    elif effective_source == "synthetic":
        synth = SyntheticConnector(ConnectorConfig())
        synth.set_count(log_count)
        connector = synth

    # Load ingestion state for incremental pulls
    from nabla.ingestion_state import get_last_ingestion, update_last_ingestion, reset_state
    ingestion_state_path = settings.effective_ingestion_state_path
    if reset_ingestion:
        reset_state(ingestion_state_path, effective_source if effective_source != "synthetic" else None)

    types = _resolve_log_types(log_types)
    result = IngestionResult(effective_source=effective_source)

    # --- Connector-based ingestion (Splunk, SumoLogic, future SIEMs) ---
    if connector is not None:
        for i, log_type in enumerate(types, 1):
            since = None
            if effective_source != "synthetic":
                since = get_last_ingestion(ingestion_state_path, effective_source, log_type)

            logger.info("Ingestion (%d/%d): fetching %s logs via %s", i, len(types), log_type, effective_source)
            try:
                logs = connector.fetch_logs(
                    watchlist=watchlist,
                    log_type=log_type,
                    since=since,
                    until=None,
                )
            except ValueError as e:
                logger.warning("Skipping %s: %s", log_type, e)
                continue

            if not logs:
                logger.info("No %s logs returned from %s", log_type, effective_source)
                continue

            ingest_result = ingest_logs(
                client=client,
                supervisor_agent_id=agents["supervisor"],
                logs=logs,
                log_type=log_type,
            )
            result.entries.extend(logs)
            result.total_normal += ingest_result["normal"]
            result.total_anomalous += ingest_result["anomalous"]
            result.total_ingested += ingest_result["count"]
            if effective_source in ("splunk", "sumologic"):
                result.siem_entries_ingested += ingest_result["count"]
            result.type_summaries.append(f"{log_type}: {ingest_result['count']} ({ingest_result['anomalous']} anomalous)")
            logger.info(
                "Ingested %s: %d logs (%d normal, %d anomalous)",
                log_type, ingest_result["count"], ingest_result["normal"], ingest_result["anomalous"],
            )

            if effective_source != "synthetic" and ingest_result["count"] > 0:
                update_last_ingestion(ingestion_state_path, effective_source, ingest_result["count"], log_type)

    # --- File-based ingestion ---
    elif effective_source == "file":
        if not file_path:
            raise ValueError("file_path is required when source='file'")

        from nabla.parsers import parse_file, normalize_entries

        raw_entries = parse_file(
            file_path,
            format_hint=file_format,
            max_entries=settings.max_file_entries,
        )

        file_log_type = None
        if log_types != "all" and not isinstance(log_types, list):
            file_log_type = log_types
        elif isinstance(log_types, list) and len(log_types) == 1:
            file_log_type = log_types[0]

        result.entries = normalize_entries(
            raw_entries,
            log_type=file_log_type,
            column_map=column_map,
        )

        if log_count and len(result.entries) > log_count:
            logger.info(
                "Truncating file entries from %d to %d (log_count=%d)",
                len(result.entries), log_count, log_count,
            )
            result.entries = result.entries[:log_count]

        result.total_ingested = len(result.entries)
        result.total_normal = result.total_ingested
        inferred_type = result.entries[0].get("type", "unknown") if result.entries else "unknown"
        result.type_summaries.append(f"{inferred_type}: {result.total_ingested}")
        logger.info(
            "File ingestion: %d entries from %s (type=%s)",
            result.total_ingested, file_path, inferred_type,
        )

    # --- Legacy synthetic ingestion (no connector resolved) ---
    else:
        lolbin_index = None
        try:
            blocks = _read_supervisor_blocks(client, agents["supervisor"], "lolbin_db")
            if blocks["lolbin_db"]:
                lolbin_index = parse_lolbin_block(blocks["lolbin_db"])
        except Exception as e:
            logger.warning("Could not read lolbin_db block: %s (using fallback LOLBIN data)", e)

        for i, log_type in enumerate(types, 1):
            logger.info("Ingestion (%d/%d): generating %d %s logs", i, len(types), log_count, log_type)
            logs = generate_synthetic_logs(log_type, count=log_count, lolbin_index=lolbin_index)
            ingest_result = ingest_logs(
                client=client,
                supervisor_agent_id=agents["supervisor"],
                logs=logs,
                log_type=log_type,
            )
            result.entries.extend(logs)
            result.total_normal += ingest_result["normal"]
            result.total_anomalous += ingest_result["anomalous"]
            result.total_ingested += ingest_result["count"]
            result.type_summaries.append(f"{log_type}: {ingest_result['count']} ({ingest_result['anomalous']} anomalous)")
            logger.info(
                "Ingested %s: %d logs (%d normal, %d anomalous)",
                log_type, ingest_result["count"], ingest_result["normal"], ingest_result["anomalous"],
            )

    # Phase 2 (remediation plan): stable event_id on every ingested entry —
    # correlation and the Phase 3 label pipeline reference events by ID.
    import hashlib as _hashlib
    for e in result.entries:
        key_material = "|".join(str(e.get(k, "")) for k in (
            "timestamp", "user", "host", "source_ip", "process", "action",
            "event_code", "dest_ip",
        ))
        e["event_id"] = _hashlib.sha256(key_material.encode()).hexdigest()[:16]

    return result
