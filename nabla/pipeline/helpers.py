"""Pipeline utility functions — log type resolution, message extraction, source resolution."""

from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import TYPE_CHECKING

from letta_client import Letta

from nabla.log import get_logger

if TYPE_CHECKING:
    from nabla.connectors.base import Watchlist

logger = get_logger("pipeline.helpers")

LOG_TYPES = ["auth", "network", "dns", "endpoint"]


def _extract_assistant_message(response) -> str:
    """Extract the assistant message content from a Letta response.

    Falls back to the last tool return if no assistant message is present
    (e.g., when the agent exits via a terminal tool rule).
    """
    last_tool_return = ""
    for msg in response.messages:
        if msg.message_type == "assistant_message" and msg.content:
            return msg.content
        if msg.message_type == "tool_return_message" and hasattr(msg, "tool_return") and msg.tool_return:
            last_tool_return = msg.tool_return
    return last_tool_return


def _read_supervisor_blocks(client: Letta, agent_id: str, *labels: str) -> dict[str, str]:
    """Read specific block labels from the supervisor agent.

    Args:
        client: Letta client instance.
        agent_id: Supervisor agent ID.
        *labels: Block labels to read.

    Returns:
        Dict mapping label to value (empty string if missing).
    """
    blocks = client.agents.blocks.list(agent_id=agent_id)
    result = {label: "" for label in labels}
    for b in blocks:
        if b.label in labels:
            result[b.label] = b.value or ""
    return result


def _resolve_log_types(log_types: list[str] | str) -> list[str]:
    """Resolve log type argument to a list of types.

    Accepts: "all", a single type string, or a list of types.
    """
    if isinstance(log_types, str):
        if log_types == "all":
            return LOG_TYPES[:]
        return [log_types]
    if "all" in log_types:
        return LOG_TYPES[:]
    return log_types


def _read_baseline_host_procs() -> dict[str, list[str]]:
    """Read historical per-host process sets from the baseline snapshots JSONL file.

    Returns a dict mapping host -> sorted list of unique process names.
    Used by the unusual-process detection method.
    """
    host_procs = defaultdict(set)
    try:
        from nabla.config import get_settings
        settings = get_settings()
        path = settings.baseline_snapshots_file
        if not os.path.exists(path):
            logger.debug("No baseline snapshots file found at %s", path)
            return {}

        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if isinstance(data, dict) and data.get("snapshot_type") == "baseline":
                        if "host_processes" in data:
                            for host, procs in data["host_processes"].items():
                                host_procs[host].update(procs)
                except json.JSONDecodeError:
                    pass  # silent by design: unparseable block JSON (2026-09 sweep)
    except Exception as e:
        logger.debug("Could not read baseline host processes: %s", e)

    return {h: sorted(procs) for h, procs in host_procs.items()}


def _extract_host_processes_from_entries(entries: list[dict]) -> dict[str, list[str]]:
    """Extract per-host process sets from current log entries.

    Returns a dict mapping host -> sorted list of unique process names.
    Used for the baseline snapshot.
    """
    host_procs = defaultdict(set)
    for e in entries:
        if e.get("type") != "endpoint":
            continue
        host = e.get("host", "")
        proc = (e.get("process") or e.get("Image") or "").lower().replace(".exe", "")
        if host and proc:
            host_procs[host].add(proc)

    return {h: sorted(procs) for h, procs in host_procs.items()}


def _resolve_source(source: str) -> str:
    """Resolve the ingestion source.

    "auto" → "splunk" if Splunk is configured, "sumologic" if SumoLogic is configured, else "synthetic"
    "synthetic" → "synthetic"
    "splunk" → "splunk"
    "sumologic" → "sumologic"
    "file" → "file"
    """
    if source in ("synthetic", "splunk", "sumologic", "file"):
        return source
    if source == "auto":
        from nabla.config import get_settings
        settings = get_settings()
        if settings.splunk_host:
            return "splunk"
        if settings.sumologic_host:
            return "sumologic"
        return "synthetic"
    raise ValueError(
        f"Unknown ingestion source: {source!r}. "
        "Use 'auto', 'synthetic', 'splunk', 'sumologic', or 'file'."
    )


def _filter_watchlist_by_groups(watchlist_path: str, groups: list[str]) -> Watchlist:
    """Filter watchlist to only include specified groups."""
    from nabla.watchlist import load_watchlist
    from nabla.connectors.base import Watchlist

    data = load_watchlist(watchlist_path)
    users = []
    hosts = []
    ips = []

    for group in groups:
        if group in ("high_value_users",):
            users.extend(data.get("high_value_users", []))
        elif group in ("critical_systems",):
            hosts.extend(data.get("critical_systems", []))
        elif group in ("watched_ips",):
            ips.extend(data.get("watched_ips", []))
        elif group in data.get("custom_groups", {}):
            name_lower = group.lower()
            entities = data["custom_groups"][group]
            if "ip" in name_lower or "network" in name_lower:
                ips.extend(entities)
            elif "host" in name_lower or "system" in name_lower or "server" in name_lower:
                hosts.extend(entities)
            else:
                users.extend(entities)

    return Watchlist(
        users=list(dict.fromkeys(users)),
        hosts=list(dict.fromkeys(hosts)),
        ips=list(dict.fromkeys(ips)),
    )
