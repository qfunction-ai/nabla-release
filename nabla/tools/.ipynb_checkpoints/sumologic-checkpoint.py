"""SumoLogic query tool for agent use.

Single function to query SumoLogic logs via the Search Job API v2.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx


# Default API endpoint (US1)
DEFAULT_HOST = "https://api.sumologic.com/api"

# Search job states that indicate completion
DONE_STATES = {
    "DONE GATHERING RESULTS",
    "DONE GATHERING HISTOGRAM",
    "CANCELLED",
}

# Max page size for message retrieval (SumoLogic limit)
MAX_PAGE_SIZE = 10_000

# Fields to drop from output (SumoLogic internal)
DROP_FIELDS = frozenset({
    "_messageid", "_sourceid", "_receipttime", "_collectorId",
    "_blockid", "_size", "_format", "_messagecount", "_raw",
    "_collector", "_source",
})


def query_sumologic(
    query: str,
    access_id: str,
    access_key: str,
    host: str = DEFAULT_HOST,
    from_time: str | None = None,
    to_time: str | None = None,
    last: str | None = None,
    max_results: int = 10_000,
    poll_interval: float = 2.0,
    poll_timeout: float = 300.0,
    raw: bool = False,
) -> list[dict[str, Any]]:
    """Query SumoLogic logs and return results.

    Uses the Search Job API v2: create job → poll → fetch → delete.

    Args:
        query: SumoLogic query string (the full query, not a file path).
        access_id: SumoLogic access ID for Basic Auth.
        access_key: SumoLogic access key for Basic Auth.
        host: SumoLogic API endpoint (default: US1).
            Common values:
            - US1: https://api.sumologic.com/api
            - US2: https://api.us2.sumologic.com/api
            - EU: https://api.eu.sumologic.com/api
            - AU: https://api.au.sumologic.com/api
        from_time: Start time as ISO string (e.g., "2026-05-28T00:00:00Z").
            Mutually exclusive with `last`.
        to_time: End time as ISO string. Defaults to now.
        last: Relative time range (e.g., "1h", "24h", "7d").
            Shorthand for from_time. Mutually exclusive with from_time.
        max_results: Maximum number of messages to return (default: 10000).
        poll_interval: Seconds between status polls (default: 2).
        poll_timeout: Max seconds to wait for job completion (default: 300).
        raw: If True, include SumoLogic internal fields in output.

    Returns:
        List of message dicts. Each dict contains the fields from your query.
        Empty list if no results.

    Raises:
        ValueError: If credentials missing or invalid time format.
        httpx.HTTPStatusError: If API request fails.
        TimeoutError: If job doesn't complete within poll_timeout.

    Example:
        >>> messages = query_sumologic(
        ...     query='_sourceCategory=auth | parse "* failed" as user',
        ...     access_id='su12345',
        ...     access_key='...',
        ...     last='1h',
        ... )
        >>> len(messages)
        42
        >>> messages[0].get('user')
        'admin'
    """
    if not access_id or not access_key:
        raise ValueError("SumoLogic access_id and access_key are required")

    # Parse time range
    now = datetime.now(timezone.utc)

    if last and from_time:
        raise ValueError("Cannot specify both 'last' and 'from_time'")

    if last:
        from_dt = _parse_relative_time(last, now)
        to_dt = now
    elif from_time:
        from_dt = _parse_time(from_time, now)
        to_dt = _parse_time(to_time, now) if to_time else now
    else:
        from_dt = now - timedelta(hours=1)
        to_dt = now

    # Create httpx client with Basic Auth
    with httpx.Client(
        base_url=host,
        auth=(access_id, access_key),
        timeout=httpx.Timeout(120.0, connect=30.0),
        follow_redirects=True,
    ) as client:
        # Create search job
        job_id = _create_job(client, query, from_dt, to_dt)

        try:
            # Poll for completion
            status = _poll_job(client, job_id, poll_interval, poll_timeout)
            message_count = status.get("messageCount", 0)

            # Fetch messages
            messages = _fetch_messages(client, job_id, message_count, max_results)

        finally:
            # Clean up
            _delete_job(client, job_id)

    # Clean output
    if not raw:
        messages = [_clean_message(m) for m in messages]

    return messages


def _parse_time(time_str: str | None, now: datetime) -> datetime:
    """Parse ISO time string or return now if None."""
    if not time_str:
        return now

    try:
        dt = datetime.fromisoformat(time_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError as e:
        raise ValueError(f"Invalid time format '{time_str}': {e}") from e


def _parse_relative_time(relative: str, now: datetime) -> datetime:
    """Parse relative time like '1h', '24h', '7d', '30d'."""
    relative = relative.lstrip("-")

    if relative.endswith("h"):
        hours = int(relative[:-1])
        return now - timedelta(hours=hours)
    elif relative.endswith("d"):
        days = int(relative[:-1])
        return now - timedelta(days=days)
    elif relative.endswith("m"):
        minutes = int(relative[:-1])
        return now - timedelta(minutes=minutes)
    else:
        # Assume hours if no suffix
        try:
            hours = int(relative)
            return now - timedelta(hours=hours)
        except ValueError as e:
            raise ValueError(f"Invalid relative time '{relative}'") from e


def _create_job(
    client: httpx.Client,
    query: str,
    from_dt: datetime,
    to_dt: datetime,
) -> str:
    """Create a SumoLogic search job and return the job ID."""
    from_ms = int(from_dt.timestamp() * 1000)
    to_ms = int(to_dt.timestamp() * 1000)

    body = {
        "query": query,
        "from": from_ms,
        "to": to_ms,
        "timeZone": "UTC",
    }

    resp = client.post("/v2/search/jobs", json=body)
    resp.raise_for_status()

    data = resp.json()
    job_id = data.get("id")
    if not job_id:
        raise ValueError(f"No job ID in response: {data}")

    return job_id


def _poll_job(
    client: httpx.Client,
    job_id: str,
    poll_interval: float,
    poll_timeout: float,
) -> dict[str, Any]:
    """Poll a search job until completion."""
    deadline = time.monotonic() + poll_timeout

    while time.monotonic() < deadline:
        resp = client.get(f"/v2/search/jobs/{job_id}")
        resp.raise_for_status()

        data = resp.json()
        state = data.get("state", "")

        if state in DONE_STATES:
            return data

        if state == "CANCELLED":
            raise ValueError(f"Search job {job_id} was cancelled")

        time.sleep(poll_interval)

    raise TimeoutError(f"Job {job_id} did not complete within {poll_timeout}s")


def _fetch_messages(
    client: httpx.Client,
    job_id: str,
    message_count: int,
    max_results: int,
) -> list[dict[str, Any]]:
    """Page through all messages from a completed search job."""
    if message_count == 0:
        return []

    max_results = min(message_count, max_results)
    results: list[dict[str, Any]] = []
    offset = 0

    while offset < max_results:
        limit = min(MAX_PAGE_SIZE, max_results - offset)
        resp = client.get(
            f"/v2/search/jobs/{job_id}/messages",
            params={"offset": offset, "limit": limit},
        )
        resp.raise_for_status()

        data = resp.json()
        messages = data.get("messages", [])

        if not messages:
            break

        # SumoLogic messages are {"map": {...}}
        for msg in messages:
            msg_map = msg.get("map", msg)
            results.append(msg_map)

        offset += len(messages)

        if len(messages) < limit:
            break

    return results


def _delete_job(client: httpx.Client, job_id: str) -> None:
    """Delete a search job (non-fatal on failure)."""
    try:
        client.delete(f"/v2/search/jobs/{job_id}")
    except Exception:
        pass


def _clean_message(msg: dict[str, Any]) -> dict[str, Any]:
    """Remove SumoLogic internal fields from a message."""
    return {k: v for k, v in msg.items() if k not in DROP_FIELDS}


# Convenience function for loading credentials from file
def load_credentials(path: str | Path) -> tuple[str, str]:
    """Load SumoLogic credentials from a JSON file.

    Args:
        path: Path to JSON file with {"access_id": "...", "access_key": "..."}

    Returns:
        Tuple of (access_id, access_key)

    Raises:
        FileNotFoundError: If file doesn't exist.
        ValueError: If file is missing required fields.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Credentials file not found: {path}")

    with open(path) as f:
        creds = json.load(f)

    access_id = creds.get("access_id")
    access_key = creds.get("access_key")

    if not access_id or not access_key:
        raise ValueError(f"Credentials file missing 'access_id' or 'access_key': {path}")

    return access_id, access_key
