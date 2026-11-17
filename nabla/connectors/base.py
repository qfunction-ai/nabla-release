"""Base connector interface and data models."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from typing import Any, Protocol

from nabla.log import get_logger

logger = get_logger("connectors.base")


# Canonical log schema — each log type's required and optional fields.
# Connectors must normalize their SIEM output to match this schema.
CANONICAL_SCHEMA: dict[str, dict[str, list[str]]] = {
    "auth": {
        "required": ["timestamp", "user", "action"],
        "optional": ["source_ip", "dest_host", "event_code", "host", "source", "sourcetype"],
    },
    "network": {
        "required": ["timestamp", "src_ip", "dst_ip"],
        "optional": ["dest_port", "protocol", "bytes", "action", "host", "source", "sourcetype"],
    },
    "dns": {
        "required": ["timestamp", "domain"],
        "optional": ["client_ip", "query_type", "action", "host", "source", "sourcetype"],
    },
    "endpoint": {
        "required": ["timestamp", "process"],
        "optional": [
            "user", "command_line", "parent_process", "action",
            "integrity_level", "host", "source", "sourcetype",
            "target_file", "target_registry", "network_connection",
        ],
    },
}


@dataclass
class Watchlist:
    """Entities to target during SIEM ingestion.

    Aggregated from watchlist file by entity type.
    """
    users: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.users and not self.hosts and not self.ips

    @classmethod
    def from_dict(cls, data: dict[str, list[str]]) -> "Watchlist":
        return cls(
            users=data.get("users", []),
            hosts=data.get("hosts", []),
            ips=data.get("ips", []),
        )


@dataclass
class ConnectorConfig:
    """Base configuration for a connector. Subclass for SIEM-specific settings."""
    log_types: list[str] = field(default_factory=lambda: ["auth", "network", "dns", "endpoint"])
    max_results: int = 10000


def escape_query_value(value: str) -> str:
    """Escape a value for safe inclusion in double-quoted query strings.

    Both Splunk (SPL) and SumoLogic use double quotes for string literals.
    Escape by doubling the quote (standard escape convention for both).

    Args:
        value: Raw entity value from the watchlist.

    Returns:
        Escaped value safe for f'"{ret}"' interpolation.
    """
    return value.replace('"', '""')


def load_credentials_secure(path: str, connector_name: str) -> dict | None:
    """Load a credentials JSON file with TOCTOU-safe permission checks.

    Opens the file via os.open() + os.fstat() to prevent TOCTOU races
    between stat() and open(). Rejects files with overly permissive
    permissions (group/other readable).

    Args:
        path: Path to the credentials JSON file.
        connector_name: Name for log messages (e.g., "Splunk", "SumoLogic").

    Returns:
        Dict of credential key-value pairs, or None on any error.
    """
    if not os.path.exists(path):
        logger.warning("%s credentials file not found: %s", connector_name, path)
        return None

    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as e:
        logger.warning("Failed to open %s credentials file %s: %s", connector_name, path, e)
        return None

    try:
        # Check permissions on the open FD (not the path) to prevent TOCTOU
        mode = stat.S_IMODE(os.fstat(fd).st_mode)
        if mode & 0o077:
            logger.warning(
                "%s credentials file %s has overly permissive permissions (%04o). "
                "Expected 0600 or 0400. Refusing to read.",
                connector_name, path, mode,
            )
            os.close(fd)
            fd = -1
            return None

        # os.fdopen takes ownership of fd — it will be closed when
        # the file object is closed. Set fd = -1 now so the finally
        # block doesn't double-close.
        f = os.fdopen(fd, "r")
        fd = -1
        try:
            creds = json.load(f)
        finally:
            f.close()

        if not isinstance(creds, dict):
            logger.warning(
                "%s credentials file must contain a JSON object, got %s",
                connector_name, type(creds).__name__,
            )
            return None

        logger.info("Loaded %s credentials from %s", connector_name, path)
        return creds
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to read %s credentials from %s: %s", connector_name, path, e)
        return None
    finally:
        if fd >= 0:
            os.close(fd)


class Connector(Protocol):
    """Protocol for SIEM connectors.

    Each connector fetches logs from a specific SIEM platform,
    applying watchlist filtering and incremental ingestion.
    """

    def fetch_logs(
        self,
        watchlist: Watchlist,
        log_type: str,
        since: str | None,
        until: str | None,
    ) -> list[dict[str, Any]]:
        """Fetch logs for a specific type from the SIEM.

        Args:
            watchlist: Entities to target (users, hosts, IPs).
            log_type: One of "auth", "network", "dns", "endpoint".
            since: ISO timestamp for incremental ingestion (None = full pull).
            until: ISO timestamp for upper bound (None = now).

        Returns:
            List of log dicts in Nabla's canonical format.
        """
        ...

    def available_log_types(self) -> list[str]:
        """Return which log types this connector can fetch."""
        ...


# ---------------------------------------------------------------------------
# Shared SIEM connector helpers — eliminates duplication between Splunk
# and SumoLogic connectors.
# ---------------------------------------------------------------------------

def load_queries_from_file(
    queries_path: str,
    connector_name: str,
    query_map: dict[str, str],
) -> None:
    """Load queries from a JSON file and merge into query_map.

    The queries file is merged with (and overrides) the existing query_map.
    Format: {"auth": "search ...", "endpoint": "search ..."}

    Args:
        queries_path: Path to JSON file with query mappings.
        connector_name: Name for log messages (e.g., "Splunk", "SumoLogic").
        query_map: Existing query map to update in-place.
    """
    if not queries_path:
        return
    if not os.path.exists(queries_path):
        logger.warning("%s queries file not found: %s", connector_name, queries_path)
        return
    try:
        with open(queries_path) as f:
            queries = json.load(f)
        if not isinstance(queries, dict):
            logger.warning(
                "%s queries file must contain a JSON object, got %s",
                connector_name, type(queries).__name__,
            )
            return
        query_map.update(queries)
        logger.info("Loaded %d %s queries from %s", len(queries), connector_name, queries_path)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to read %s queries from %s: %s", connector_name, queries_path, e)


def apply_credentials(
    credentials_path: str,
    connector_name: str,
    config: ConnectorConfig,
    key_map: dict[str, str],
) -> None:
    """Load credentials from file and apply to config attributes.

    The credentials file takes precedence over direct attributes.
    Format: JSON with keys matching the key_map values.

    Args:
        credentials_path: Path to JSON credentials file.
        connector_name: Name for log messages.
        config: The config object to set attributes on.
        key_map: Mapping of config_attr_name → json_key_name.
            e.g. {"token": "token", "username": "username"} for Splunk
            e.g. {"access_id": "access_id", "access_key": "access_key"} for SumoLogic
    """
    if not credentials_path:
        return
    creds = load_credentials_secure(credentials_path, connector_name)
    if creds is None:
        return
    for attr_name, json_key in key_map.items():
        if creds.get(json_key):
            setattr(config, attr_name, creds[json_key])


def validate_host_ssrf(host_url: str) -> tuple[set[str], str]:
    """Validate a host URL for SSRF and capture resolved IPs.

    Runs SSRF validation on the host URL and captures the resolved
    IP addresses for DNS rebinding detection later.

    Args:
        host_url: The SIEM host URL to validate.

    Returns:
        Tuple of (original_ips, hostname) where original_ips is the
        set of resolved IPs and hostname is the parsed hostname.

    Raises:
        ValueError: If SSRF validation fails.
    """
    import socket
    from urllib.parse import urlparse

    original_ips: set[str] = set()
    from nabla.ssrf import validate_connector_url
    is_valid, err = validate_connector_url(host_url)
    if not is_valid:
        raise ValueError(f"Host URL failed SSRF validation: {err}")

    hostname = urlparse(host_url).hostname or ""
    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        original_ips = {sa[0] for _, _, _, _, sa in resolved}
    except socket.gaierror:
        pass  # silent by design: hostname resolution absent (validation semantics) (2026-09 sweep)

    return original_ips, hostname


def warn_ssl_disabled(connector_name: str, host: str) -> None:
    """Log a warning when SSL verification is disabled."""
    logger.warning(
        "SSL verification is DISABLED for %s host %s. "
        "This exposes credentials to man-in-the-middle attacks. "
        "Set NABLA_%s_VERIFY_SSL=true in production.",
        connector_name, host, connector_name.upper(),
    )


def build_watchlist_clause(
    watchlist: Watchlist,
    field_map: dict[str, str | list[str]],
    connector_name: str,
) -> str:
    """Build a watchlist filter clause for a SIEM query.

    Args:
        watchlist: Entities to target (users, hosts, IPs).
        field_map: Mapping of entity type to query field name(s).
            String values are used directly as field names.
            List values generate multiple IN clauses joined by OR
            (e.g., ["src_ip", "client_ip"] for Splunk).
            e.g. {"user": "user", "host": "host", "ip": ["src_ip", "client_ip"]}
            e.g. {"user": "user", "host": "_sourceHost", "ip": "_sourceIP"}
        connector_name: Name for error messages.

    Returns:
        Filter clause like (user IN ("admin") OR host IN ("DC01")),
        or empty string if the watchlist is empty.
    """
    parts = []
    if watchlist.users:
        field = field_map["user"]
        quoted = ", ".join(f'"{escape_query_value(u)}"' for u in watchlist.users)
        parts.append(f"{field} IN ({quoted})")
    if watchlist.hosts:
        field = field_map["host"]
        quoted = ", ".join(f'"{escape_query_value(h)}"' for h in watchlist.hosts)
        parts.append(f"{field} IN ({quoted})")
    if watchlist.ips:
        field_spec = field_map["ip"]
        quoted = ", ".join(f'"{escape_query_value(ip)}"' for ip in watchlist.ips)
        if isinstance(field_spec, list):
            # Multiple fields for the same IP list (e.g., Splunk src_ip + client_ip)
            ip_parts = [f"{f} IN ({quoted})" for f in field_spec]
            parts.append(" OR ".join(ip_parts))
        else:
            parts.append(f"{field_spec} IN ({quoted})")

    if not parts:
        return ""
    return "(" + " OR ".join(parts) + ")"


def resolve_query(
    log_type: str,
    watchlist: Watchlist,
    query_map: dict[str, str],
    connector_name: str,
    field_map: dict[str, str | list[str]],
) -> str:
    """Resolve a query string, injecting watchlist filters.

    If the query contains {watchlist_clause}, it gets replaced with
    a constructed filter from the watchlist. Otherwise the query runs as-is.

    Args:
        log_type: One of "auth", "network", "dns", "endpoint".
        watchlist: Entities to filter on.
        query_map: Mapping of log type → query string.
        connector_name: Name for error messages.
        field_map: Field mapping for watchlist clause construction.

    Returns:
        The resolved query string.

    Raises:
        ValueError: If no query is configured for the log type.
    """
    query = query_map.get(log_type, "")
    if not query:
        raise ValueError(f"No {connector_name} query configured for log type '{log_type}'")

    if "{watchlist_clause}" in query:
        clause = build_watchlist_clause(watchlist, field_map, connector_name)
        query = query.replace("{watchlist_clause}", clause)
        if not clause:
            # Remove trailing whitespace or dangling search clauses
            # that might result from an empty watchlist
            query = query.rstrip()

    return query


def validate_output(
    logs: list[dict[str, Any]],
    log_type: str,
    connector_name: str,
    strict: bool = True,
) -> None:
    """Validate fetched logs against the canonical schema.

    Logs warnings for missing required fields but does not fail —
    partial data is better than no data.

    Args:
        logs: List of log dicts to validate.
        log_type: One of "auth", "network", "dns", "endpoint".
        connector_name: Name for log messages.
        strict: If True, check only the first log as representative (Splunk).
            If False, check what fraction of logs have each required field (SumoLogic).
    """
    if not logs:
        return

    schema = CANONICAL_SCHEMA.get(log_type)
    if not schema:
        return

    required = schema["required"]
    if strict:
        # Check first log as representative
        sample = logs[0]
        missing = [f for f in required if f not in sample]
        if missing:
            logger.warning(
                "%s %s query output missing required fields: %s. "
                "Update your NABLA_%s_%s_QUERY to include these fields.",
                connector_name, log_type, missing,
                connector_name.upper(), log_type.upper(),
            )

        optional = schema["optional"]
        present_optional = [f for f in optional if f in sample]
        logger.debug(
            "%s %s output: required=%s present, optional=%s present",
            connector_name, log_type,
            [f for f in required if f in sample],
            present_optional,
        )
    else:
        # Check what fraction of logs have each required field
        for req_field in required:
            present_count = sum(1 for log in logs if req_field in log)
            fraction = present_count / len(logs)
            if fraction < 0.1:
                logger.warning(
                    "%s %s query: only %d/%d (%.0f%%) logs have required field '%s'. "
                    "Update your NABLA_%s_%s_QUERY if this is unexpected.",
                    connector_name, log_type, present_count, len(logs),
                    fraction * 100, req_field,
                    connector_name.upper(), log_type.upper(),
                )

        optional = schema["optional"]
        present_optional = [f for f in optional if f in logs[0]]
        logger.debug(
            "%s %s output: required present=%s, optional present=%s",
            connector_name, log_type,
            [f for f in required if f in logs[0]],
            present_optional,
        )
