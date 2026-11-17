"""Field name auto-detection and column mapping for log file normalization.

Maps common SIEM/EDR column names to Nabla's canonical field schema.
Supports both auto-detection (guessing from column names) and user-provided
column mapping overrides via CLI --map flag.
"""

from __future__ import annotations

# Canonical field → list of known aliases (case-insensitive, stripped of _ and -)
FIELD_ALIASES: dict[str, list[str]] = {
    "user": [
        "user", "username", "user_name", "src_user", "dst_user",
        "account", "account_name", "subjectusername", "targetusername",
        "login", "logonname",
    ],
    "source_ip": [
        "source_ip", "src_ip", "srcip", "source_address", "src_addr",
        "ipaddress", "sourceip", "src_host_ip",
        "client_ip", "clientip", "client_address",
    ],
    "dest_ip": [
        "dest_ip", "dst_ip", "dstip", "destination_ip", "dest_address",
        "destinationip", "dest_host_ip",
    ],
    "dest_host": [
        "dest_host", "dst_host", "destination_host", "target_host",
    ],
    "timestamp": [
        "timestamp", "time", "date", "event_time", "datetime", "utctime",
        "time_created", "creation_time", "eventtime", "starttime",
    ],
    "action": [
        "action", "event_type", "event_action", "status", "outcome",
        "eventname", "eventstatus",
    ],
    "process": [
        "process", "process_name", "image", "newprocessname",
        "application", "program", "executable",
    ],
    "parent_process": [
        "parent_process", "parent_image", "parentprocessname",
        "parentprocess", "parentexecutable",
    ],
    "parent_command_line": [
        "parent_command_line", "parentcommandline", "parent_cmd_line",
    ],
    "command_line": [
        "command_line", "commandline", "cmd_line", "process_command_line",
    ],
    "current_directory": [
        "current_directory", "currentdirectory", "working_directory",
    ],
    "host": [
        "host", "hostname", "computer_name", "computername",
        "machine_name", "dvc", "system_name",
    ],
    "domain": [
        "domain", "query", "query_name", "requested_domain", "dns_query",
    ],
    "dest_port": [
        "dest_port", "dst_port", "destination_port",
    ],
    "protocol": [
        "protocol", "proto", "transport_protocol",
    ],
    "event_code": [
        "event_code", "eventcode", "event_id", "eventid",
        "event_data_name",
    ],
    "integrity_level": [
        "integrity_level", "integritylevel", "mandatory_label",
    ],
    "source": [
        "source", "sourcetype", "log_source", "provider",
    ],
    "type": [
        "type", "log_type", "logtype", "record_type",
    ],
    "anomaly": [
        "anomaly", "anomaly_type", "alert_type", "flag",
    ],
    "details": [
        "details", "message", "description", "event_data", "info",
    ],
    "bytes": [
        "bytes", "bytes_sent", "bytes_received", "size",
    ],
    "query_type": [
        "query_type", "dns_type", "rrtype",
    ],
    "target_file": [
        "target_file", "targetfile", "file_path", "filepath",
        "file_target", "object_name", "targetfilename",
    ],
    "target_registry": [
        "target_registry", "targetregistry", "registry_key",
        "registrykey", "reg_key", "registry_path",
        "targetobject",  # Sysmon EventID 13 (Registry Value Set)
    ],
    "network_connection": [
        "network_connection", "networkconnection", "destination_address",
        "remote_address", "remote_server", "connection_target",
    ],
}


def _normalize_key(key: str) -> str:
    """Normalize a column name for comparison: lowercase, strip _ and -."""
    return key.lower().replace("_", "").replace("-", "").replace(" ", "")


def auto_detect_fields(columns: list[str]) -> dict[str, str]:
    """Map raw column names to canonical field names using FIELD_ALIASES.

    Args:
        columns: List of raw column names from the log file.

    Returns:
        Dict mapping canonical field name → raw column name.
        Only includes matches found in the column list.
    """
    # Build reverse lookup: normalized alias → (canonical_name, original_alias)
    reverse: dict[str, tuple[str, str]] = {}
    for canonical, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            norm = _normalize_key(alias)
            reverse[norm] = (canonical, alias)

    mapping: dict[str, str] = {}
    used_columns: set[str] = set()

    for col in columns:
        norm_col = _normalize_key(col)
        if norm_col in reverse:
            canonical, _ = reverse[norm_col]
            # Don't overwrite an earlier match
            if canonical not in mapping:
                mapping[canonical] = col
                used_columns.add(col)

    return mapping


def apply_column_map(
    auto_map: dict[str, str],
    user_map: dict[str, str],
) -> dict[str, str]:
    """Merge auto-detected field mapping with user-provided overrides.

    Args:
        auto_map: Auto-detected mapping (canonical → raw column name).
        user_map: User overrides (canonical → raw column name).

    Returns:
        Merged mapping with user overrides taking precedence.
    """
    merged = dict(auto_map)
    merged.update(user_map)
    return merged


def parse_column_map_string(map_str: str) -> dict[str, str]:
    """Parse a CLI --map string into a dict.

    Format: "canonical=raw_col,canonical2=raw_col2"
    Example: "user=UserName,source_ip=Src_IP"

    Args:
        map_str: Comma-separated key=value pairs.

    Returns:
        Dict mapping canonical field name → raw column name.

    Raises:
        ValueError: If the format is invalid.
    """
    result: dict[str, str] = {}
    if not map_str:
        return result

    for pair in map_str.split(","):
        pair = pair.strip()
        if "=" not in pair:
            raise ValueError(
                f"Invalid column mapping: {pair!r}. "
                "Expected format: canonical=raw_col"
            )
        key, value = pair.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value:
            raise ValueError(
                f"Invalid column mapping: {pair!r}. "
                "Both canonical and raw column names must be non-empty."
            )
        result[key] = value

    return result


def infer_log_type(entries: list[dict]) -> str:
    """Infer log type from field names in the parsed entries.

    Args:
        entries: List of normalized log dicts.

    Returns:
        One of "auth", "network", "dns", "endpoint", or "auth" as default.
    """
    if not entries:
        return "auth"

    sample = entries[0]
    fields = set(sample.keys())

    # DNS: has domain or query_type
    if "domain" in fields or "query_type" in fields:
        return "dns"

    # Network: has source_ip + dest_ip or dest_port
    if ("source_ip" in fields) and (
        "dest_ip" in fields or "dest_port" in fields
    ):
        return "network"

    # Endpoint: has process or parent_process or command_line
    if "process" in fields or "parent_process" in fields or "command_line" in fields:
        return "endpoint"

    # Auth: has action with login_ prefix, or event_code
    if "action" in fields:
        action_val = str(sample.get("action", "")).lower()
        if "login" in action_val or "logon" in action_val or "logoff" in action_val:
            return "auth"

    # Default
    return "auth"
