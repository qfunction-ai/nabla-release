"""Watchlist management for targeted SIEM ingestion.

Watchlists define which entities (users, systems, IPs) to focus on
during ingestion. Empty watchlist = no ingestion (safe default).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Any

from nabla.log import get_logger

logger = get_logger("watchlist")

# Built-in group names (users can also add custom groups)
BUILTIN_GROUPS = ["high_value_users", "critical_systems", "watched_ips"]

# Entity validation patterns
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,253}$")

# Characters that must never appear in entity values — they could enable
# SPL injection or other query language attacks even after escaping.
_DANGEROUS_CHARS = set('|;`$\\{}[]!#&<>\'"')


def validate_entity(entity: str, group: str) -> str | None:
    """Validate an entity value for the given group type.

    Returns None if valid, or an error message string if invalid.
    """
    if not entity or len(entity) > 253:
        return f"Entity must be 1-253 characters, got {len(entity)}"

    # Reject SPL metacharacters even before format-specific validation
    dangerous = _DANGEROUS_CHARS.intersection(entity)
    if dangerous:
        return f"Entity contains dangerous characters: {', '.join(repr(c) for c in sorted(dangerous))}"

    if group == "watched_ips" or "ip" in group.lower() or "network" in group.lower():
        try:
            ipaddress.ip_address(entity)
        except ValueError:
            return f"Invalid IP address: {entity!r}"
    elif group in ("high_value_users",) or "user" in group.lower():
        if not _USERNAME_RE.match(entity):
            return f"Invalid username: {entity!r} (alphanumeric, dots, dashes, underscores only)"
    elif group in ("critical_systems",) or any(kw in group.lower() for kw in ("host", "system", "server")):
        if not _HOSTNAME_RE.match(entity):
            return f"Invalid hostname: {entity!r} (alphanumeric, dots, dashes, underscores only)"
    else:
        # Unknown group type — allow but validate against basic safety
        if not _USERNAME_RE.match(entity):
            return f"Invalid entity: {entity!r} (alphanumeric, dots, dashes, underscores only)"

    return None


def _default_watchlist() -> dict[str, Any]:
    """Return the default empty watchlist structure."""
    return {
        "high_value_users": [],
        "critical_systems": [],
        "watched_ips": [],
        "custom_groups": {},
    }


def load_watchlist(path: str) -> dict[str, Any]:
    """Load watchlist from a JSON file. Creates default if missing."""
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
        logger.debug("Loaded watchlist from %s (%d built-in groups)", path, len(BUILTIN_GROUPS))
        return data
    logger.info("Watchlist file not found at %s, creating default", path)
    data = _default_watchlist()
    save_watchlist(path, data)
    return data


def save_watchlist(path: str, data: dict[str, Any]) -> None:
    """Save watchlist to a JSON file."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    logger.debug("Saved watchlist to %s", path)


def add_entity(path: str, group: str, entity: str) -> None:
    """Add an entity to a watchlist group.

    Raises:
        ValueError: If the entity fails validation for the group type.
    """
    # Validate entity format
    validation_error = validate_entity(entity, group)
    if validation_error:
        raise ValueError(validation_error)

    from nabla.persistence import file_lock

    with file_lock(path):
        data = load_watchlist(path)

        if group in BUILTIN_GROUPS:
            if entity not in data[group]:
                data[group].append(entity)
            else:
                logger.debug("Entity '%s' already in group '%s'", entity, group)
                return
        elif group in data.get("custom_groups", {}):
            if entity not in data["custom_groups"][group]:
                data["custom_groups"][group].append(entity)
            else:
                logger.debug("Entity '%s' already in custom group '%s'", entity, group)
                return
        else:
            # Create new custom group
            if "custom_groups" not in data:
                data["custom_groups"] = {}
            data["custom_groups"][group] = [entity]
            logger.info("Created custom group '%s'", group)

        save_watchlist(path, data)
        logger.info("Added '%s' to group '%s'", entity, group)


def remove_entity(path: str, group: str, entity: str) -> None:
    """Remove an entity from a watchlist group."""
    from nabla.persistence import file_lock

    with file_lock(path):
        data = load_watchlist(path)

        if group in BUILTIN_GROUPS:
            if entity in data[group]:
                data[group].remove(entity)
            else:
                logger.debug("Entity '%s' not in group '%s'", entity, group)
                return
        elif group in data.get("custom_groups", {}):
            if entity in data["custom_groups"][group]:
                data["custom_groups"][group].remove(entity)
            # Remove empty custom groups
            if not data["custom_groups"][group]:
                del data["custom_groups"][group]
                logger.info("Removed empty custom group '%s'", group)
        else:
            logger.warning("Group '%s' not found", group)
            return

        save_watchlist(path, data)
        logger.info("Removed '%s' from group '%s'", entity, group)


def list_groups(path: str) -> dict[str, list[str]]:
    """Return all groups and their entities."""
    data = load_watchlist(path)
    result = {}
    for group in BUILTIN_GROUPS:
        result[group] = data.get(group, [])
    for group, entities in data.get("custom_groups", {}).items():
        result[group] = entities
    return result


def get_all_entities(path: str) -> dict[str, list[str]]:
    """Return entities aggregated by type: users, hosts, ips.

    Maps watchlist groups to entity categories:
    - high_value_users → users
    - critical_systems → hosts
    - watched_ips → ips
    - custom_groups → users (by default, unless group name contains 'host' or 'ip')
    """
    data = load_watchlist(path)
    users = list(data.get("high_value_users", []))
    hosts = list(data.get("critical_systems", []))
    ips = list(data.get("watched_ips", []))

    for group_name, entities in data.get("custom_groups", {}).items():
        name_lower = group_name.lower()
        if "ip" in name_lower or "network" in name_lower:
            ips.extend(entities)
        elif "host" in name_lower or "system" in name_lower or "server" in name_lower:
            hosts.extend(entities)
        else:
            users.extend(entities)

    # Deduplicate
    return {
        "users": list(dict.fromkeys(users)),
        "hosts": list(dict.fromkeys(hosts)),
        "ips": list(dict.fromkeys(ips)),
    }
