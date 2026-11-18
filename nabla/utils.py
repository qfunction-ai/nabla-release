"""Shared utility functions used across multiple modules.

Contains pure functions with no module-level side effects or heavy imports.
These are extracted from detection.py, baselines.py, and gcn_lof.py to
eliminate duplication while avoiding circular imports.
"""

import ipaddress
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def is_routable_ip(ip: str) -> bool:
    """Check if an IP address is publicly routable.

    Private (RFC 1918), loopback, link-local, unique-local IPv6,
    carrier-grade NAT, and benchmark addresses are NOT routable.
    Only public IPs should count toward impossible-travel detection.

    Args:
        ip: IP address string (IPv4 or IPv6).

    Returns:
        True if the IP is publicly routable, False otherwise.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Loopback
    if addr.is_loopback:
        return False
    # Link-local (fe80::/10, 169.254/16)
    if addr.is_link_local:
        return False
    # Private (10/8, 172.16/12, 192.168/16, fc00::/7)
    if addr.is_private:
        return False
    # Reserved / unspecified
    if addr.is_reserved or addr.is_unspecified:
        return False
    # Multicast
    if addr.is_multicast:
        return False
    return True


def is_off_hours(timestamp: str) -> bool:
    """Check if a timestamp falls in off-hours (22:00-06:00 UTC).

    Args:
        timestamp: ISO format timestamp string.

    Returns:
        True if the hour is < 6 or >= 22.
    """
    hour = _parse_hour(timestamp)
    if hour < 0:
        return False  # unparseable: not off-hours (A18)
    return hour < 6 or hour >= 22


# ---------------------------------------------------------------------------
# Path traversal protection — shared allowed directories
# ---------------------------------------------------------------------------

_ALLOWED_DIRS: list[Path] = [
    Path("/data").resolve(),
    Path("/tmp").resolve(),
    Path(tempfile.gettempdir()).resolve(),
]
# Add macOS temp dirs if they exist
_macos_tmp = Path("/private/tmp").resolve()
if _macos_tmp.exists() and _macos_tmp not in _ALLOWED_DIRS:
    _ALLOWED_DIRS.append(_macos_tmp)
_macos_var = Path("/private/var").resolve()
if _macos_var.exists() and _macos_var not in _ALLOWED_DIRS:
    _ALLOWED_DIRS.append(_macos_var)


def get_allowed_dirs() -> list[Path]:
    """Return the list of allowed directories for file path validation.

    Used by parsers and export/import to prevent path traversal attacks.
    Centralizes the allowed dirs list so it's defined once.

    Returns:
        List of resolved Path objects for allowed directories.
    """
    return list(_ALLOWED_DIRS)


def path_is_allowed(path: Path) -> bool:
    """Check if a resolved path falls within any allowed directory.

    Args:
        path: A resolved Path object.

    Returns:
        True if the path starts with an allowed directory.
    """
    return any(str(path).startswith(str(d)) for d in _ALLOWED_DIRS)


# ---------------------------------------------------------------------------
# Timestamp parsing — normalize ISO timestamps with timezone
# ---------------------------------------------------------------------------

def parse_iso_timestamp(ts: str) -> datetime | None:
    """Parse an ISO timestamp string and normalize timezone to UTC.

    Handles:
    - Z suffix (replace with +00:00 for fromisoformat)
    - Naive timestamps (assume UTC)
    - Already-timezone-aware timestamps (pass through)

    Args:
        ts: ISO format timestamp string.

    Returns:
        A timezone-aware datetime in UTC, or None if parsing fails.
    """
    if not ts:
        return None
    try:
        # Handle Z suffix that fromisoformat doesn't accept
        normalized = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Severity ordering — single source of truth
# ---------------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}



def _parse_hour(ts: str) -> int:
    """Hour-of-day (UTC) from an ISO timestamp, robust to offsets (A18).

    Replaces int(ts[11:13]) slices, which assume a specific ISO layout and
    read the LOCAL hour on offset timestamps instead of UTC.
    """
    dt = parse_iso_timestamp(str(ts))
    if dt is None:
        return -1  # unparseable: callers treat as not-off-hours
    return dt.astimezone(timezone.utc).hour
