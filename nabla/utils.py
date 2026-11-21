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
# Machine accounts (F5)
# ---------------------------------------------------------------------------
#
# Behavioral baselines describe a PERSON. A service account has no habits to
# deviate from: `root` and `SYSTEM` doing privileged work at 03:00 is the job,
# not an anomaly. Scoring them produces incidents that are always wrong, and
# those incidents bury the ones that matter.
#
# The real dataset-v1 is 13 machine principals to 1 human (`helpdeskone`), so
# this is not a corner case — it is most of the population.
#
# The rules below are ordered from unambiguous to heuristic. Anything matched
# is EXCLUDED from behavioral baselining, never hidden: callers log what they
# excluded so an operator can see the decision and correct it.

# Windows machine accounts always end in '$' (WIN-SRV01$). Structural.
_MACHINE_SUFFIX = "$"

# Unix system principals. Fixed and well-known; these UIDs exist on every
# POSIX system and never belong to a person.
_UNIX_SYSTEM_PRINCIPALS = frozenset({
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "backup", "list", "irc", "gnats", "nobody",
    "adm", "operator", "halt", "shutdown", "ftp", "tss", "sshd", "ntp",
    "chrony", "messagebus", "syslog", "uuidd", "www-data", "httpd", "apache",
    "nginx", "mysql", "postgres", "redis", "mongodb", "elasticsearch",
    "systemd-network", "systemd-resolve", "systemd-timesync",
})

# Windows system principals, as they appear in Security event logs.
_WINDOWS_SYSTEM_PRINCIPALS = frozenset({
    "system", "local system", "network service", "local service",
    "anonymous logon", "defaultaccount", "wdagutilityaccount",
    "nt authority\\system", "nt authority\\local service",
    "nt authority\\network service", "nt authority\\anonymous logon",
})

# Naming conventions that declare "this is a service account".
_SERVICE_PREFIXES = ("svc-", "svc_", "svc.", "service-", "service_", "sa-", "sa_")
_SERVICE_SUFFIXES = ("-svc", "_svc", ".svc", "-service", "_service")

# Well-known automation and infrastructure principals with no structural
# marker. Curated rather than exhaustive — extend per environment with
# NABLA_MACHINE_ACCOUNTS (comma-separated) or NABLA_HUMAN_ACCOUNTS to force
# an account back into baselining.
_KNOWN_AUTOMATION = frozenset({
    "jenkins", "gitlab-runner", "github-actions", "runner", "buildbot",
    "ansible", "terraform", "puppet", "chef-client", "salt", "rundeck",
    "octopus", "bamboo", "teamcity", "circleci", "travis", "artifactory",
    "nexus", "sonar", "snyk", "aqua", "sysdig",
    "nagios", "zabbix", "icinga", "sensu", "prometheus", "grafana",
    "telegraf", "collectd", "datadog", "solarwinds", "kaseya", "lansweeper",
    "pdq", "tanium", "qualys", "nessus", "rapid7", "tenable",
    "wsus", "sccm", "vss", "intune", "jamf", "kandji",
    "splunk", "splunkd", "logstash", "filebeat", "winlogbeat", "metricbeat",
    "kafka", "zookeeper", "airflow", "nifi", "hadoop", "spark",
    "vcenter", "esxi", "vmware", "citrix", "okta", "duo",
    "ec2-user", "gce-user", "azureuser", "cloud-user",
})

# Values that mean "no user recorded", not "a user we do not know".
_PLACEHOLDER_PRINCIPALS = frozenset({
    "", "-", "--", "n/a", "na", "none", "null", "nil", "unknown", "?",
    "0", "nouser", "no user",
})


def is_machine_account(name: str, extra: set[str] | None = None) -> bool:
    """True if `name` is a machine/service principal rather than a person.

    Behavioral baselines describe people. A service account has no habits to
    deviate from, so scoring one produces incidents that are always wrong and
    drown out the ones that matter.

    Args:
        name: The account name as it appears in the logs.
        extra: Additional names to treat as machine accounts (environment
            specific, from NABLA_MACHINE_ACCOUNTS).

    Returns:
        True if the account should be excluded from behavioral baselining.
    """
    if name is None:
        return True
    raw = str(name).strip()
    lowered = raw.lower()

    if lowered in _PLACEHOLDER_PRINCIPALS:
        return True
    if extra and lowered in {e.strip().lower() for e in extra}:
        return True
    # Windows machine account: trailing '$'
    if raw.endswith(_MACHINE_SUFFIX):
        return True
    if lowered in _UNIX_SYSTEM_PRINCIPALS or lowered in _WINDOWS_SYSTEM_PRINCIPALS:
        return True
    if lowered in _KNOWN_AUTOMATION:
        return True
    if lowered.startswith(_SERVICE_PREFIXES) or lowered.endswith(_SERVICE_SUFFIXES):
        return True
    return False


def machine_account_overrides() -> set[str]:
    """Environment-specific machine accounts via Settings (N9: the raw
    env read was unreachable in Docker — compose doesn't forward it)."""
    from nabla.config import get_settings

    raw = get_settings().machine_accounts or ""
    return {part.strip() for part in raw.split(",") if part.strip()}


def human_account_overrides() -> set[str]:
    """Accounts forced back into baselining, from NABLA_HUMAN_ACCOUNTS.

    The escape hatch for a false positive: an operator who knows `ftp` is a
    person at their site should not have to patch the code.
    """
    from nabla.config import get_settings

    raw = get_settings().human_accounts or ""
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def is_baselineable_user(name: str) -> bool:
    """True if this user should be behaviorally baselined.

    Combines the machine-account predicate with the human override, which
    always wins.
    """
    if str(name).strip().lower() in human_account_overrides():
        return True
    return not is_machine_account(name, extra=machine_account_overrides())


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
    # R17: convert to the SITE timezone before taking the hour (UTC default
    # preserved; a fixed UTC window mislabeled every non-UTC organization)
    try:
        from zoneinfo import ZoneInfo
        from nabla.config import get_settings
        tz_name = get_settings().timezone or "UTC"
        target = ZoneInfo(tz_name) if tz_name != "UTC" else timezone.utc
    except Exception:
        target = timezone.utc
    return dt.astimezone(target).hour


def hour_is_unusual(counts: dict[int, float], hour: int,
                    min_share: float = 0.02, min_total: float = 50.0) -> bool:
    """R10 (round 3): share-based hour-unusualness.

    Binary typical_hours membership couldn't represent '2% of activity at
    night, consistently' — sparse-night users fired entity-off-hours on
    every quiet-hour blip (the harness xfail's diagnosis). A decayed
    histogram with a share threshold can.
    """
    total = sum(counts.values())
    return total >= min_total and counts.get(hour, 0.0) / total < min_share
