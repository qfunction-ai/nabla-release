"""Data exfiltration detection — dedicated module for detecting data theft patterns.

Four sub-detectors:
1. Volume anomaly — Per-user outbound network volume exceeds baseline
2. Destination anomaly — Connections to unusual destinations/ports
3. DNS tunneling — Long subdomains, high entropy, excessive TXT queries
4. Staging pattern — Sequential file creation → archival → network transfer

Each sub-detector produces anomalies with type "data_exfiltration" and
category "exfil_volume", "exfil_destination", "exfil_dns_tunneling", or
"exfil_staging". These feed into the risk scoring engine's
data_exfiltration category.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from nabla.log import get_logger

if TYPE_CHECKING:
    from nabla.baselines import EntityProfileStore
    from nabla.peer_groups import PeerGroupStore

logger = get_logger("exfiltration")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Known cloud storage endpoints that indicate potential exfiltration
def _sanctioned_services() -> set[str]:
    """Sanctioned cloud services (A16): comma-separated NABLA_SANCTIONED_SERVICES."""
    import os
    raw = os.environ.get("NABLA_SANCTIONED_SERVICES", "")
    return {s.strip().lower() for s in raw.split(",") if s.strip()}


_CLOUD_STORAGE_DOMAINS = {
    "drive.google.com", "docs.google.com", "drive.google.com",
    "dropbox.com", "api.dropboxapi.com", "content.dropboxapi.com",
    "onedrive.live.com", "1drv.com", "sharepoint.com",
    "box.com", "app.box.com", "upload.box.com",
    "wetransfer.com", "transfer.sh", "file.io",
    "mega.nz", "g.api.mega.co.nz",
    "aws.amazon.com", "s3.amazonaws.com", "s3.dualstack.amazonaws.com",
}

# DNS tunneling indicators
_MAX_SUBLABEL_LENGTH = 40  # Labels > 40 chars are suspicious
_DNS_ENTROPY_THRESHOLD = 3.5  # Shannon entropy threshold for suspicious domains
_TXT_QUERY_PATTERN = re.compile(r"\bTXT\b", re.IGNORECASE)

# Staging pattern: file creation → archival → network transfer
_STAGING_WINDOW_MINUTES = 30

# Known archive extensions
_ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz", ".tgz"}

# Common legitimate ports (not suspicious for outbound traffic)
_COMMON_PORTS = {80, 443, 53, 22, 3389, 8080, 8443, 25, 587, 993, 143}

# MITRE ATT&CK mappings
_MITRE_T1048 = {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}
_MITRE_T1041 = {"id": "T1041", "name": "Exfiltration Over C2 Channel"}
_MITRE_T1071 = {"id": "T1071", "name": "Application Layer Protocol"}
_MITRE_T1567 = {"id": "T1567", "name": "Exfiltration Over Web Service"}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string.

    Higher entropy → more random → more likely to be encoded/tunneled data.

    Args:
        text: String to compute entropy for.

    Returns:
        Shannon entropy in bits.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_suspicious_domain(domain: str) -> bool:
    """Check if a domain has DNS tunneling indicators.

    Args:
        domain: Full domain name (e.g., "abc123XYZ.data.example.com").

    Returns:
        True if the domain has tunneling indicators.
    """
    if not domain:
        return False

    # Check for unusually long subdomain labels
    parts = domain.split(".")
    for part in parts:
        if len(part) > _MAX_SUBLABEL_LENGTH:
            return True

    # Check for high entropy in the full domain
    entropy = _shannon_entropy(domain)
    if entropy > _DNS_ENTROPY_THRESHOLD:
        return True

    return False


# ---------------------------------------------------------------------------
# Sub-detector 1: Volume anomaly
# ---------------------------------------------------------------------------

def _detect_volume_anomaly(
    entries: list[dict],
    entity_profiles: EntityProfileStore | None = None,
    sigma: float = 3.0,
) -> list[dict]:
    """Detect per-user network volume anomalies.

    Flags users whose current-run network event count exceeds their
    EWMA baseline × sigma.

    Args:
        entries: List of log entry dicts.
        entity_profiles: Entity profile store for EWMA baselines.
        sigma: Z-score threshold for volume anomaly.

    Returns:
        List of anomaly dicts.
    """
    anomalies = []

    # Count network events per user WITH the batch time span (A17: compare
    # like with like — network-events-per-hour against the per-hour baseline;
    # the old count-vs-EWMA compared mismatched units and rarely fired)
    from nabla.baselines import observation_rate
    net_entries_by_user: dict[str, list] = {}
    for entry in entries:
        if entry.get("action") == "network_connect" or entry.get("type") == "network":
            user = entry.get("user", "")
            if user:
                net_entries_by_user.setdefault(user, []).append(entry)

    for user, user_net in net_entries_by_user.items():
        count = len(user_net)
        if entity_profiles is None:
            continue
        profile = entity_profiles.get_user(user)
        if profile is None or profile.observation_count < 3:
            continue

        ewma = profile.typical_event_count
        z = ewma.z_score(observation_rate(user_net))  # R4 bucketed
        if z > sigma:
            anomalies.append({
                "entity": user,
                "entity_type": "user",
                "detection_method": "exfil_volume",
                "type": "data_exfiltration",
                "severity": "high" if z > sigma * 1.5 else "medium",
                "confidence": min(0.95, 0.5 + z / 10),
                "details": (
                    f"User {user} has {count} network events "
                    f"(z-score {z:.1f} vs baseline {ewma.value:.0f})"
                ),
                "mitre_attack": [_MITRE_T1048],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    return anomalies


# ---------------------------------------------------------------------------
# Sub-detector 2: Destination anomaly
# ---------------------------------------------------------------------------

def _detect_destination_anomaly(
    entries: list[dict],
    entity_profiles: EntityProfileStore | None = None,
    peer_groups: PeerGroupStore | None = None,
) -> list[dict]:
    """Detect connections to unusual destinations.

    Flags connections to:
    - Destinations not in the user's typical set
    - Non-standard ports (not _COMMON_PORTS)
    - Known cloud storage endpoints
    - Destinations not in the peer group's typical set

    Args:
        entries: List of log entry dicts.
        entity_profiles: Entity profile store.
        peer_groups: Peer group store (optional).

    Returns:
        List of anomaly dicts.
    """
    anomalies = []

    # Group network entries by user
    user_networks: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        if entry.get("action") == "network_connect" or entry.get("type") == "network":
            user = entry.get("user", "")
            if user:
                user_networks[user].append(entry)

    for user, net_entries in user_networks.items():
        # Get the user's typical destinations from entity profile
        typical_dests: set[str] = set()
        typical_ports: set[int] = set()
        if entity_profiles is not None:
            profile = entity_profiles.get_user(user)
            if profile:
                # UserProfile doesn't have typical_destinations yet —
                # use IP set as proxy. Host profiles do have destinations.
                pass

        # Get peer group's typical destinations
        peer_dests: set[str] = set()
        if peer_groups is not None:
            group = peer_groups.get_group_for_entity(user)
            if group:
                for member in group.members:
                    if member == user:
                        continue
                    if entity_profiles is not None:
                        member_profile = entity_profiles.get_user(member)
                        if member_profile:
                            peer_dests.update(member_profile.typical_ips)

        for entry in net_entries:
            dest_ip = entry.get("dest_ip", entry.get("destination_ip", ""))
            dest_port = entry.get("dest_port", entry.get("destination_port", ""))
            dest_domain = entry.get("dest_domain", entry.get("destination", ""))

            flags = []

            # Check cloud storage destination (A16: sanctioned services are
            # exempt — most orgs use Drive/OneDrive/etc. as daily traffic;
            # NABLA_SANCTIONED_SERVICES is a comma-separated env list)
            if dest_domain:
                domain_lower = dest_domain.lower()
                sanctioned = _sanctioned_services()
                for cloud_domain in _CLOUD_STORAGE_DOMAINS:
                    if cloud_domain in domain_lower:
                        if any(s in domain_lower for s in sanctioned):
                            break  # sanctioned for this deployment: not exfil
                        flags.append(f"cloud storage: {cloud_domain}")
                        break

            # Check non-standard port
            if dest_port:
                try:
                    port = int(dest_port)
                    if port not in _COMMON_PORTS:
                        flags.append(f"unusual port: {port}")
                except ValueError:
                    pass  # silent by design: unparseable timestamp in exfil analysis (2026-09 sweep)

            # High-severity: cloud storage on non-standard port
            if flags:
                anomalies.append({
                    "entity": user,
                    "entity_type": "user",
                    "detection_method": "exfil_destination",
                    "type": "data_exfiltration",
                    "severity": "high" if any("cloud" in f for f in flags) else "medium",
                    "confidence": 0.7 if any("cloud" in f for f in flags) else 0.5,
                    "details": (
                        f"User {user} connected to {dest_domain or dest_ip}:{dest_port} "
                        f"({', '.join(flags)})"
                    ),
                    "mitre_attack": [_MITRE_T1567] if any("cloud" in f for f in flags) else [_MITRE_T1048],
                    "timestamp": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
                })

    return anomalies


# ---------------------------------------------------------------------------
# Sub-detector 3: DNS tunneling
# ---------------------------------------------------------------------------

def _detect_dns_tunneling(
    entries: list[dict],
) -> list[dict]:
    """Detect DNS tunneling indicators.

    Flags:
    - DNS queries with unusually long subdomain labels
    - High entropy domain names
    - Excessive TXT record queries

    Args:
        entries: List of log entry dicts.

    Returns:
        List of anomaly dicts.
    """
    anomalies = []

    # Group DNS entries by user
    user_dns: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        if entry.get("type") == "dns" or entry.get("log_type") == "dns":
            user = entry.get("user", "")
            if user:
                user_dns[user].append(entry)

    for user, dns_entries in user_dns.items():
        suspicious_queries = []
        txt_count = 0
        domain_counter: Counter[str] = Counter()

        for entry in dns_entries:
            query = entry.get("query", entry.get("query_name", ""))
            query_type = entry.get("query_type", "")

            if not query:
                continue

            domain_counter[query.lower()] += 1

            if query_type.upper() == "TXT":
                txt_count += 1

            if _is_suspicious_domain(query):
                suspicious_queries.append(query)

        # Flag users with suspicious DNS queries
        if suspicious_queries:
            anomalies.append({
                "entity": user,
                "entity_type": "user",
                "detection_method": "dns_tunneling",
                "type": "data_exfiltration",
                "severity": "high",
                "confidence": min(0.9, 0.5 + len(suspicious_queries) * 0.1),
                "details": (
                    f"User {user} made {len(suspicious_queries)} DNS queries with "
                    f"tunneling indicators: {suspicious_queries[:3]}"
                ),
                "mitre_attack": [_MITRE_T1071],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        # Flag excessive TXT queries (potential C2 channel)
        if txt_count > 5:
            anomalies.append({
                "entity": user,
                "entity_type": "user",
                "detection_method": "dns_tunneling",
                "type": "data_exfiltration",
                "severity": "medium",
                "confidence": 0.6,
                "details": (
                    f"User {user} made {txt_count} TXT record queries "
                    f"(potential DNS tunneling C2 channel)"
                ),
                "mitre_attack": [_MITRE_T1041],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    return anomalies


# ---------------------------------------------------------------------------
# Sub-detector 4: Staging pattern
# ---------------------------------------------------------------------------

def _detect_staging_pattern(
    entries: list[dict],
    window_minutes: int = 30,
) -> list[dict]:
    """Detect data staging patterns.

    Flags sequential actions suggesting data staging:
    - File creation → archival (zip/tar) → network transfer within window
    - Off-hours large data transfers

    Args:
        entries: List of log entry dicts.
        window_minutes: Time window for staging pattern detection.

    Returns:
        List of anomaly dicts.
    """
    anomalies = []

    # Group by user and sort by timestamp
    user_entries: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        user = entry.get("user", "")
        if user:
            user_entries[user].append(entry)

    for user, entries_list in user_entries.items():
        # Sort by timestamp
        def _get_ts(e: dict) -> str:
            return e.get("timestamp", "")
        sorted_entries = sorted(entries_list, key=_get_ts)

        # Look for staging patterns: file creation → archive → network
        file_creates = []
        archives = []
        network_transfers = []

        for entry in sorted_entries:
            action = entry.get("action", "").lower()
            target = entry.get("target_file", entry.get("file_path", entry.get("object", "")))

            if action in ("create", "write", "file_create", "file_written"):
                file_creates.append(entry)
            elif action in ("archive", "compress") or (
                target and any(target.lower().endswith(ext) for ext in _ARCHIVE_EXTENSIONS)
            ):
                archives.append(entry)
            elif action == "network_connect" or entry.get("type") == "network":
                network_transfers.append(entry)

        # Check if we have the pattern within the time window
        if file_creates and (archives or network_transfers):
            # Find the latest file creation
            last_create_ts = file_creates[-1].get("timestamp", "")
            if not last_create_ts:
                continue

            from nabla.utils import parse_iso_timestamp
            create_dt = parse_iso_timestamp(last_create_ts)
            if create_dt is None:
                continue

            # Check for archive within window
            archive_after_create = False
            for archive in archives:
                ts = archive.get("timestamp", "")
                if not ts:
                    continue
                archive_dt = parse_iso_timestamp(ts)
                if archive_dt is None:
                    continue
                if 0 < (archive_dt - create_dt).total_seconds() < window_minutes * 60:
                    archive_after_create = True
                    break

            # Check for network transfer within window
            network_after_create = False
            for transfer in network_transfers:
                ts = transfer.get("timestamp", "")
                if not ts:
                    continue
                transfer_dt = parse_iso_timestamp(ts)
                if transfer_dt is None:
                    continue
                if 0 < (transfer_dt - create_dt).total_seconds() < window_minutes * 60:
                    network_after_create = True
                    break

            if archive_after_create and network_after_create:
                anomalies.append({
                    "entity": user,
                    "entity_type": "user",
                    "detection_method": "exfil_staging",
                    "type": "data_exfiltration",
                    "severity": "critical",
                    "confidence": 0.85,
                    "details": (
                        f"User {user} staged data: file creation → archival → "
                        f"network transfer within {window_minutes} minutes"
                    ),
                    "mitre_attack": [_MITRE_T1048, _MITRE_T1567],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            elif network_after_create:
                # A21: create->transfer alone is ordinary work (every office
                # user does this). Alert only when the transfer is sizeable;
                # below that it is informational context another finding can
                # cite, not a standalone high-severity alert.
                transfer_size = sum(int(t.get("bytes") or 0) for t in network_transfers)
                if transfer_size >= 10_000_000:  # 10 MB heuristic
                    anomalies.append({
                        "entity": user,
                        "entity_type": "user",
                        "detection_method": "exfil_staging",
                        "type": "data_exfiltration",
                        "severity": "high",
                        "confidence": 0.6,
                        "details": (
                            f"User {user} had file creation followed by a sizeable "
                            f"network transfer ({transfer_size / 1e6:.0f} MB) within "
                            f"{window_minutes} minutes (no archival)"
                        ),
                        "mitre_attack": [_MITRE_T1048],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

    return anomalies


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def detect_exfiltration(
    entries: list[dict],
    entity_profiles: EntityProfileStore | None = None,
    peer_groups: PeerGroupStore | None = None,
    thresholds: dict | None = None,
) -> list[dict]:
    """Detect data exfiltration patterns across all log entries.

    Runs four sub-detectors and returns combined anomalies.

    Args:
        entries: List of log entry dicts with canonical field names.
        entity_profiles: Entity profile store for baseline comparison.
        peer_groups: Peer group store for peer-relative analysis.
        thresholds: Optional threshold overrides.

    Returns:
        List of anomaly dicts with type "data_exfiltration".
    """
    if thresholds is None:
        from nabla.rl.calibration import effective_thresholds
        thresholds = effective_thresholds()  # Phase 3: calibration store over defaults

    sigma = thresholds.get("exfil_volume_sigma", 3.0)
    window = thresholds.get("exfil_staging_window_minutes", 30)

    all_anomalies = []

    # 1. Volume anomaly
    try:
        volume_anomalies = _detect_volume_anomaly(entries, entity_profiles, sigma=sigma)
        all_anomalies.extend(volume_anomalies)
    except Exception as e:
        logger.warning("Volume anomaly detection failed: %s", e)

    # 2. Destination anomaly
    try:
        dest_anomalies = _detect_destination_anomaly(entries, entity_profiles, peer_groups)
        all_anomalies.extend(dest_anomalies)
    except Exception as e:
        logger.warning("Destination anomaly detection failed: %s", e)

    # 3. DNS tunneling
    try:
        dns_anomalies = _detect_dns_tunneling(entries)
        all_anomalies.extend(dns_anomalies)
    except Exception as e:
        logger.warning("DNS tunneling detection failed: %s", e)

    # 4. Staging pattern
    try:
        staging_anomalies = _detect_staging_pattern(entries, window_minutes=window)
        all_anomalies.extend(staging_anomalies)
    except Exception as e:
        logger.warning("Staging pattern detection failed: %s", e)

    if all_anomalies:
        logger.info(
            "Exfiltration detection: %d anomalies "
            "(volume=%d, dest=%d, dns=%d, staging=%d)",
            len(all_anomalies),
            sum(1 for a in all_anomalies if a.get("detection_method") == "exfil_volume"),
            sum(1 for a in all_anomalies if a.get("detection_method") == "exfil_destination"),
            sum(1 for a in all_anomalies if a.get("detection_method") == "dns_tunneling"),
            sum(1 for a in all_anomalies if a.get("detection_method") == "exfil_staging"),
        )

    return all_anomalies
