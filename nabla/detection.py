"""Deterministic anomaly detection — no LLM involved.

Extracts the detection logic from the former anomaly agent tools into
plain Python functions that operate on lists of log dicts. No Letta client,
no env vars, no context window limit. Processes all events.

Detection methods:
1. Pre-flagged anomalies (from log source)
2. Z-score on per-user event counts (> threshold sigma from mean)
3. Failed login ratio (brute force: > threshold% failures)
4. Off-hours activity (events between 22:00-06:00 UTC)
5. Multi-IP for single user (impossible travel heuristic)
6. Activity spike (> threshold x mean event count)
7. LOLBIN abuse (suspicious command-line patterns in endpoint logs)
8. Suspicious parent-child process relationships
9. Critical host privilege escalation
10. Unusual process per host (vs historical baseline)
10b. Known attack script execution (LinEnum, Mimikatz, etc.)
10c. Enumeration behavior detection (rapid child spawning, sensitive path
     access, enumeration command patterns — catches renamed scripts)
10d. Renamed attack tool detection (distinctive command-line signatures
     from Rubeus, Mimikatz, SharpHound, etc. — catches renamed binaries)
11. Rapid action sequence (lateral movement / cleanup)
20. EWMA drift (gradual rate increase that z-score misses)
21. CUSUM shift (sustained small shift accumulation)
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from nabla.log import get_logger
from nabla.utils import is_routable_ip

if TYPE_CHECKING:
    from nabla.baselines import EntityProfileStore
    from nabla.connectors.base import Watchlist

logger = get_logger("detection")

# Default thresholds — derived from THRESHOLDS in rl/calibration.py (Phase 3)
from nabla.rl.calibration import THRESHOLDS as _CAL_THRESHOLDS
DEFAULT_THRESHOLDS = {name: default for name, (_, _, _, default) in _CAL_THRESHOLDS.items()}

# Hardcoded LOLBIN signatures — fallback when lolbin_db block is empty
FALLBACK_LOLBIN_SIGS = [
    ("certutil", ["urlcache", "download", "-f", "verifyctl"], ["T1105", "T1140"]),
    ("mshta", ["http://", "https://", "vbscript"], ["T1218"]),
    ("wscript", [".vbs", ".js"], ["T1059"]),
    ("cscript", [".vbs", ".js"], ["T1059"]),
    ("regsvr32", ["/i:http", "scrobj.dll"], ["T1218"]),
    ("rundll32", ["javascript:", "http://"], ["T1218", "T1085"]),
    ("bitsadmin", ["/transfer", "/download"], ["T1105"]),
    ("powershell", ["-enc", "-encodedcommand", "frombase64string", "invoke-expression", "iex", "-w hidden"], ["T1059"]),
    ("wmic", ["process call create", "/node:"], ["T1047"]),
]

# Minimal fallback list for known attack scripts when the ATT&CK STIX bundle
# is unavailable. The primary source is build_tool_name_index() from attack.py,
# which extracts 800+ tool/malware names from the STIX bundle automatically.
# This fallback covers the most common tools that might not match by exact name.
_FALLBACK_ATTACK_SCRIPTS: dict[str, tuple[str, str]] = {
    "linenum.sh": ("Linux local enumeration", "T1082"),
    "linenum": ("Linux local enumeration", "T1082"),
    "linuxprivchecker": ("Linux privilege escalation check", "T1055"),
    "unix-privesc-check": ("Unix privilege escalation check", "T1055"),
    "pspy": ("Process snooping without root", "T1057"),
    "mimikatz": ("Credential dumping", "T1003"),
    "rubeus": ("Kerberos attack tool", "T1558"),
    "bloodhound": ("Active Directory reconnaissance", "T1087"),
    "sharphound": ("Active Directory reconnaissance", "T1087"),
    "seatbelt": (".NET security audit tool", "T1082"),
    "winpeas": ("Windows privilege escalation check", "T1055"),
    "linpeas": ("Linux privilege escalation check", "T1055"),
    "lazagne": ("Credential recovery tool", "T1003"),
    "crackmapexec": ("Post-exploitation framework", "T1021"),
    "responder": ("LLMNR/NBT-NS poisoner", "T1557"),
    "nmap -": ("Network reconnaissance", "T1046"),
    "recon-ng": ("Web reconnaissance framework", "T1593"),
    "empire": ("Post-exploitation framework", "T1059"),
    "covenant": (".NET post-exploitation framework", "T1059"),
    "sliver": ("C2 framework", "T1071"),
    "havoc": ("C2 framework", "T1071"),
    "chisel": ("Tunneling proxy", "T1572"),
    "ligolo": ("Tunneling proxy", "T1572"),
    "socat tcp-listen": ("Port forwarding/relay", "T1572"),
    "cobaltstrike": ("Cobalt Strike C2 framework", "T1071"),
    "carbonstrike": ("Cobalt Strike variant", "T1071"),
    "beacon.exe": ("Cobalt Strike beacon", "T1071"),
    "teamserver": ("Cobalt Strike team server", "T1071"),
    "metasploit": ("Metasploit framework", "T1059"),
    "msfconsole": ("Metasploit console", "T1059"),
    "msfvenom": ("Metasploit payload generator", "T1059"),
    "hydra": ("Brute force tool", "T1110"),
    "hashcat": ("Password cracker", "T1110"),
    "impacket": ("Impacket framework", "T1021"),
    "secretsdump": ("Impacket credential dumper", "T1003"),
    "wmiexec": ("Impacket WMI exec", "T1021"),
    "smbexec": ("Impacket SMB exec", "T1021"),
    "psexec.py": ("Impacket PsExec", "T1021"),
    "atexec": ("Impacket scheduled task exec", "T1053"),
    "certify": ("AD CS abuse tool", "T1558"),
    "certipy": ("AD CS abuse tool", "T1558"),
    "godpotato": ("Token impersonation exploit", "T1548"),
    "juicypotato": ("Token impersonation exploit", "T1548"),
    "printspoofer": ("Print spooler exploit", "T1548"),
    "roguepotato": ("Token impersonation exploit", "T1548"),
    "safetykatz": ("Credential dumping (GhostPack)", "T1003"),
    "sharpdpapi": ("DPAPI credential access (GhostPack)", "T1003"),
}

# Legitimate enterprise tool paths — processes from these paths are NOT LOLBINs
# even if their filename matches a LOLBIN signature (e.g., splunk-powershell.exe)
LEGITIMATE_TOOL_PATHS = {
    "\\splunkuniversalforwarder\\",
    "\\splunk\\bin\\",
    "\\microsoft monitoring agent\\",
    "\\program files\\microsoft\\",
    "\\programdata\\microsoft\\",
    "\\windows\\defender\\",
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\program files\\windows defender\\",
}

SUSPICIOUS_PARENTS = {
    "winword", "excel", "powerpnt", "outlook",
    "acrobat", "reader", "chrome", "firefox",
    "thunderbird", "acrord32",
}

ESCALATION_CMD_PATTERNS = [
    "sudo", "runas", "sedebugprivilege", "setakeownershipprivilege",
    "seloaddriverprivilege", "su -", "su root", "pkexec",
]

UAC_BYPASS_PARENTS = {"fodhelper", "eventvwr", "compmgmtlauncher", "slui"}

ESCALATION_PROCESSES = {"sudo", "su", "runas", "psexec", "pkexec"}

COMMON_PROCESSES = {
    "explorer", "svchost", "csrss", "lsass", "services",
    "winlogon", "dwm", "taskhostw", "smss", "conhost",
    "runtimebroker", "sihost", "taskhost", "ctfmon",
}

# Suspicious file paths — processes running from unusual locations
# Each entry: (friendly_name, regex_pattern)
SUSPICIOUS_PATH_PATTERNS = [  # noqa: E241
    ("perflogs",     r"\\PerfLogs\\"),           # Rarely used legitimately
    ("appdata",      r"\\AppData\\"),            # User app data — common malware staging
    ("public",       r"\\Public\\"),             # C:\Users\Public — world-writable
    ("win_temp",     r"\\Windows\\Temp\\"),      # Temp directory — common dropper location
    ("temp",         r"\\Temp\\"),               # Any temp directory
    ("programdata",  r"\\ProgramData\\"),        # ProgramData — world-writable, hidden
    ("downloads",    r"\\Downloads\\"),          # Downloads — user-introduced files
    ("shallow_path", r"^C:\\[^\\]+\\[^\\]+$"),  # Shallow paths like C:\Intel\LB3.exe (exactly 2 levels)
]

# Known legitimate Windows paths — processes from these are NOT suspicious
LEGITIMATE_PATHS = [
    r"\\Windows\\System32\\",
    r"\\Windows\\SysWOW64\\",
    r"\\Windows\\winsxs\\",
    r"\\Program Files\\",
    r"\\Program Files (x86)\\",
    r"\\SplunkUniversalForwarder\\",
    r"\\Windows\\SoftwareDistribution\\",
    r"\\Windows\\servicing\\",
    r"\\Windows\\assembly\\",
    r"\\Windows\\Explorer.EXE$",      # Explorer shell
    r"\\Windows\\regedit.exe$",       # Registry editor
    r"\\Windows\\notepad.exe$",       # Notepad
    r"\\Windows\\winhlp32.exe$",      # Help
    r"\\Windows\\write.exe$",         # WordPad
    r"\\Windows\\splwow64.exe$",      # Print driver
    r"\\Windows\\System32\\",         # Already covered, but keep for safety
]

# Registry keys that are high-value targets for attackers
CRITICAL_REGISTRY_PATTERNS = [
    r"CurrentVersion\\Run",           # Persistence
    r"CurrentVersion\\RunOnce",       # Persistence
    r"CurrentVersion\\Policies",      # Policy manipulation
    r"CurrentVersion\\Image File",    # Image File Execution Options (debugger injection)
    r"WINEVT\\Channels",             # Event logging configuration (defense evasion)
    r"CurrentVersion\\WINEVT",       # Same, alternate path
    r"Services\\",                    # Service registration
    r"CurrentControlSet\\Services",   # Service configuration
]

# Known system parents — processes that legitimately spawn children as SYSTEM
# Stored without .exe suffix (code normalizes by stripping .exe before lookup)
SYSTEM_PARENTS = {
    "services", "wininit", "lsass", "csrss",
    "svchost", "smss", "taskhostw", "dwm",
    "splunkd", "splunk-powershell", "splunk-netmon",
    "splunk-regmon", "splunk-monitornohandle",
}


def _get_field(entry: dict, *names: str) -> str:
    """Get the first non-empty value from a list of field name candidates.

    Args:
        entry: Dictionary to search for values.
        names: Field name candidates, checked in order.

    Returns:
        The first non-empty value found, or empty string.
    """
    for n in names:
        v = entry.get(n)
        if v:
            return v
    return ""


def _parse_ts(ts: str) -> datetime | None:
    """Parse an ISO timestamp; None when absent/unparseable."""
    from nabla.utils import parse_iso_timestamp
    return parse_iso_timestamp(ts)


def _newest_event_time(entries: list[dict]) -> str:
    """N2.3 (round 4): an anomaly must carry EVENT time or risk scoring
    treats it as absent — ten detectors shipped `"timestamp": ""` and their
    anomalies silently contributed nothing to risk once absent-means-absent
    landed (the harness caught it: attack fired, score stayed 0.0). Newest
    triggering event's raw stamp; empty string when the events carry none
    (genuinely absent data stays absent — the degradation counts it).
    """
    best = ""
    for e in entries:
        ts = e.get("timestamp", "")
        if ts > best:
            best = ts
    return best


def _event_hour_of(e: dict) -> int:
    """S3 (round 5): the local hour of an event entry, for slicing an
    entity's events into atypical-hour evidence. Returns -1 when the
    stamp is unparseable (such events are never off-hours evidence)."""
    ts = e.get("timestamp", "")
    if not ts:
        return -1
    try:
        from nabla.utils import _parse_hour
        return _parse_hour(ts)
    except (ValueError, IndexError):
        return -1


def _contributing_ids(entries: list[dict], cap: int = 50) -> list[str]:
    """S3 (round 5): the stable event ids of the events an aggregate
    anomaly was actually DERIVED from.

    The round-4 stamping pass linked aggregates to whatever shared the
    user's newest timestamp — a brute-force ratio got linked to the
    certutil event that happened last, and distinct attack steps merged
    below the chain minimum. Aggregate detectors now pass their own
    contributing slice (the failed logins, the new-IP logins, the
    atypical-hour events) so the anomaly cites its evidence. Prefers
    the ingestion-time event_id (pipeline/ingestion.py:~228); falls
    back to the full-entry hash for entries that predate it.
    """
    import hashlib

    out: list[str] = []
    for e in entries:
        eid = e.get("event_id")
        if not eid:
            eid = hashlib.sha256(
                json.dumps(e, sort_keys=True, default=str).encode()
            ).hexdigest()[:16]
        if eid not in out:
            out.append(eid)
    return out[:cap]


def parse_lolbin_block(
    block_text: str,
) -> tuple[list[tuple[str, list[str], list[str]]], str]:
    """Parse the lolbin_db block text into LOLBIN signatures.

    Args:
        block_text: Text from the lolbin_db shared block.

    Returns:
        (sigs, source) where sigs is a list of (process_name,
        command_patterns, mitre_ids) tuples and source is "db" when the
        block parsed to real signatures or "fallback" when detection will
        run on FALLBACK_LOLBIN_SIGS instead (Q-1: the caller must raise a
        run degradation in that case — the round-8 exit gate found
        production lolbin had run on the 9-entry fallback since deployment
        with zero degradations fired).
    """
    sigs = []
    if not block_text:
        return list(FALLBACK_LOLBIN_SIGS), "fallback"

    in_windows = False
    for line in block_text.strip().split("\n"):
        line = line.strip()
        if line == "=== WINDOWS LOLBINS ===":
            in_windows = True
            continue
        elif line == "=== UNIX GTFOBINS ===":
            in_windows = False
            continue
        if in_windows and " | " in line:
            parts = [p.strip() for p in line.split("|")]
            name = parts[0].lower().replace(".exe", "")
            categories = [c.strip() for c in parts[1].split(",")] if len(parts) > 1 else []
            mitre_ids = [m.strip() for m in parts[2].split(",")] if len(parts) > 2 else []
            cat_patterns = []
            for cat in categories:
                cat_lower = cat.lower()
                if cat_lower == "download":
                    cat_patterns.extend(["urlcache", "download", "-f", "/transfer"])
                elif cat_lower == "execute":
                    cat_patterns.extend(["http://", "https://", "vbscript", "/i:http", "scrobj.dll"])
                elif cat_lower == "encode":
                    cat_patterns.extend(["-encode", "base64"])
                elif cat_lower == "decode":
                    cat_patterns.extend(["-decode", "decode"])
                elif cat_lower in ("read", "ads"):
                    cat_patterns.extend(["/c type", "more", "type "])
                elif cat_lower == "write":
                    cat_patterns.extend(["/c echo", "> ", ">> "])
            if cat_patterns:
                sigs.append((name, cat_patterns, mitre_ids))

    if sigs:
        return sigs, "db"
    return list(FALLBACK_LOLBIN_SIGS), "fallback"


def format_anomaly_queue(anomalies: list[dict]) -> str:
    """Format anomalies for the anomaly_queue shared block.

    Each anomaly is written as two lines:
    1. A human-readable summary line
    2. A JSON line with the full anomaly dict (prefixed with JSON:)

    This gives downstream tools (build_timeline) access to all structured
    fields including mitre_ids, z_score, details, etc.

    To keep the block within the agent's context window, only the
    MAX_ANOMALIES_IN_QUEUE most severe anomalies are included.
    JSON lines are trimmed to essential fields to reduce size.

    Args:
        anomalies: List of anomaly dicts.

    Returns:
        Formatted text for the anomaly_queue block.
    """
    MAX_ANOMALIES_IN_QUEUE = 15

    if not anomalies:
        return "Pending anomalies: none"

    # Sort by severity (critical > high > medium > low) and keep top N
    from nabla.utils import SEVERITY_ORDER
    sorted_anomalies = sorted(
        anomalies,
        key=lambda a: SEVERITY_ORDER.get(a.get("severity", "info"), 5),
    )
    if len(sorted_anomalies) > MAX_ANOMALIES_IN_QUEUE:
        sorted_anomalies = sorted_anomalies[:MAX_ANOMALIES_IN_QUEUE]

    lines = [f"Pending anomalies: {len(anomalies)} (showing top {len(sorted_anomalies)} by severity)"]
    for i, a in enumerate(sorted_anomalies, 1):
        sev = a.get("severity", "?").upper()
        atype = a.get("type", "unknown")
        ts = a.get("timestamp", "")
        user = a.get("user", "")
        details = a.get("details", "")
        parts = [f"  {i}. [{sev}] {atype}"]
        if ts:
            parts.append(f"ts={ts}")
        if user:
            parts.append(f'user="{user}"')
        if a.get("source_ip"):
            parts.append(f"ip={a['source_ip']}")
        if a.get("mitre_ids"):
            parts.append(f"mitre={','.join(a['mitre_ids'])}")
        # Truncate details to keep block size manageable
        if details and len(details) > 120:
            details = details[:117] + "..."
        parts.append(details)
        lines.append(" ".join(parts))
        # Append compact JSON — only essential fields to reduce block size
        json_keys = ["type", "severity", "user", "source_ip", "timestamp",
                     "details", "detection_method", "log_type",
                     "community_id", "chain_id",
                     "mitre_ids", "z_score", "gcn_lof_score",
                     "tool_name", "tool_display_name", "entity_context"]
        compact = {k: a[k] for k in json_keys if k in a}
        # Truncate details in JSON too
        if "details" in compact and len(compact["details"]) > 120:
            compact["details"] = compact["details"][:117] + "..."
        lines.append(f"  JSON:{json.dumps(compact, separators=(',', ':'))}")
    return "\n".join(lines)


def compute_baselines(entries: list[dict]) -> dict:
    """Compute statistical baselines from log entries.

    Args:
        entries: List of log entry dicts.

    Returns:
        Dict with 'users' (per-user baselines) and 'global' (aggregate stats).
    """
    user_actions = defaultdict(list)
    user_ips = defaultdict(set)
    user_hours = defaultdict(list)

    for e in entries:
        user = e.get("user", e.get("src_ip", e.get("client_ip", "unknown")))
        action = e.get("action", e.get("protocol", e.get("query_type", "unknown")))
        user_actions[user].append(action)
        ip = e.get("source_ip", e.get("src_ip", e.get("client_ip", "")))
        if ip and is_routable_ip(ip):
            user_ips[user].add(ip)
        ts = e.get("timestamp", "")
        if ts:
            try:
                from nabla.utils import _parse_hour
                hour = _parse_hour(ts)
                user_hours[user].append(hour)
            except (ValueError, IndexError):
                pass  # silent by design: malformed entry fields (2026-09 sweep)

    baselines = {}
    for user, actions in user_actions.items():
        counter = Counter(actions)
        total = len(actions)
        hours = user_hours.get(user, [])
        baselines[user] = {
            "total_events": total,
            "action_distribution": dict(counter),
            "unique_ips": len(user_ips[user]),
            "ips": list(user_ips[user]),
            "hours_active": sorted(set(hours)) if hours else [],
            "off_hours_count": sum(1 for h in hours if h < 6 or h >= 22),
        }

    event_counts = [b["total_events"] for b in baselines.values()]
    if event_counts:
        mean_count = sum(event_counts) / len(event_counts)
        variance = sum((c - mean_count) ** 2 for c in event_counts) / len(event_counts)
        std_count = variance ** 0.5
    else:
        mean_count = 0
        std_count = 0

    return {
        "users": baselines,
        "global": {
            "mean_events_per_user": round(mean_count, 2),
            "std_events_per_user": round(std_count, 2),
            "total_users": len(baselines),
            "total_events": len(entries),
        },
    }


def detect_anomalies(
    entries: list[dict],
    thresholds: dict[str, float] | None = None,
    watchlist: "Watchlist | None" = None,
    lolbin_sigs: list[tuple[str, list[str], list[str]]] | None = None,
    baseline_host_procs: dict[str, list[str]] | None = None,
    attack_tool_index: dict[str, tuple[str, str]] | None = None,
    entity_profiles: "EntityProfileStore | None" = None,
    new_accounts: set[str] | None = None,
    phase: str = "detection",
) -> tuple[list[dict], dict]:
    """Run all detection methods on log entries.

    Args:
        entries: List of log entry dicts (all types mixed).
        thresholds: Detection thresholds. Uses defaults if None.
        watchlist: Watchlist with users, hosts, ips for critical host detection.
        lolbin_sigs: LOLBIN signatures (process, patterns, mitre_ids). Uses fallback if None.
        baseline_host_procs: Historical per-host process sets for unusual process detection.
        attack_tool_index: Tool/malware name index from ATT&CK STIX bundle.
            Maps lowercase name → (description, technique_id). If None, uses
            a minimal fallback list. Build via nabla.attack.build_tool_name_index().
        entity_profiles: Entity baseline profiles from nabla.baselines. When
            provided and warm-up is complete for an entity, detection methods
            compare against per-entity historical norms instead of batch-level
            statistics. None (default) preserves backward-compatible behavior.
        new_accounts: Set of newly created account names. Z-score and activity
            spike detection are skipped for these users since high volume is
            expected during their first days. None (default) preserves
            backward-compatible behavior.
        phase: System phase — "baseline" or "detection". During baseline,
            baseline-dependent methods (z-score, off-hours, activity spike,
            multi-IP, unusual process, EWMA, CUSUM, entity composites) are
            suppressed. Only signature-based methods (LOLBIN, attack scripts,
            critical host escalation, etc.) are active. Default "detection"
            preserves backward-compatible behavior.

    Returns:
        Tuple of (anomalies_list, baselines_dict).
    """
    if thresholds is None:
        thresholds = dict(DEFAULT_THRESHOLDS)
    else:
        # Merge with defaults for any missing keys
        merged = dict(DEFAULT_THRESHOLDS)
        merged.update(thresholds)
        thresholds = merged
    if lolbin_sigs is None:
        lolbin_sigs = list(FALLBACK_LOLBIN_SIGS)

    # --- Compute per-user aggregates ---
    user_events = defaultdict(list)
    user_ips = defaultdict(set)
    user_hours = defaultdict(list)
    user_auth = defaultdict(lambda: {"success": 0, "failure": 0})
    # S3 (round 5): the contributing events per user per auth outcome —
    # aggregate anomalies cite their own evidence, not the newest event.
    user_auth_events: dict[str, dict[str, list[dict]]] = defaultdict(
        lambda: {"success": [], "failure": []})

    for e in entries:
        user = e.get("user", e.get("src_ip", e.get("client_ip", "unknown")))
        user_events[user].append(e)
        ip = e.get("source_ip", e.get("src_ip", e.get("client_ip", "")))
        if ip and is_routable_ip(ip):
            user_ips[user].add(ip)
        ts = e.get("timestamp", "")
        if ts:
            try:
                from nabla.utils import _parse_hour
                hour = _parse_hour(ts)
                user_hours[user].append(hour)
            except (ValueError, IndexError):
                pass  # silent by design: malformed entry fields (2026-09 sweep)
        action = e.get("action", "")
        if action == "login_success":
            user_auth[user]["success"] += 1
            user_auth_events[user]["success"].append(e)
        elif action == "login_failure":
            user_auth[user]["failure"] += 1
            user_auth_events[user]["failure"].append(e)

    # Global stats for z-score
    event_counts = [len(ev) for ev in user_events.values()]
    if len(event_counts) >= 2:
        mean_count = sum(event_counts) / len(event_counts)
        variance = sum((c - mean_count) ** 2 for c in event_counts) / len(event_counts)
        std_count = variance ** 0.5 if variance > 0 else 0.01
    else:
        mean_count = sum(event_counts) if event_counts else 0
        std_count = 0.01

    anomalies: list[dict] = []

    # --- 1. Pre-flagged anomalies ---
    for e in entries:
        if e.get("anomaly"):
            anomalies.append({
                "type": e["anomaly"],
                "severity": "medium",
                "user": e.get("user", "unknown"),
                "source_ip": e.get("source_ip", e.get("src_ip", e.get("client_ip", ""))),
                "timestamp": e.get("timestamp", ""),
                "details": e.get("details", ""),
                "detection_method": "pre_flagged",
            })

    # --- 2. Z-score on per-user event counts ---
    # Suppressed during baseline phase — needs statistical baselines.
    if phase != "baseline":
        # When entity baselines are available and warm-up is complete, compare
        # against the user's own historical EWMA instead of batch mean. This
        # prevents high-volume users from being flagged as anomalies simply
        # because their activity exceeds the batch average.
        z_sigma = thresholds["z_score_sigma"]
        entity_z_sigma = thresholds.get("entity_event_count_sigma", z_sigma)
        for user, events in user_events.items():
            # Skip z-score for new accounts — high volume is expected
            if new_accounts and user in new_accounts:
                continue
            count = len(events)
            # Try entity baseline first
            entity_z = None
            if entity_profiles is not None and entity_profiles.warm_up_complete("user", user):
                profile = entity_profiles.get_user(user)
                if profile and profile.observation_count >= 3:
                    # A8: rate vs rate — the run's events-per-hour against
                    # the per-hour EWMA (count-vs-rate compared mismatched units)
                    # N4 (round 4) + S4 (round 5): score EVERY hour in the
                    # batch, report the peak, and compare against the
                    # family-adjusted threshold (scanning H hours multiplies
                    # the false-alert chance; Bonferroni corrects it back).
                    # The old newest-hour-only read missed a 120-event burst
                    # at 03:00 in a day upload (z=46 invisible, newest hour
                    # quiet, z=0).
                    from nabla.baselines import hourly_rates, family_z_threshold
                    rates = hourly_rates(events, profile)
                    entity_verdict = False  # R6-5: set on ANY entity-baseline outcome
                    entity_z = None
                    if rates:
                        peak_hour, peak_rate = max(rates.items(), key=lambda kv: kv[1])
                        entity_z = profile.typical_event_count.z_score(peak_rate)
                        fam_sigma = family_z_threshold(entity_z_sigma, len(rates))
                        entity_verdict = True  # a warm baseline JUDGED the activity
                        # S7: one rate alert per entity per absolute hour —
                        # 5-min batches re-score the cumulative hour, and a
                        # busy hour used to re-alert on every batch in it.
                        if (entity_z > fam_sigma
                                and getattr(profile, "last_rate_alert_hour", "")
                                != peak_hour):
                            profile.last_rate_alert_hour = peak_hour
                            from nabla.pipeline.clock_ingestion import event_hour_key
                            _peak_events = [
                                e for e in events
                                if event_hour_key(e) == peak_hour
                            ] or events
                            anomalies.append({
                                "type": "entity_event_count_spike",
                                "severity": "high" if entity_z > fam_sigma + 1.0 else "medium",
                                "user": user,
                                "source_ip": list(user_ips[user])[0] if user_ips[user] else "",
                                "timestamp": _newest_event_time(_peak_events),
                                "event_ids": _contributing_ids(_peak_events),  # S3: the peak hour's events
                                "details": (
                                    f"User {user} peak hour {peak_hour} rate "
                                    f"{peak_rate:.0f}/hr (entity_z={entity_z:.1f}, "
                                    f"ewma={profile.typical_event_count.value:.1f}, "
                                    f"std={profile.typical_event_count.std:.1f}, "
                                    f"threshold={fam_sigma:.2f} over {len(rates)}h)"
                                ),
                                "detection_method": "entity_z_score",
                                "z_score": round(entity_z, 2),
                                "raw_score": round(entity_z, 3),  # N10: calibratable
                                "entity_baseline": True,
                            })
                    if entity_verdict:
                        continue  # R6-5: judged by own baseline — alert, deduped, or normal; the batch z-score never re-judges a baselined user
            # Fall back to batch-level z-score (A15: with n users the max
            # achievable z is sqrt(n-1) — below 10 users the 2.0 threshold is
            # unreachable; skip the batch statistic rather than run math that
            # can never fire)
            if std_count > 0 and len(user_events) >= 10:
                z_score = (count - mean_count) / std_count
                if z_score > z_sigma:
                    anomalies.append({
                        "type": "z_score_spike",
                        "severity": "high" if z_score > z_sigma + 1.0 else "medium",
                        "user": user,
                        "source_ip": list(user_ips[user])[0] if user_ips[user] else "",
                        "timestamp": events[0].get("timestamp", ""),
                        "details": (
                            f"User {user} has {count} events "
                            f"(z={z_score:.1f}, mean={mean_count:.1f}, "
                            f"std={std_count:.1f}, threshold={z_sigma})"
                        ),
                        "detection_method": "z_score",
                        "z_score": round(z_score, 2),
                        "raw_score": round(z_score, 3),  # N10: calibratable
                    })

    # --- 3. Failed login ratio (brute force) ---
    # Suppressed during baseline phase — needs statistical baselines.
    if phase != "baseline":
        # When entity baselines are available, compare against the user's own
        # historical auth failure ratio. A user with normally 5% failures who
        # suddenly has 60% is anomalous even if 60% is below the global threshold.
        bf_ratio = thresholds["brute_force_ratio"]
        entity_auth_sigma = thresholds.get("entity_auth_failure_sigma", 2.0)
        for user, auth in user_auth.items():
            total_auth = auth["success"] + auth["failure"]
            if total_auth < 3:
                continue
            current_ratio = auth["failure"] / total_auth
            # Try entity baseline first
            entity_flagged = False
            if entity_profiles is not None and entity_profiles.warm_up_complete("user", user):
                profile = entity_profiles.get_user(user)
                if profile and profile.auth_failure_ratio.variance > 0:
                    auth_z = profile.auth_failure_ratio.z_score(current_ratio)
                    if auth_z > entity_auth_sigma:
                        anomalies.append({
                            "type": "entity_auth_failure_spike",
                            "severity": "high",
                            "user": user,
                            "source_ip": list(user_ips[user])[0] if user_ips[user] else "",
                            "details": (
                                f"User {user} has {auth['failure']} failures "
                                f"out of {total_auth} auth events "
                                f"({current_ratio:.0%}, entity_z={auth_z:.1f}, "
                                f"ewma_ratio={profile.auth_failure_ratio.value:.2f}, "
                                f"threshold={entity_auth_sigma})"
                            ),
                            "detection_method": "entity_auth_failure",
                            "entity_baseline": True,
                            "raw_score": round(auth_z, 3),
                            # S3: cite the auth events the ratio derives from
                            "timestamp": _newest_event_time(
                                user_auth_events[user]["failure"]
                                or user_events.get(user, [])),  # N2.3: event time
                            "event_ids": _contributing_ids(
                                user_auth_events[user]["failure"]
                                + user_auth_events[user]["success"]),
                        })
                        entity_flagged = True
            # Fall back to global threshold
            if not entity_flagged and current_ratio > bf_ratio:
                anomalies.append({
                    "type": "brute_force_attempt",
                    "severity": "high",
                    "user": user,
                    "source_ip": list(user_ips[user])[0] if user_ips[user] else "",
                    "timestamp": _newest_event_time(
                        user_auth_events[user]["failure"]
                        or user_events.get(user, [])),  # N2.3: event time
                    "details": (
                        f"User {user} has {auth['failure']} failures "
                        f"out of {total_auth} auth events "
                        f"({current_ratio:.0%}, threshold={bf_ratio})"
                    ),
                    "detection_method": "failed_login_ratio",
                    "raw_score": round(current_ratio, 3),
                    # S3: cite the auth events the ratio derives from
                    "event_ids": _contributing_ids(
                        user_auth_events[user]["failure"]
                        + user_auth_events[user]["success"]),
                })

    # --- 4. Off-hours activity ---
    # Suppressed during baseline phase — needs typical_hours baselines.
    if phase != "baseline":
        # When entity baselines are available, compare against the user's own
        # typical_hours instead of the fixed 22:00-06:00 window. A night-shift
        # worker who normally works 22:00-06:00 should not be flagged.
        oh_count = int(thresholds["off_hours_count"])
        # F5: machine accounts have no habits to deviate from. `root` and
        # `SYSTEM` working at 03:00 is the job, not an anomaly — and in the
        # real dataset 13 of 14 principals are machine accounts, so scoring
        # them buries the one human who matters. Excluded, and logged so the
        # decision is visible rather than silent.
        from nabla.utils import is_baselineable_user
        machine_users = sorted(u for u in user_hours if not is_baselineable_user(u))
        if machine_users:
            logger.info(
                "Off-hours: excluded %d machine account(s) from behavioral "
                "baselining: %s",
                len(machine_users), machine_users[:10],
            )
        for user, hours in user_hours.items():
            if not is_baselineable_user(user):
                continue
            # Try entity baseline first
            entity_flagged = False
            if entity_profiles is not None and entity_profiles.warm_up_complete("user", user):
                profile = entity_profiles.get_user(user)
                if profile and profile.typical_hours:
                    # R10 (round 3): share-based unusualness when the
                    # histogram is warm (sum >= 50) — binary set-membership
                    # fired sparse-night users on every quiet-hour blip;
                    # the histogram says '2% share = typical for them'
                    from nabla.utils import hour_is_unusual
                    hist = getattr(profile, "hour_histogram", {}) or {}
                    if sum(hist.values()) >= 50.0:
                        unusual_hours = [h for h in hours if hour_is_unusual(hist, h)]
                    else:
                        unusual_hours = [h for h in hours if h not in profile.typical_hours]
                    if len(unusual_hours) >= oh_count:
                        _oh_events = [
                            e for e in user_events.get(user, [])
                            if _event_hour_of(e) in set(unusual_hours)
                        ]  # S3: the atypical-hour events are the evidence
                        anomalies.append({
                            "type": "entity_off_hours_activity",
                            "severity": "medium",
                            "user": user,
                            "source_ip": list(user_ips[user])[0] if user_ips[user] else "",
                            "timestamp": _newest_event_time(_oh_events or user_events.get(user, [])),
                            "event_ids": _contributing_ids(_oh_events),
                            "details": (
                                f"User {user} has {len(unusual_hours)} events "
                                f"during atypical hours "
                                f"(usual: {sorted(profile.typical_hours)}, "
                                f"unusual: {sorted(set(unusual_hours))}, "
                                f"threshold={oh_count})"
                            ),
                            "detection_method": "entity_off_hours",
                            "entity_baseline": True,
                            "raw_score": len(unusual_hours),  # N10: calibratable
                        })
                        entity_flagged = True
            # Fall back to fixed off-hours window
            if not entity_flagged:
                off_hours = [h for h in hours if h < 6 or h >= 22]
                _oh_events_global = [
                    e for e in user_events.get(user, [])
                    if _event_hour_of(e) < 6 or _event_hour_of(e) >= 22
                ]  # S3: the off-hours events are the evidence
                if len(off_hours) >= oh_count:
                    anomalies.append({
                        "type": "off_hours_activity",
                        "severity": "medium",
                        "user": user,
                        "source_ip": list(user_ips[user])[0] if user_ips[user] else "",
                        "timestamp": _newest_event_time(_oh_events_global or user_events.get(user, [])),
                        "event_ids": _contributing_ids(_oh_events_global),
                        "details": (
                            f"User {user} has {len(off_hours)} events "
                            f"during off-hours (22:00-06:00 UTC, threshold={oh_count})"
                        ),
                        "detection_method": "off_hours",
                        "raw_score": len(off_hours),  # N10: calibratable
                    })

    # --- 5. Multi-IP for single user (impossible travel) ---
    # Suppressed during baseline phase — needs typical_ips baselines.
    if phase != "baseline":
        # When entity baselines are available, flag IPs not previously seen
        # for this user instead of using a fixed count threshold. A user who
        # normally uses 5 IPs and adds 2 new ones is more suspicious than a
        # user who normally uses 10 IPs and appears from 3.
        ip_count = int(thresholds["multi_ip_count"])
        entity_new_ip_thresh = int(thresholds.get("entity_new_ip_threshold", 2))
        for user, ips in user_ips.items():
            # Try entity baseline first
            entity_flagged = False
            if entity_profiles is not None and entity_profiles.warm_up_complete("user", user):
                profile = entity_profiles.get_user(user)
                if profile and profile.typical_ips:
                    new_ips = ips - profile.typical_ips
                    if len(new_ips) >= entity_new_ip_thresh:
                        _new_ip_events = [
                            e for e in user_events.get(user, [])
                            if e.get("source_ip", e.get("src_ip", e.get("client_ip", ""))) in new_ips
                        ]  # S3: logins from the new IPs are the evidence
                        anomalies.append({
                            "type": "entity_new_ip",
                            "severity": "high" if len(new_ips) >= 3 else "medium",
                            "user": user,
                            "source_ip": ", ".join(sorted(new_ips)),
                            "timestamp": _newest_event_time(_new_ip_events or user_events.get(user, [])),
                            "event_ids": _contributing_ids(_new_ip_events),
                            "details": (
                                f"User {user} appeared from {len(new_ips)} new IPs: "
                                f"{', '.join(sorted(new_ips))} "
                                f"(known: {len(profile.typical_ips)}, "
                                f"threshold={entity_new_ip_thresh})"
                            ),
                            "detection_method": "entity_new_ip",
                            "entity_baseline": True,
                            "raw_score": len(new_ips),  # N10: calibratable
                        })
                        entity_flagged = True
            # Fall back to batch-level multi-IP check
            if not entity_flagged and len(ips) >= ip_count:
                anomalies.append({
                    "type": "multiple_source_ips",
                    "severity": "high",
                    "user": user,
                    "source_ip": ", ".join(ips),
                    "timestamp": _newest_event_time(user_events.get(user, [])),
                    "event_ids": _contributing_ids(user_events.get(user, [])),  # S3: all this user's events carry the IPs
                    "details": f"User {user} appeared from {len(ips)} unique IPs: {', '.join(ips)} (threshold={ip_count})",
                    "detection_method": "multi_ip",
                    "raw_score": len(ips),  # N10: calibratable
                })

    # --- 6. Activity spike ---
    # Suppressed during baseline phase — needs statistical baselines.
    if phase != "baseline":
        # When entity baselines are available, compare against the user's own
        # typical event count instead of batch mean. A user who normally has
        # 500 events and has 500 this run is not spiking, even if the batch
        # mean is 50.
        spike_mult = thresholds["spike_multiplier"]
        for user, events in user_events.items():
            # Skip activity spike for new accounts — high volume is expected
            if new_accounts and user in new_accounts:
                continue
            count = len(events)
            # Try entity baseline first
            entity_flagged = False
            if entity_profiles is not None and entity_profiles.warm_up_complete("user", user):
                profile = entity_profiles.get_user(user)
                if profile and profile.typical_event_count.value > 0:
                    # S4 (round 5): peak-hour rate, not newest-hour — a
                    # multi-hour upload's burst must be visible
                    from nabla.baselines import hourly_rates
                    rates = hourly_rates(events, profile)
                    peak_rate = max(rates.values()) if rates else None
                    entity_spike = (peak_rate is not None
                                    and peak_rate > profile.typical_event_count.value * spike_mult)
                    # R6-5: ANY entity-baseline verdict (spike OR normal)
                    # ends the judgment — the batch spike check below must
                    # not re-judge a baselined user. (Was `if entity_spike
                    # or True:` — a dead conditional that read like a bug.)
                    entity_flagged = True
                    if entity_spike:
                        from nabla.pipeline.clock_ingestion import event_hour_key
                        _peak_h = max(rates, key=lambda h: rates[h])
                        _peak_events = [e for e in events
                                        if event_hour_key(e) == _peak_h] or events
                        anomalies.append({
                            "type": "entity_activity_spike",
                            "severity": "high",
                            "user": user,
                            "source_ip": list(user_ips[user])[0] if user_ips[user] else "",
                            "timestamp": _newest_event_time(_peak_events),
                            "event_ids": _contributing_ids(_peak_events),  # S3
                            "details": (
                                f"User {user} peak hour {_peak_h} rate "
                                f"{peak_rate:.0f}/hr vs "
                                f"entity ewma {profile.typical_event_count.value:.1f} "
                                f"(threshold={spike_mult}x)"
                            ),
                            "detection_method": "entity_activity_spike",
                            "entity_baseline": True,
                            "raw_score": round(peak_rate / profile.typical_event_count.value, 3),  # N10: calibratable (multiplier units)
                        })
                        entity_flagged = True
            # Fall back to batch-level spike check
            if not entity_flagged and mean_count > 0 and count > mean_count * spike_mult:
                anomalies.append({
                    "type": "activity_spike",
                    "severity": "high",
                    "user": user,
                    "source_ip": list(user_ips[user])[0] if user_ips[user] else "",
                    "timestamp": events[0].get("timestamp", ""),
                    "details": f"User {user} has {count} events vs mean {mean_count:.1f} (threshold={spike_mult}x)",
                    "detection_method": "activity_spike",
                    "raw_score": round(count / mean_count, 3),  # N10: calibratable (multiplier units)
                })

    # --- 7. LOLBIN abuse ---
    lolbin_sensitivity = thresholds.get("lolbin_sensitivity", 0.7)
    min_pattern_matches = 1
    if lolbin_sensitivity >= 0.9:
        min_pattern_matches = 0
    elif lolbin_sensitivity < 0.5:
        min_pattern_matches = 2

    for e in entries:
        if e.get("type") != "endpoint":
            continue
        proc_full = e.get("process", "").lower()
        proc = proc_full.replace(".exe", "")
        cmd = e.get("command_line", "").lower()
        if not cmd and min_pattern_matches > 0:
            continue
        # Skip processes from legitimate enterprise tool paths
        # (e.g., splunk-powershell.exe from \SplunkUniversalForwarder\)
        is_legitimate_path = any(lp in proc_full for lp in LEGITIMATE_TOOL_PATHS)
        if is_legitimate_path:
            continue
        for sig_proc, sig_patterns, sig_mitre in lolbin_sigs:
            if sig_proc in proc:
                matched = sum(1 for p in sig_patterns if p in cmd) if cmd else 0
                if matched >= min_pattern_matches:
                    anomaly_entry = {
                        "type": "lolbin_abuse",
                        "severity": "high",
                        "user": e.get("user", "unknown"),
                        "host": e.get("host", ""),  # S2: dual attribution
                        "source_ip": e.get("source_ip", ""),
                        "timestamp": e.get("timestamp", ""),
                        "details": f"LOLBIN {e.get('process', '')} with suspicious command: {cmd[:120]}",
                        "detection_method": "lolbin",
                    }
                    if sig_mitre:
                        anomaly_entry["mitre_ids"] = sig_mitre
                    anomalies.append(anomaly_entry)
                break

    # --- 8. Suspicious parent-child process relationships ---
    pc_sensitivity = thresholds.get("parent_child_sensitivity", 0.7)
    suspicious_children = set()
    for sig_proc, _, _ in lolbin_sigs:
        suspicious_children.add(sig_proc.lower().replace(".exe", ""))
        suspicious_children.add(sig_proc.lower())
    suspicious_children.update({"cmd", "powershell", "bash", "sh", "python", "perl", "python3"})

    min_pc_patterns = 1
    if pc_sensitivity >= 0.9:
        min_pc_patterns = 0
    elif pc_sensitivity < 0.5:
        min_pc_patterns = 1

    for e in entries:
        if _get_field(e, "type") != "endpoint":
            continue
        parent = _get_field(e, "parent_process", "ParentImage", "ParentProcessName").lower().replace(".exe", "")
        proc = _get_field(e, "process", "Image", "NewProcessName").lower().replace(".exe", "")
        cmd = _get_field(e, "command_line", "CommandLine").lower()
        if not parent or not proc:
            continue
        if parent in SUSPICIOUS_PARENTS and proc in suspicious_children:
            if min_pc_patterns > 0 and pc_sensitivity < 0.5:
                suspicious_cmd_patterns = [
                    "http://", "https://", "download", "urlcache", "-enc",
                    "encodedcommand", "iex", "invoke-expression", "-w hidden",
                    "base64", "frombase64string", "bypass", "noprofile",
                ]
                if not any(p in cmd for p in suspicious_cmd_patterns):
                    continue
            anomalies.append({
                "type": "suspicious_parent_child",
                "severity": "high",
                "user": _get_field(e, "user", "User"),
                "host": _get_field(e, "host", "HostName"),  # S2: dual attribution
                "source_ip": _get_field(e, "source_ip", "src_ip"),
                "timestamp": _get_field(e, "timestamp"),
                "details": f"Suspicious parent-child: {parent}.exe -> {proc}.exe" + (f" cmd={cmd[:80]}" if cmd else ""),
                "detection_method": "parent_child",
            })

    # --- 9. Critical host privilege escalation ---
    ch_sensitivity = thresholds.get("critical_host_sensitivity", 0.7)
    critical_hosts = set()
    if watchlist and hasattr(watchlist, "hosts"):
        critical_hosts = set(watchlist.hosts)
    if not critical_hosts:
        for e in entries:
            h = _get_field(e, "host", "Computer").upper()
            # A20: token-match, not substring — 'DC' as a substring hits
            # unrelated names; split on separators and match whole tokens
            tokens = re.split(r"[-_.]", h.upper())
            # A20: whole-token matches; DC01/DC02-style names included since
            # bare "DC" as a token is rare in real hostnames
            critical_tokens = ["DC", "DC01", "DC02", "DOMAIN", "BUILD", "PROD", "FINANCE"]
            if any(kw in tokens for kw in critical_tokens):
                critical_hosts.add(_get_field(e, "host", "Computer"))

    for e in entries:
        if _get_field(e, "type") != "endpoint":
            continue
        host = _get_field(e, "host", "Computer")
        if not critical_hosts or host not in critical_hosts:
            continue
        cmd = _get_field(e, "command_line", "CommandLine").lower()
        proc = _get_field(e, "process", "Image", "NewProcessName").lower()
        parent = _get_field(e, "parent_process", "ParentImage").lower()

        is_escalation = False
        severity = "medium"
        details = ""

        if any(p in cmd for p in ESCALATION_CMD_PATTERNS) or proc.replace(".exe", "") in ESCALATION_PROCESSES:
            is_escalation = True
            severity = "critical"
            details = f"Escalation command on critical host {host}: {cmd[:100]}"
        elif parent.replace(".exe", "") in {p.replace(".exe", "") for p in UAC_BYPASS_PARENTS}:
            child_proc = proc.replace(".exe", "")
            if child_proc in suspicious_children:
                is_escalation = True
                severity = "high"
                details = f"UAC bypass on critical host {host}: {parent} -> {proc}"
        elif ch_sensitivity >= 0.9 and _get_field(e, "action") == "execute":
            user = _get_field(e, "user", "User").lower()
            if user and "admin" not in user and "system" not in user and "svc_" not in user:
                is_escalation = True
                severity = "medium"
                details = f"Non-admin execute on critical host {host}: {user} ran {proc}"

        if is_escalation:
            if ch_sensitivity < 0.5 and severity != "critical":
                continue
            anomalies.append({
                "type": "critical_host_escalation",
                "severity": severity,
                "user": _get_field(e, "user", "User"),
                "host": _get_field(e, "host", "HostName"),  # S2: dual attribution
                "source_ip": _get_field(e, "source_ip", "src_ip"),
                "timestamp": _get_field(e, "timestamp"),
                "details": details,
                "detection_method": "critical_host_escalation",
            })

    # --- 10. Unusual process per host ---
    # Suppressed during baseline phase — needs historical process baselines.
    if phase != "baseline":
        # When entity baselines are available, use the host profile's
        # typical_processes set (which tracks processes across runs) as the
        # primary baseline. Fall back to baseline_host_procs from archival
        # memory if no entity profile exists.
        up_sensitivity = thresholds.get("unusual_process_sensitivity", 0.5)
        entity_new_proc_thresh = int(thresholds.get("entity_new_process_threshold", 3))
        host_processes = defaultdict(set)
        for e in entries:
            if _get_field(e, "type") != "endpoint":
                continue
            host = _get_field(e, "host", "Computer")
            proc = _get_field(e, "process", "Image", "NewProcessName").lower().replace(".exe", "")
            if host and proc:
                host_processes[host].add(proc)
        # N2.3: host detectors need event time too — newest endpoint
        # event per host (host_processes carries names only).
        # S3 (round 5): also keep the events themselves, so host
        # aggregates cite THEIR evidence instead of the host's newest.
        host_newest_ts: dict[str, str] = {}
        host_endpoint_events: dict[str, list[dict]] = defaultdict(list)
        for e in entries:
            if _get_field(e, "type") != "endpoint":
                continue
            h = _get_field(e, "host", "Computer")
            ts = _get_field(e, "timestamp")
            if h:
                host_endpoint_events[h].append(e)
            if h and ts and ts > host_newest_ts.get(h, ""):
                host_newest_ts[h] = ts

        baseline_procs_map = baseline_host_procs or {}
        for host, procs in host_processes.items():
            # Try entity baseline first
            entity_profile = None
            if entity_profiles is not None and entity_profiles.warm_up_complete("host", host):
                entity_profile = entity_profiles.get_host(host)

            if entity_profile is not None and entity_profile.typical_processes:
                # Use entity profile's typical_processes as baseline
                new_procs = []
                for proc in procs:
                    proc_stem = proc.replace(".exe", "").lower()
                    proc_name = proc_stem.rsplit("\\", 1)[-1] if "\\" in proc_stem else proc_stem
                    if up_sensitivity >= 0.5 and proc_name in COMMON_PROCESSES:
                        continue
                    if up_sensitivity < 0.5:
                        is_lolbin = any(sig_proc in proc_name for sig_proc, _, _ in lolbin_sigs)
                        if not is_lolbin:
                            continue
                    if proc_name not in entity_profile.typical_processes:
                        new_procs.append(proc)

                if len(new_procs) >= entity_new_proc_thresh:
                    anomalies.append({
                        "type": "entity_new_process",
                        "severity": "high" if len(new_procs) >= entity_new_proc_thresh * 2 else "medium",
                        "user": "",
                        "source_ip": "",
                        "timestamp": host_newest_ts.get(host, ""),  # N2.3: event time
                        "details": (
                            f"{len(new_procs)} new processes on host {host} "
                            f"(known: {len(entity_profile.typical_processes)}, "
                            f"new: {', '.join(p[:40] for p in new_procs[:5])}, "
                            f"threshold={entity_new_proc_thresh})"
                        ),
                        "detection_method": "entity_new_process",
                        "host": host,
                        "entity_baseline": True,
                        "raw_score": len(new_procs),  # N10: calibratable
                        # S3: cite the endpoint events that introduced the
                        # new processes, not the host's newest event
                        "event_ids": _contributing_ids([
                            e for e in host_endpoint_events.get(host, [])
                            if (e.get("process", e.get("Image", e.get("NewProcessName", "")))
                                .lower().replace(".exe", "")) in set(new_procs)
                        ]),
                    })
                # Also flag individual new processes that are LOLBINs or attack tools
                for proc in new_procs:
                    proc_stem = proc.replace(".exe", "").lower()
                    proc_name = proc_stem.rsplit("\\", 1)[-1] if "\\" in proc_stem else proc_stem
                    is_lolbin = any(sig_proc in proc_name for sig_proc, _, _ in lolbin_sigs)
                    is_attack = attack_tool_index and proc_name in attack_tool_index
                    if is_lolbin or is_attack:
                        anomalies.append({
                            "type": "unusual_process_per_host",
                            "severity": "high",
                            "user": "",
                            "source_ip": "",
                            "timestamp": host_newest_ts.get(host, ""),  # N2.3: event time
                            "details": f"New {('attack' if is_attack else 'LOLBIN')} process {proc} on host {host} (not in entity baseline)",
                            "detection_method": "entity_unusual_process",
                            "host": host,
                            "process": proc,
                            "event_ids": _contributing_ids([
                                e for e in host_endpoint_events.get(host, [])
                                if proc in (e.get("process", e.get("Image", e.get("NewProcessName", "")))
                                            .lower().replace(".exe", ""))
                            ]),  # S3: this process's events are the evidence
                            "entity_baseline": True,
                        })
            else:
                # Fall back to baseline_host_procs from archival memory
                baseline_procs = set(baseline_procs_map.get(host, []))
                for proc in procs:
                    proc_stem = proc.replace(".exe", "").lower()
                    if up_sensitivity >= 0.5 and proc_stem in COMMON_PROCESSES:
                        continue
                    if up_sensitivity < 0.5:
                        is_lolbin = any(sig_proc in proc_stem for sig_proc, _, _ in lolbin_sigs)
                        if not is_lolbin:
                            continue
                    if baseline_procs_map and proc_stem not in baseline_procs:
                        anomalies.append({
                            "type": "unusual_process_per_host",
                            "severity": "medium",
                            "user": "",
                            "source_ip": "",
                            "timestamp": host_newest_ts.get(host, ""),  # N2.3: event time
                            "details": f"Process {proc} first seen on host {host} (not in baseline)",
                            "detection_method": "unusual_process",
                            "host": host,
                            "process": proc,
                        })

    # --- 10b. Known attack script execution ---
    # --- 10c. Known attack script detection ---
    # Uses the ATT&CK STIX bundle as the primary source for known attack
    # tool/malware names. The fallback list is merged in (it covers binary
    # names like "beacon.exe" that the STIX index doesn't have).
    if attack_tool_index:
        # Merge fallback entries into STIX index (fallback takes precedence
        # for overlapping keys — it has more specific binary names)
        known_scripts = {**attack_tool_index, **_FALLBACK_ATTACK_SCRIPTS}
        # Pre-compile a single combined regex for word-boundary matching.
        # This is much faster than compiling 1100+ individual patterns per event.
        # Pattern: (?:^|[^a-z0-9])(name1|name2|...)(?:[^a-z0-9]|$)
        _sorted_names = sorted(known_scripts.keys(), key=len, reverse=True)
        _combined_pattern = re.compile(
            r'(?:^|[^a-z0-9])(' + '|'.join(re.escape(n) for n in _sorted_names) + r')(?:[^a-z0-9]|$)',
            re.IGNORECASE,
        )
    else:
        known_scripts = _FALLBACK_ATTACK_SCRIPTS
        _combined_pattern = None

    for e in entries:
        if _get_field(e, "type") != "endpoint":
            continue
        cmd = _get_field(e, "command_line", "CommandLine").lower()
        target = _get_field(e, "target_file", "TargetFilename", "TargetObject").lower()
        proc = _get_field(e, "process", "Image", "NewProcessName").lower()
        if not cmd and not target:
            continue
        if _combined_pattern:
            # Single regex match against all tool names at once
            m = _combined_pattern.search(cmd) or _combined_pattern.search(target) or _combined_pattern.search(proc)
            if m:
                script_name = m.group(1).lower()
                description, mitre_id = known_scripts[script_name]
                # Extract display name from description: first part before
                # markdown links or detailed text. E.g., "Cobalt Strike beacon"
                # from "Cobalt Strike beacon", or "Cobalt Strike" from
                # "[Cobalt Strike](url) is a commercial..."
                display_name = description
                # Strip markdown links: [Name](url) → Name
                display_name = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', display_name)
                # Take first sentence/phrase (before period or " is ")
                display_name = re.split(r'\.\s| is ', display_name, 1)[0].strip()
                anomalies.append({
                    "type": "known_attack_script",
                    "severity": "critical",
                    "user": _get_field(e, "user", "User"),
                    "host": _get_field(e, "host", "HostName"),  # S2: dual attribution
                    "source_ip": _get_field(e, "source_ip", "SourceIp", "SourceAddress"),
                    "timestamp": _get_field(e, "timestamp"),
                    "details": f"Known attack script: {description} ({script_name})",
                    "detection_method": "attack_script",
                    "mitre_ids": [mitre_id],
                    "command_line": cmd[:200],
                    "process": proc,
                    "tool_name": script_name,
                    "tool_display_name": display_name,
                })
        else:
            # Fallback: substring matching on curated list
            for script_name, (description, mitre_id) in known_scripts.items():
                if script_name in cmd or script_name in target or script_name in proc:
                    anomalies.append({
                        "type": "known_attack_script",
                        "severity": "critical",
                        "user": _get_field(e, "user", "User"),
                        "host": _get_field(e, "host", "HostName"),  # S2: dual attribution
                        "source_ip": _get_field(e, "source_ip", "SourceIp", "SourceAddress"),
                        "timestamp": _get_field(e, "timestamp"),
                        "details": f"Known attack script: {description} ({script_name})",
                        "detection_method": "attack_script",
                        "mitre_ids": [mitre_id],
                        "command_line": cmd[:200],
                        "process": proc,
                        "tool_name": script_name,
                        "tool_display_name": description,
                    })
                    break  # One match per entry is enough

    # --- 10d. Renamed attack tool detection ---
    # Catches renamed attack tools (e.g., Rubeus → Rsynctool.exe) by their
    # distinctive command-line signatures rather than process name.
    # Each signature: (command pattern, tool name, description, mitre_id)
    RENAMED_TOOL_SIGS = [
        # Rubeus — Kerberos attack tool (T1558, T1003)
        ("asktgs ", "Rubeus", "Kerberos TGS request (Rubeus)", "T1558"),
        ("asktgt ", "Rubeus", "Kerberos TGT request (Rubeus)", "T1558"),
        ("diamond ", "Rubeus", "Kerberos diamond ticket (Rubeus)", "T1558"),
        ("kerberoast ", "Rubeus", "Kerberoasting (Rubeus)", "T1558"),
        ("asreproast ", "Rubeus", "AS-REP roasting (Rubeus)", "T1558"),
        ("createnetonly ", "Rubeus", "Create sacrificial process (Rubeus)", "T1558"),
        ("/s4u ", "Rubeus", "S4U2Self/S4U2Proxy abuse (Rubeus)", "T1558"),
        ("/ptt ", "Rubeus", "Pass-the-ticket (Rubeus)", "T1558"),
        ("/nowrap ", "Rubeus", "Ticket without wrapper (Rubeus)", "T1558"),
        ("/ticket:", "Rubeus", "Kerberos ticket operation (Rubeus)", "T1558"),
        # Mimikatz — credential dumping (T1003)
        ("sekurlsa::logonpasswords", "Mimikatz", "Credential dumping (Mimikatz)", "T1003"),
        ("sekurlsa::wdigest", "Mimikatz", "WDigest credential extraction (Mimikatz)", "T1003"),
        ("lsadump::lsa", "Mimikatz", "LSA dump (Mimikatz)", "T1003"),
        ("lsadump::dcsync", "Mimikatz", "DCSync attack (Mimikatz)", "T1003"),
        ("kerberos::ptt ", "Mimikatz", "Pass-the-ticket (Mimikatz)", "T1558"),
        ("kerberos::golden ", "Mimikatz", "Golden ticket (Mimikatz)", "T1558"),
        # BloodHound/SharpHound — AD recon (T1087)
        ("--collectionmethod ", "SharpHound", "AD data collection (SharpHound)", "T1087"),
        ("--domain ", "SharpHound", "AD domain targeting (SharpHound)", "T1087"),
        # CrackMapExec — post-exploitation (T1021)
        ("--exec-method ", "CrackMapExec", "Post-exploitation execution (CME)", "T1021"),
        # Cobalt Strike — C2 framework (T1071)
        ("-jar cobaltstrike", "Cobalt Strike", "Cobalt Strike JAR launch", "T1071"),
        ("cobaltstrike.jar", "Cobalt Strike", "Cobalt Strike JAR reference", "T1071"),
        ("carbonstrike", "Cobalt Strike", "Cobalt Strike variant directory", "T1071"),
        ("\\msse-", "Cobalt Strike", "Cobalt Strike SMB named pipe", "T1071"),
        ("\\status_", "Cobalt Strike", "Cobalt Strike status pipe", "T1071"),
        ("\\postex_", "Cobalt Strike", "Cobalt Strike post-ex pipe", "T1071"),
        # Mimikatz — additional signatures (T1003, T1558)
        ("privilege::debug", "Mimikatz", "Privilege debug (Mimikatz)", "T1003"),
        ("token::elevate", "Mimikatz", "Token elevation (Mimikatz)", "T1548"),
        ("sekurlsa::pth ", "Mimikatz", "Pass-the-hash (Mimikatz)", "T1558"),
        ("sekurlsa::tickets", "Mimikatz", "Ticket export (Mimikatz)", "T1558"),
        ("sekurlsa::ekeys", "Mimikatz", "Kerberos key extraction (Mimikatz)", "T1558"),
        ("sekurlsa::minidump", "Mimikatz", "LSASS minidump (Mimikatz)", "T1003"),
        ("lsadump::sam", "Mimikatz", "SAM dump (Mimikatz)", "T1003"),
        ("lsadump::secrets", "Mimikatz", "LSA secrets dump (Mimikatz)", "T1003"),
        ("lsadump::cache", "Mimikatz", "Cached credential dump (Mimikatz)", "T1003"),
        ("crypto::certificates", "Mimikatz", "Certificate extraction (Mimikatz)", "T1558"),
        ("misc::skeleton", "Mimikatz", "Skeleton key injection (Mimikatz)", "T1548"),
        # Seatbelt — GhostPack credential enumeration (T1082)
        ("-group=", "Seatbelt", "Command group selection (Seatbelt)", "T1082"),
        ("secpackagecreds", "Seatbelt", "Security package credentials (Seatbelt)", "T1003"),
        ("credenum", "Seatbelt", "Credential enumeration (Seatbelt)", "T1003"),
        ("dpapimasterkeys", "Seatbelt", "DPAPI master keys (Seatbelt)", "T1003"),
        ("windowsvault", "Seatbelt", "Windows vault credentials (Seatbelt)", "T1003"),
        # Impacket — secretsdump (T1003)
        ("-just-dc", "Impacket", "DC credential dump (secretsdump)", "T1003"),
        ("-use-vss", "Impacket", "VSS-based credential dump (secretsdump)", "T1003"),
        # SharpHound — additional signatures (T1087)
        ("--stealth", "SharpHound", "Stealth collection (SharpHound)", "T1087"),
        ("-c all", "SharpHound", "Full collection method (SharpHound)", "T1087"),
        ("dconly", "SharpHound", "DC-only enumeration (SharpHound)", "T1087"),
        ("--ldapfilter", "SharpHound", "LDAP filter collection (SharpHound)", "T1087"),
    ]

    for e in entries:
        if _get_field(e, "type") != "endpoint":
            continue
        cmd = _get_field(e, "command_line", "CommandLine").lower()
        proc = _get_field(e, "process", "Image", "NewProcessName").lower()
        proc_stem = proc.replace(".exe", "").split("\\")[-1]
        if not cmd:
            continue
        for sig_pattern, tool_name, description, mitre_id in RENAMED_TOOL_SIGS:
            if sig_pattern in cmd:
                # Skip if the process name already matches the tool
                # (that's caught by known_attack_script above)
                if tool_name.lower() in proc_stem:
                    continue
                anomalies.append({
                    "type": "renamed_attack_tool",
                    "severity": "critical",
                    "user": _get_field(e, "user", "User"),
                    "host": _get_field(e, "host", "HostName"),  # S2: dual attribution
                    "source_ip": _get_field(e, "source_ip", "SourceIp", "SourceAddress"),
                    "timestamp": _get_field(e, "timestamp"),
                    "details": f"Renamed attack tool: {description} (process: {proc_stem})",
                    "detection_method": "renamed_tool",
                    "mitre_ids": [mitre_id],
                    "command_line": cmd[:200],
                    "process": proc,
                    "tool_name": tool_name,
                })
                break  # One match per entry is enough

    # --- 10c. Enumeration behavior detection ---
    # Catches renamed/disguised enumeration scripts by their *behavior*,
    # not their name. Flags processes that:
    #   (a) spawn many child processes rapidly (batch enumeration)
    #   (b) access multiple sensitive paths in sequence
    #   (c) use command-line patterns typical of enumeration
    enum_sensitivity = thresholds.get("enumeration_sensitivity", 0.7)
    if enum_sensitivity > 0:
        # --- (a) Rapid child process spawning ---
        # A single parent spawning 10+ distinct child processes within
        # a short window is enumeration behavior regardless of the parent name.
        _ENUM_SPAWN_THRESHOLD = 10 if enum_sensitivity >= 0.7 else 20
        _ENUM_SPAWN_WINDOW_MIN = 5  # 5-minute window

        parent_children: dict[tuple[str, str, str], list[tuple[str, str]]] = defaultdict(list)
        # key: (parent_process, user, host), value: [(child_process, timestamp)]
        for e in entries:
            if _get_field(e, "type") != "endpoint":
                continue
            parent = _get_field(e, "parent_process", "ParentImage", "ParentProcessName")
            proc = _get_field(e, "process", "Image", "NewProcessName")
            user = _get_field(e, "user", "User")
            host = _get_field(e, "host", "Computer")
            ts = _get_field(e, "timestamp")
            if not parent or not proc or not ts:
                continue
            parent_stem = parent.lower().replace(".exe", "").split("/")[-1].split("\\")[-1]
            # Skip system parents that legitimately spawn many children
            if parent_stem in SYSTEM_PARENTS:
                continue
            parent_children[(parent, user, host)].append((proc, ts))

        for (parent, user, host), children in parent_children.items():
            # Parse timestamps and sort
            parsed = []
            for proc, ts in children:
                dt = _parse_ts(ts)
                if dt is not None:
                    parsed.append((proc, dt))
                    continue
            if len(parsed) < _ENUM_SPAWN_THRESHOLD:
                continue
            parsed.sort(key=lambda x: x[1])

            # Sliding window: count distinct children within _ENUM_SPAWN_WINDOW_MIN
            distinct_children = set()
            window_start = parsed[0][1]
            flagged = False
            for proc, dt in parsed:
                while dt > window_start + timedelta(minutes=_ENUM_SPAWN_WINDOW_MIN):
                    # Advance window — remove oldest
                    # (simplified: just reset window start)
                    window_start = dt
                    distinct_children = set()
                distinct_children.add(proc.lower().replace(".exe", ""))
                if len(distinct_children) >= _ENUM_SPAWN_THRESHOLD:
                    parent_stem = parent.lower().replace(".exe", "").split("/")[-1].split("\\")[-1]
                    anomalies.append({
                        "type": "enumeration_behavior",
                        "severity": "high",
                        "user": user,
                        "source_ip": _get_field(
                            next(
                                e for e in entries
                                if _get_field(e, "parent_process", "ParentImage") == parent
                                and _get_field(e, "user", "User") == user
                            ),
                            "source_ip", "SourceIp", "SourceAddress",
                        ) if any(
                            _get_field(e, "parent_process", "ParentImage") == parent
                            and _get_field(e, "user", "User") == user
                            for e in entries
                        ) else "",
                        "timestamp": dt.isoformat() if hasattr(dt, "isoformat") else "",
                        "details": (
                            f"Enumeration behavior: {parent_stem} spawned "
                            f"{len(distinct_children)} distinct child processes "
                            f"within {_ENUM_SPAWN_WINDOW_MIN}min"
                        ),
                        "detection_method": "enumeration_behavior",
                        "mitre_ids": ["T1082", "T1057"],
                        "process": parent,
                        "host": host,
                    })
                    flagged = True
                    break
            if flagged:
                continue  # One alert per parent is enough

        # --- (b) Sensitive file/path access patterns ---
        # A process accessing multiple sensitive paths in sequence is
        # performing enumeration regardless of its name.
        _LINUX_SENSITIVE_PATHS = [
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
            "/etc/resolv.conf", "/etc/crontab", "/etc/sudoers",
            "/home/", "/root/", "/.ssh/", "/.bash_history",
            "/var/log/", "/proc/self/", "/proc/version",
            "/sys/class/", "/etc/ssh/",
        ]
        _WINDOWS_SENSITIVE_PATHS = [
            "\\windows\\temp\\", "\\appdata\\", "\\programdata\\",
            "\\users\\", "\\sam", "\\system32\\config\\",
            "\\windows\\system32\\", "\\.ssh\\", "\\.bash_history",
            "\\sysvol\\", "\\ntds.dit",
        ]
        _SENSITIVE_REGISTRY = [
            "CurrentVersion\\Run", "SAM", "SYSTEM", "SECURITY",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ]

        # Track per-process target file access
        proc_targets: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        # key: (process, user, host), value: set of matched sensitive patterns
        for e in entries:
            if _get_field(e, "type") != "endpoint":
                continue
            proc = _get_field(e, "process", "Image")
            target = _get_field(e, "target_file", "TargetFilename", "TargetObject")
            registry = _get_field(e, "target_file", "TargetObject")
            user = _get_field(e, "user", "User")
            host = _get_field(e, "host", "Computer")
            key = (proc, user, host)

            # Check file targets
            if target:
                target_lower = target.lower()
                for pat in _LINUX_SENSITIVE_PATHS + _WINDOWS_SENSITIVE_PATHS:
                    if pat.lower() in target_lower:
                        proc_targets[key].add(pat)
                        break

            # Check registry targets
            if registry and "registry" in _get_field(e, "action", "EventCategory").lower():
                reg_lower = registry.lower()
                for pat in _SENSITIVE_REGISTRY:
                    if pat.lower() in reg_lower:
                        proc_targets[key].add(f"reg:{pat}")
                        break

        # Flag processes accessing 3+ distinct sensitive path categories
        _ENUM_PATH_THRESHOLD = 3 if enum_sensitivity >= 0.7 else 5
        for (proc, user, host), matched_paths in proc_targets.items():
            if len(matched_paths) >= _ENUM_PATH_THRESHOLD:
                proc_stem = proc.lower().replace(".exe", "").split("/")[-1].split("\\")[-1]
                anomalies.append({
                    "type": "enumeration_behavior",
                    "severity": "high",
                    "user": user,
                    "source_ip": "",
                    "timestamp": (
                        _get_field(
                            next(
                                e for e in entries
                                if _get_field(e, "process", "Image") == proc
                                and _get_field(e, "user", "User") == user
                            ),
                            "timestamp",
                        ) if any(
                            _get_field(e, "process", "Image") == proc
                            and _get_field(e, "user", "User") == user
                            for e in entries
                        ) else ""
                    ),
                    "details": (
                        f"Enumeration behavior: {proc_stem} accessed "
                        f"{len(matched_paths)} sensitive paths "
                        f"({', '.join(sorted(matched_paths)[:5])})"
                    ),
                    "detection_method": "enumeration_behavior",
                    "mitre_ids": ["T1082", "T1005"],
                    "process": proc,
                    "host": host,
                })

        # --- (c) Command-line enumeration patterns ---
        # Catches scripts that use enumeration commands even if renamed.
        _LINUX_ENUM_COMMANDS = [
            "find / -name", "find / -type", "find / -perm",
            "cat /etc/passwd", "cat /etc/shadow", "cat /etc/hosts",
            "grep -r ", "grep -rl ", "xargs grep",
            "uname -a", "uname -r",
            "whoami", "id ", "hostname",
            "ifconfig", "ip addr", "ip route",
            "netstat -", "ss -", "lsof -",
            "ps aux", "ps -ef", "top -b",
            "ls -la /", "ls -la /etc", "ls -la /home",
            "cat /proc/", "ls /proc/",
            "crontab -l", "systemctl list-",
            "dpkg -l", "rpm -qa", "apt list",
        ]
        _WINDOWS_ENUM_COMMANDS = [
            "systeminfo", "whoami /all", "whoami /priv",
            "net user", "net localgroup", "net group",
            "net share", "net use",
            "ipconfig /all", "ipconfig /displaydns",
            "netstat -ano", "netstat -r",
            "tasklist /v", "tasklist /svc",
            "wmic os get", "wmic computersystem get",
            "wmic process list", "wmic service list",
            "wmic qfe list", "wmic startup list",
            "reg query hklm", "reg query hklm\\software",
            "reg query hkcu", "reg save",
            "dir /s /b c:\\", "dir /s /b \\\\",
            "type c:\\windows\\", "type c:\\users\\",
            "cmdkey /list", "vaultcmd list",
            "powershell -command get-", "get-wmiobject",
            "get-process", "get-service", "get-nettcpconnection",
            "invoke-expression", "iex ",
            "downloadstring", "downloadfile",
            "adfind -f", "csvde -f",
        ]

        _ENUM_CMD_THRESHOLD = 3 if enum_sensitivity >= 0.7 else 5
        user_enum_cmds: dict[tuple[str, str], set[str]] = defaultdict(set)
        # key: (user, host), value: set of matched enum commands
        for e in entries:
            if _get_field(e, "type") != "endpoint":
                continue
            cmd = _get_field(e, "command_line", "CommandLine").lower()
            if not cmd:
                continue
            user = _get_field(e, "user", "User")
            host = _get_field(e, "host", "Computer")
            key = (user, host)

            for pat in _LINUX_ENUM_COMMANDS + _WINDOWS_ENUM_COMMANDS:
                if pat.lower() in cmd:
                    user_enum_cmds[key].add(pat)

        for (user, host), matched_cmds in user_enum_cmds.items():
            if len(matched_cmds) >= _ENUM_CMD_THRESHOLD:
                anomalies.append({
                    "type": "enumeration_behavior",
                    "severity": "high",
                    "user": user,
                    "source_ip": "",
                    "timestamp": (
                        _get_field(
                            next(
                                e for e in entries
                                if _get_field(e, "user", "User") == user
                                and _get_field(e, "host", "Computer") == host
                            ),
                            "timestamp",
                        ) if any(
                            _get_field(e, "user", "User") == user
                            and _get_field(e, "host", "Computer") == host
                            for e in entries
                        ) else ""
                    ),
                    "details": (
                        f"Enumeration behavior: {user} used "
                        f"{len(matched_cmds)} enumeration commands "
                        f"({', '.join(sorted(matched_cmds)[:5])})"
                    ),
                    "detection_method": "enumeration_behavior",
                    "mitre_ids": ["T1082", "T1059"],
                    "host": host,
                })

    # --- 11. Rapid action sequence (lateral movement / cleanup) ---
    seq_window = int(thresholds.get("action_sequence_window_minutes", 30))
    user_host_events = defaultdict(list)
    for e in entries:
        if _get_field(e, "type") != "endpoint":
            continue
        user = _get_field(e, "user", "User")
        host = _get_field(e, "host", "Computer")
        action = _get_field(e, "action")
        cmd = _get_field(e, "command_line", "CommandLine").lower()
        ts = _get_field(e, "timestamp")
        if not action and cmd:
            if any(p in cmd for p in ["echo ", "> ", ">> ", "copy ", "xcopy ", "cp ", "new-item"]):
                action = "create"
            elif any(p in cmd for p in ["del ", "rm ", "erase ", "remove-item", "rmdir"]):
                action = "delete"
            else:
                action = "execute"
        elif not action:
            action = "execute"
        if user and host:
            user_host_events[(user, host)].append({"action": action, "timestamp": ts})

    for (user, host), events in user_host_events.items():
        actions_present = set(ev["action"] for ev in events)
        if not actions_present.issuperset({"create", "execute", "delete"}):
            continue
        create_times = [ev["timestamp"] for ev in events if ev["action"] == "create" and ev["timestamp"]]
        execute_times = [ev["timestamp"] for ev in events if ev["action"] == "execute" and ev["timestamp"]]
        delete_times = [ev["timestamp"] for ev in events if ev["action"] == "delete" and ev["timestamp"]]
        if not (create_times and execute_times and delete_times):
            continue
        all_times = []
        for ts_list in [create_times, execute_times, delete_times]:
            for t in ts_list:
                dt = _parse_ts(t)
                if dt is not None:
                    all_times.append(dt)
        if len(all_times) >= 3:
            earliest = min(all_times)
            latest = max(all_times)
            window_minutes = (latest - earliest).total_seconds() / 60
            if window_minutes <= seq_window:
                anomalies.append({
                    "type": "rapid_action_sequence",
                    "severity": "high",
                    "user": user,
                    "source_ip": "",
                    "timestamp": earliest.isoformat(),
                    "details": (
                        f"Create->execute->delete on {host} by {user} "
                        f"within {window_minutes:.0f}min (window={seq_window}min)"
                    ),
                    "detection_method": "action_sequence",
                    "host": host,
                })

    # --- 12. Suspicious file path ---
    sp_sensitivity = thresholds.get("suspicious_path_sensitivity", 0.7)
    if sp_sensitivity > 0:
        for e in entries:
            if _get_field(e, "type") != "endpoint":
                continue
            proc = _get_field(e, "process", "Image")
            if not proc:
                continue
            proc_lower = proc.lower()
            # Skip processes from known legitimate paths
            is_legitimate = any(re.search(pat, proc_lower, re.IGNORECASE) for pat in LEGITIMATE_PATHS)
            if is_legitimate:
                continue
            # Check for specific suspicious path patterns (high confidence)
            matched_patterns = [name for name, pat in SUSPICIOUS_PATH_PATTERNS
                                if re.search(pat, proc_lower, re.IGNORECASE)]
            # Also flag any process NOT in a legitimate path that has a shallow
            # directory structure (2-3 levels from root) — legitimate software
            # is typically deeper (C:\Program Files\Vendor\App\Sub\file.exe)
            is_shallow = bool(re.match(r"^[A-Z]:\\[^\\]+(\\[^\\]+){1,2}$", proc, re.IGNORECASE))
            if is_shallow:
                matched_patterns.append("shallow_path")
            if matched_patterns:
                # At high sensitivity, flag all matches; at low, only flag 2+ patterns
                if sp_sensitivity < 0.5 and len(matched_patterns) < 2:
                    continue
                anomalies.append({
                    "type": "suspicious_file_path",
                    "severity": "high" if len(matched_patterns) >= 2 else "medium",
                    "user": _get_field(e, "user", "User"),
                    "host": _get_field(e, "host", "HostName"),  # S2: dual attribution
                    "source_ip": _get_field(e, "source_ip", "src_ip"),
                    "timestamp": _get_field(e, "timestamp"),
                    "details": f"Process from suspicious path: {proc} (patterns: {', '.join(matched_patterns)})",
                    "detection_method": "suspicious_path",
                    "process": proc,
                })

    # --- 13. High-integrity process from unusual parent ---
    ia_sensitivity = thresholds.get("integrity_anomaly_sensitivity", 0.7)
    if ia_sensitivity > 0:
        for e in entries:
            if _get_field(e, "type") != "endpoint":
                continue
            integrity = _get_field(e, "integrity_level", "IntegrityLevel").lower()
            user = _get_field(e, "user", "User").lower()
            parent = _get_field(e, "parent_process", "ParentImage").lower().replace(".exe", "")
            # Extract just the filename from the parent path
            parent_stem = parent.rsplit("\\", 1)[-1] if "\\" in parent else parent
            # Flag when a SYSTEM-level process is spawned by a non-system parent
            is_high_integrity = integrity in ("system", "high") or "nt authority\\system" in user
            if not is_high_integrity:
                continue
            parent_is_system = parent_stem in SYSTEM_PARENTS
            if parent_is_system:
                continue
            # At low sensitivity, only flag if the child is also suspicious
            if ia_sensitivity < 0.5:
                proc = _get_field(e, "process", "Image").lower().replace(".exe", "")
                proc_stem = proc.rsplit("\\", 1)[-1] if "\\" in proc else proc
                is_lolbin = any(sig_proc in proc_stem for sig_proc, _, _ in lolbin_sigs)
                if not is_lolbin:
                    continue
            anomalies.append({
                "type": "integrity_anomaly",
                "severity": "high",
                "user": _get_field(e, "user", "User"),
                "host": _get_field(e, "host", "HostName"),  # S2: dual attribution
                "source_ip": _get_field(e, "source_ip", "src_ip"),
                "timestamp": _get_field(e, "timestamp"),
                "details": (
                    f"High-integrity process from non-system parent: "
                    f"integrity={integrity}, parent={parent_stem}"
                ),
                "detection_method": "integrity_anomaly",
            })

    # --- 14. Registry modification by non-standard process ---
    ra_sensitivity = thresholds.get("registry_abuse_sensitivity", 0.7)
    if ra_sensitivity > 0:
        for e in entries:
            if _get_field(e, "type") != "endpoint":
                continue
            action = _get_field(e, "action", "EventType").lower()
            # Only look at registry modification events
            if action not in ("registry_set", "registry_add_delete", "setvalue", "deletevalue",
                              "createkey", "deletekey"):
                continue
            proc = _get_field(e, "process", "Image")
            target = _get_field(e, "target_registry", "TargetObject")
            if not proc or not target:
                continue
            proc_lower = proc.lower()
            target_lower = target.lower()
            # Skip processes from known legitimate paths
            is_legitimate = any(re.search(pat, proc_lower, re.IGNORECASE) for pat in LEGITIMATE_PATHS)
            if is_legitimate and ra_sensitivity < 0.9:
                continue
            # Check if the registry key is a high-value target
            is_critical_key = any(re.search(pat, target_lower, re.IGNORECASE)
                                  for pat in CRITICAL_REGISTRY_PATTERNS)
            # At low sensitivity, only flag critical keys from non-standard processes
            if ra_sensitivity < 0.5 and not is_critical_key:
                continue
            # At medium+ sensitivity, also flag any registry modification from
            # a process in a suspicious path
            is_suspicious_proc = any(re.search(pat, proc_lower, re.IGNORECASE)
                                     for _, pat in SUSPICIOUS_PATH_PATTERNS)
            is_shallow = bool(re.match(r"^[A-Z]:\\[^\\]+(\\[^\\]+){1,2}$", proc, re.IGNORECASE))
            if not is_critical_key and not is_suspicious_proc and not is_shallow:
                continue
            severity = "high" if is_critical_key else "medium"
            anomalies.append({
                "type": "registry_abuse",
                "severity": severity,
                "user": _get_field(e, "user", "User"),
                "host": _get_field(e, "host", "HostName"),  # S2: dual attribution
                "source_ip": _get_field(e, "source_ip", "src_ip"),
                "timestamp": _get_field(e, "timestamp"),
                "details": f"Registry modification by {proc}: {target[:100]}",
                "detection_method": "registry_abuse",
                "target_registry": target,
            })

    # --- 15. Network connection from unusual process ---
    na_sensitivity = thresholds.get("network_anomaly_sensitivity", 0.7)
    if na_sensitivity > 0:
        # Processes that should never make outbound network connections
        NETWORK_LOLBIN_PROCS = {
            "certutil", "mshta", "wscript", "cscript", "regsvr32",
            "rundll32", "bitsadmin", "cmstp", "installutil",
            "msbuild", "msiexec", "presentationhost",
        }
        for e in entries:
            if _get_field(e, "type") != "endpoint":
                continue
            action = _get_field(e, "action").lower()
            if action != "network_connect":
                continue
            proc = _get_field(e, "process", "Image").lower()
            proc_stem = proc.rsplit("\\", 1)[-1].replace(".exe", "") if "\\" in proc else proc.replace(".exe", "")
            dest_ip = _get_field(e, "dest_ip", "DestinationIp")
            dest_port = _get_field(e, "dest_port", "DestinationPort")
            is_lolbin_network = proc_stem in NETWORK_LOLBIN_PROCS
            # Skip processes from known legitimate paths (unless they're LOLBINs)
            is_legitimate = any(re.search(pat, proc, re.IGNORECASE) for pat in LEGITIMATE_PATHS)
            if is_legitimate and not is_lolbin_network:
                continue
            # Check if process is from a suspicious path
            is_suspicious_proc = any(re.search(pat, proc, re.IGNORECASE)
                                     for _, pat in SUSPICIOUS_PATH_PATTERNS)
            is_shallow = bool(re.match(r"^[A-Z]:\\[^\\]+(\\[^\\]+){1,2}$", proc, re.IGNORECASE))
            if is_lolbin_network:
                severity = "high"
            elif is_suspicious_proc or is_shallow:
                if na_sensitivity < 0.5:
                    continue
                severity = "medium"
            else:
                continue
            anomalies.append({
                "type": "network_anomaly",
                "severity": severity,
                "user": _get_field(e, "user", "User"),
                "host": _get_field(e, "host", "HostName"),  # S2: dual attribution
                "source_ip": _get_field(e, "source_ip", "src_ip"),
                "timestamp": _get_field(e, "timestamp"),
                "details": f"Network connection from {proc} to {dest_ip}:{dest_port}",
                "detection_method": "network_anomaly",
            })

    # --- 20. EWMA (Exponentially Weighted Moving Average) ---
    # --- 21. CUSUM (Cumulative Sum) ---
    # --- 22. Entity behavior composite anomaly ---
    # All suppressed during baseline phase — need time-series and entity baselines.
    if phase != "baseline":
        # Detects gradual drift in event rates that z-score misses because the
        # baseline catches up. A brute force attack ramping from 2→5→12 failed
        # logins/hour looks normal to z-score but EWMA flags it by hour 2.
        _BIN_MINUTES = 5
        user_bins: dict[str, list[tuple[int, int]]] = defaultdict(list)  # user -> [(bin_idx, 1)]
        ewma_sensitivity = thresholds.get("ewma_sensitivity", 0.7)
        cusum_sensitivity = thresholds.get("cusum_sensitivity", 0.7)

        # Bin events into 5-minute windows per user (shared by EWMA and CUSUM)
        if ewma_sensitivity > 0 or cusum_sensitivity > 0:
            for e in entries:
                user = _get_field(e, "user", "User")
                ts = _get_field(e, "timestamp")
                if not user or not ts:
                    continue
                dt = _parse_ts(ts)
                if dt is None:
                    continue
                bin_idx = int(dt.timestamp()) // (_BIN_MINUTES * 60)
                user_bins[user].append((bin_idx, 1))

        if ewma_sensitivity > 0:
            # Smoothing factor: low λ = slow drift detection, high λ = fast response
            ewma_lambda = 0.3 if ewma_sensitivity >= 0.7 else 0.1
            # How many sigma above the EWMA to trigger
            ewma_sigma_mult = 2.0 if ewma_sensitivity >= 0.7 else 3.0

            # Aggregate counts per bin
            for user, bin_events in user_bins.items():
                bin_counts: dict[int, int] = defaultdict(int)
                for bin_idx, _ in bin_events:
                    bin_counts[bin_idx] += 1
                if len(bin_counts) < 3:
                    continue  # Need at least 3 bins for EWMA

                sorted_bins = sorted(bin_counts.items())
                counts = [c for _, c in sorted_bins]

                # Compute EWMA and variance
                ewma_val = float(counts[0])
                ewma_var = 0.0  # Exponentially weighted variance
                for i, c in enumerate(counts):
                    if i == 0:
                        continue
                    diff = c - ewma_val
                    ewma_val = ewma_lambda * c + (1 - ewma_lambda) * ewma_val
                    ewma_var = ewma_lambda * diff ** 2 + (1 - ewma_lambda) * ewma_var

                # Check each bin against the EWMA threshold at that point
                # Re-run EWMA to check each bin incrementally
                running_ewma = float(counts[0])
                running_var = 0.0
                for i, c in enumerate(counts):
                    if i == 0:
                        continue
                    # R4 (round 3): Poisson floor on the inline EWMA std too —
                    # quiet-bin stretches left running_var ~0 and normal count
                    # jitter fired 'ewma_drift' on healthy users (the residual
                    # noise the harness's separation probe isolated)
                    running_std = max(running_var ** 0.5, max(running_ewma, 1.0) ** 0.5)
                    running_threshold = running_ewma + ewma_sigma_mult * running_std
                    if c > running_threshold and running_threshold > 0:
                        bin_ts = sorted_bins[i][0] * _BIN_MINUTES * 60
                        try:
                            ts_str = datetime.fromtimestamp(bin_ts, tz=timezone.utc).isoformat()
                        except (OSError, OverflowError):
                            ts_str = ""
                        anomalies.append({
                            "type": "ewma_drift",
                            "severity": "high",
                            "user": user,
                            "source_ip": "",
                            "timestamp": ts_str,
                            "details": (
                                f"EWMA drift: {c} events in {_BIN_MINUTES}min bin "
                                f"(ewma={running_ewma:.1f}, "
                                f"threshold={running_threshold:.1f})"
                            ),
                            "detection_method": "ewma",
                        })
                        break  # One alert per user is enough
                    diff = c - running_ewma
                    running_ewma = ewma_lambda * c + (1 - ewma_lambda) * running_ewma
                    running_var = ewma_lambda * diff ** 2 + (1 - ewma_lambda) * running_var

        # --- 21. CUSUM (Cumulative Sum) ---
        # Detects sustained small shifts that individual outliers don't trigger.
        # A compromised account generating 15% more events consistently won't
        # trigger z-score but CUSUM accumulates evidence.
        if cusum_sensitivity > 0:
            # k = allowance (slack), h = decision threshold
            # Lower sensitivity = higher h (harder to trigger)
            cusum_k = 0.5  # 0.5σ allowance
            cusum_h = 4.0 if cusum_sensitivity >= 0.7 else 5.0  # ARL₀ ≈ 370-465

            for user, bin_events in user_bins.items():
                bin_counts: dict[int, int] = defaultdict(int)
                for bin_idx, _ in bin_events:
                    bin_counts[bin_idx] += 1
                if len(bin_counts) < 3:
                    continue

                sorted_bins = sorted(bin_counts.items())
                counts = [c for _, c in sorted_bins]

                # Compute mean and std of the first half as reference
                n_ref = max(len(counts) // 2, 2)
                ref_counts = counts[:n_ref]
                mu_0 = sum(ref_counts) / len(ref_counts)
                var_0 = sum((c - mu_0) ** 2 for c in ref_counts) / len(ref_counts)
                sigma = var_0 ** 0.5 if var_0 > 0 else 1.0

                # CUSUM: S_t = max(0, S_{t-1} + (x_t - mu_0 - k*sigma) / sigma)
                s_plus = 0.0
                s_minus = 0.0
                for i, c in enumerate(counts):
                    if i < n_ref:
                        continue  # Skip reference period
                    z = (c - mu_0) / sigma
                    s_plus = max(0.0, s_plus + z - cusum_k)
                    s_minus = max(0.0, s_minus - z - cusum_k)

                    if s_plus > cusum_h:
                        bin_ts = sorted_bins[i][0] * _BIN_MINUTES * 60
                        try:
                            ts_str = datetime.fromtimestamp(bin_ts, tz=timezone.utc).isoformat()
                        except (OSError, OverflowError):
                            ts_str = ""
                        anomalies.append({
                            "type": "cusum_shift",
                            "severity": "high",
                            "user": user,
                            "source_ip": "",
                            "timestamp": ts_str,
                            "details": (
                                f"CUSUM sustained shift: S+={s_plus:.1f} "
                                f"(h={cusum_h}), mean={mu_0:.1f}/bin, current={c}"
                            ),
                            "detection_method": "cusum",
                        })
                        break  # One alert per user is enough
                    if s_minus > cusum_h:
                        bin_ts = sorted_bins[i][0] * _BIN_MINUTES * 60
                        try:
                            ts_str = datetime.fromtimestamp(bin_ts, tz=timezone.utc).isoformat()
                        except (OSError, OverflowError):
                            ts_str = ""
                        anomalies.append({
                            "type": "cusum_drop",
                            "severity": "medium",
                            "user": user,
                            "source_ip": "",
                            "timestamp": ts_str,
                            "details": (
                                f"CUSUM sustained drop: S-={s_minus:.1f} "
                                f"(h={cusum_h}), mean={mu_0:.1f}/bin, current={c}"
                            ),
                            "detection_method": "cusum",
                        })
                        break

        # --- 22. Entity behavior composite anomaly ---
        # Combines multiple entity-level signals into a single composite score.
        # Flags entities where multiple behavioral indicators deviate from their
        # historical norms simultaneously, even if no single indicator exceeds
        # its threshold. This catches subtle compromise patterns that evade
        # individual detectors.
        # Only runs when entity_profiles is provided.
        if entity_profiles is not None:
            composite_threshold = thresholds.get("entity_behavior_composite_threshold", 0.6)
            entity_new_user_thresh = int(thresholds.get("entity_new_user_threshold", 1))

            # --- 22a. User composite: combines event count, IP novelty, off-hours, auth ratio ---
            for user, events in user_events.items():
                if not entity_profiles.warm_up_complete("user", user):
                    continue
                profile = entity_profiles.get_user(user)
                if profile is None:
                    continue

                signals = 0
                total_signals = 4  # max possible signals
                signal_details = []

                # Signal 1: Event count deviation from entity EWMA
                count = len(events)
                if profile.typical_event_count.variance > 0:
                    # S4 (round 5): peak-hour rate, not newest-hour
                    from nabla.baselines import hourly_rates
                    _rates = hourly_rates(events, profile)
                    _peak = max(_rates.values()) if _rates else None
                    event_z = (profile.typical_event_count.z_score(_peak)
                               if _peak is not None else 0.0)
                    if event_z > 1.5:  # Lower threshold for composite
                        signals += 1
                        signal_details.append(f"event_count_z={event_z:.1f}")

                # Signal 2: New IPs not in typical set
                current_ips = user_ips.get(user, set())
                if profile.typical_ips:
                    new_ips = current_ips - profile.typical_ips
                    if len(new_ips) > 0:
                        signals += 1
                        signal_details.append(f"{len(new_ips)} new IPs")

                # Signal 3: Off-hours deviation from entity typical hours
                current_hours = user_hours.get(user, [])
                if profile.typical_hours and current_hours:
                    unusual = [h for h in current_hours if h not in profile.typical_hours]
                    if len(unusual) > 0:
                        signals += 1
                        signal_details.append(f"{len(unusual)} atypical hours")

                # Signal 4: Auth failure ratio deviation
                auth = user_auth.get(user, {"success": 0, "failure": 0})
                total_auth = auth["success"] + auth["failure"]
                if total_auth > 0 and profile.auth_failure_ratio.variance > 0:
                    current_ratio = auth["failure"] / total_auth
                    auth_z = profile.auth_failure_ratio.z_score(current_ratio)
                    if auth_z > 1.5:
                        signals += 1
                        signal_details.append(f"auth_failure_z={auth_z:.1f}")

                # Composite score: fraction of signals triggered
                composite_score = signals / total_signals if total_signals > 0 else 0
                if composite_score >= composite_threshold and signals >= 2:
                    anomalies.append({
                        "type": "entity_behavior_composite",
                        "severity": "high" if composite_score >= 0.75 else "medium",
                        "user": user,
                        "source_ip": list(user_ips[user])[0] if user_ips[user] else "",
                        "timestamp": events[0].get("timestamp", ""),
                        "details": (
                            f"User {user}: {signals}/{total_signals} behavioral signals "
                            f"(score={composite_score:.2f}, threshold={composite_threshold}): "
                            f"{', '.join(signal_details)}"
                        ),
                        "detection_method": "entity_behavior_composite",
                        "entity_baseline": True,
                        "composite_score": round(composite_score, 3),
                        "raw_score": round(composite_score, 3),  # N10: calibratable
                    })

            # --- 22b. Host composite: combines new processes, new users, auth anomalies ---
            for host, procs in host_processes.items():
                if not entity_profiles.warm_up_complete("host", host):
                    continue
                profile = entity_profiles.get_host(host)
                if profile is None:
                    continue

                signals = 0
                total_signals = 3  # max possible signals
                signal_details = []

                # Signal 1: New processes not in typical set
                new_procs = []
                for proc in procs:
                    proc_stem = proc.replace(".exe", "").lower()
                    proc_name = proc_stem.rsplit("\\", 1)[-1] if "\\" in proc_stem else proc_stem
                    if proc_name not in profile.typical_processes and proc_name not in COMMON_PROCESSES:
                        new_procs.append(proc_name)
                if len(new_procs) > 0:
                    signals += 1
                    signal_details.append(f"{len(new_procs)} new processes")

                # Signal 2: New users not in typical set
                current_users = set()
                for e in entries:
                    e_host = _get_field(e, "host", "Computer")
                    if e_host == host:
                        u = _get_field(e, "user", "User")
                        if u:
                            current_users.add(u)
                if profile.typical_users:
                    new_users = current_users - profile.typical_users
                    if len(new_users) >= entity_new_user_thresh:
                        signals += 1
                        signal_details.append(f"{len(new_users)} new users: {', '.join(list(new_users)[:3])}")

                # Signal 3: Auth failure ratio deviation
                host_auth_success = 0
                host_auth_failure = 0
                for e in entries:
                    e_host = _get_field(e, "host", "Computer")
                    if e_host == host:
                        action = _get_field(e, "action")
                        if action == "login_success":
                            host_auth_success += 1
                        elif action == "login_failure":
                            host_auth_failure += 1
                total_host_auth = host_auth_success + host_auth_failure
                if total_host_auth > 0 and profile.typical_auth_failure_ratio.variance > 0:
                    current_ratio = host_auth_failure / total_host_auth
                    auth_z = profile.typical_auth_failure_ratio.z_score(current_ratio)
                    if auth_z > 1.5:
                        signals += 1
                        signal_details.append(f"auth_failure_z={auth_z:.1f}")

                composite_score = signals / total_signals if total_signals > 0 else 0
                if composite_score >= composite_threshold and signals >= 2:
                    anomalies.append({
                        "type": "entity_host_composite",
                        "severity": "high" if composite_score >= 0.75 else "medium",
                        "user": "",
                        "source_ip": "",
                        "timestamp": _get_field(e, "timestamp"),  # N2.3: event time
                        "details": (
                            f"Host {host}: {signals}/{total_signals} behavioral signals "
                            f"(score={composite_score:.2f}, threshold={composite_threshold}): "
                            f"{', '.join(signal_details)}"
                        ),
                        "detection_method": "entity_host_composite",
                        "host": host,
                        "entity_baseline": True,
                        "composite_score": round(composite_score, 3),
                        "raw_score": round(composite_score, 3),  # N10: calibratable
                    })

    # Compute baselines for snapshot storage
    baselines = compute_baselines(entries)

    # Add log_type to each anomaly (for threat tool cross-type correlation)
    # Build lookup: user -> set of log types, ip -> set of log types
    user_log_types = defaultdict(set)
    ip_log_types = defaultdict(set)
    for e in entries:
        lt = e.get("type", "unknown")
        u = e.get("user", "")
        ip = e.get("source_ip", e.get("src_ip", e.get("client_ip", "")))
        if u:
            user_log_types[u].add(lt)
        if ip:
            ip_log_types[ip].add(lt)

    for a in anomalies:
        if "log_type" not in a:
            # Infer from the anomaly's user or IP
            u = a.get("user", "")
            ip = a.get("source_ip", "")
            types = set()
            if u and u in user_log_types:
                types.update(user_log_types[u])
            if ip and ip in ip_log_types:
                types.update(ip_log_types[ip])
            if len(types) == 1:
                a["log_type"] = types.pop()
            elif len(types) > 1:
                a["log_type"] = "mixed"
            else:
                a["log_type"] = "unknown"

    logger.info("Detected %d anomalies across %d entries", len(anomalies), len(entries))

    # Phase 2 (remediation plan): stable anomaly IDs on every anomaly
    _stamp_anomaly_ids(anomalies)
    # N7 (round 4): source event ids on every anomaly — the chain gate
    # dedups distinct events by these; without them three detectors on ONE
    # event counted as three and flagged false chains
    _stamp_event_ids(anomalies, entries)

    return anomalies, baselines


def _stamp_anomaly_ids(anomalies: list[dict]) -> None:
    """Phase 2: stable anomaly_id on every anomaly (deterministic hash).

    Hash of (entity, detection_method, timestamp, evidence) — re-running
    the same batch produces identical IDs, which risk retention (A6)
    deduplicates on, correlation chains reference, and the Phase 3 label
    pipeline keys dispositions against. Attached in ONE place rather than
    at 32 construction sites; same-run collisions (same method+entity+ts
    firing twice) get a discriminator suffix.
    """
    import hashlib

    seen: dict[str, int] = {}
    for a in anomalies:
        entity = a.get("entity", a.get("user", a.get("host", "unknown")))
        key_material = "|".join(str(x) for x in (
            entity,
            a.get("detection_method", a.get("type", "")),
            a.get("timestamp", ""),
            a.get("source_ip", ""),
            str(a.get("details", ""))[:80],
            a.get("process", ""),
        ))
        digest = hashlib.sha256(key_material.encode()).hexdigest()[:16]
        if digest in seen:
            seen[digest] += 1
            digest = f"{digest}-{seen[digest]}"
        else:
            seen[digest] = 1
        a["anomaly_id"] = digest


_EVENT_IDS_CAP = 50


def _stamp_event_ids(anomalies: list[dict], entries: list[dict]) -> None:
    """N7 (round 4) + S3 (round 5): every anomaly carries event_ids — the
    stable ids of the source events it derived from.

    S3 changed the division of labor: aggregate detectors now record
    their OWN contributing events at construction (the failed logins,
    the new-IP logins, the atypical-hour events) via _contributing_ids.
    This pass is the FALLBACK for anomalies that arrive without
    event_ids — per-event detections whose (entity, timestamp) exactly
    identifies their single source. It no longer overwrites: a detector
    that cited its evidence keeps it. Idempotent by construction.

    Prefers the ingestion-time event_id (pipeline/ingestion.py:~228,
    hash of key material) over the full-entry hash — one ID scheme
    system-wide; the full-entry hash survives only for entries that
    predate ingestion stamping.
    """
    import hashlib

    by_user: dict[tuple[str, str], list[str]] = defaultdict(list)
    by_host: dict[tuple[str, str], list[str]] = defaultdict(list)
    for e in entries:
        eid = str(e.get("event_id") or "") or hashlib.sha256(
            json.dumps(e, sort_keys=True, default=str).encode()
        ).hexdigest()[:16]
        # mirror the detectors' aggregate key derivation exactly
        u = e.get("user", e.get("src_ip", e.get("client_ip", "unknown")))
        ts = e.get("timestamp", "")
        if ts:
            if u:
                by_user[(str(u), ts)].append(eid)
            h = e.get("host", "")
            if h:
                by_host[(str(h), ts)].append(eid)
    for a in anomalies:
        if a.get("event_ids"):
            continue  # S3: the detector cited its own evidence
        ts = a.get("timestamp", "")
        ids: list[str] = []
        if ts:
            u = a.get("user", "")
            if u:
                ids = by_user.get((str(u), ts), [])
            if not ids:
                h = a.get("host", "")
                if h:
                    ids = by_host.get((str(h), ts), [])
        a["event_ids"] = ids[:_EVENT_IDS_CAP]
