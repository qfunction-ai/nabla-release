"""Deterministic threat correlation — replaces the threat hunting LLM agent.

Ports the logic from the 6 threat tools (fetch_anomalies, fetch_graph_context,
correlate_events, assess_threat_level, produce_finding, build_timeline) into
plain Python functions. No LLM calls needed — all of this is pattern-matching,
grouping, scoring, and templated narrative construction.

The supervisor LLM agent stays for interpretation, false positive filtering,
and attack narrative synthesis. It receives condensed, pre-correlated findings
instead of thousands of raw anomalies.
"""

import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from nabla.log import get_logger
from nabla.utils import esc_block_value

logger = get_logger("correlation")

# Maximum anomalies fed to the timeline builder.
# With 32K context windows, the supervisor can't handle a 38K-char timeline.
# Keep the highest-severity 200 anomalies for the narrative.
_MAX_ANOMALIES_FOR_TIMELINE = 200

# Maximum combined output size (findings + timeline) in characters.
# The supervisor's context window is ~32K tokens (~128K chars), but shared
# blocks + persona + tool schemas already consume most of it.  Keep the
# correlation output under 8K chars to leave room for the LLM to reason.
_MAX_OUTPUT_CHARS = 8000

# V-1 (round 10): findings-block COUNT cap. The threat_findings block
# is the review prompt's payload — a run with hundreds of findings
# would overflow the reviewer's context window. The cap renders the
# loudest 25 and marks the rest; the overflow is a RECORDED
# degradation (threat_findings_capped), never silent truncation.
MAX_BLOCK_FINDINGS = 25

# --- Type labels for timeline narrative ---
_TYPE_LABELS = {
    "lolbin_abuse": "suspicious use of living-off-the-land binaries (LOLBINs)",
    "activity_spike": "an unusual spike in activity volume",
    "z_score_spike": "statistically anomalous activity levels",
    "brute_force_attempt": "brute force authentication attempts",
    "off_hours_activity": "activity during off-hours (22:00-06:00 UTC)",
    "multiple_source_ips": "activity from multiple source IPs",
    "suspicious_domain": "connections to suspicious domains",
    "privilege_escalation": "privilege escalation activity",
    "unusual_process": "execution of unusual processes",
    "rapid_action_sequence": "a rapid create-execute-delete action sequence",
    "suspicious_path": "process execution from a suspicious path",
    "integrity_anomaly": "integrity level anomaly (SYSTEM from non-system parent)",
    "registry_abuse": "registry modification by a non-standard process",
    "network_anomaly": "suspicious network connection from a LOLBIN or unusual path",
    "gcn_lof": "relational anomaly detected by graph analysis",
    "provenance_community": "anomalous provenance community",
    "temporal_chain": "temporal kill-chain sequence",
}

_MITRE_NAMES = {
    "T1105": "Ingress Tool Transfer",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1059": "Command and Scripting Interpreter",
    "T1110": "Brute Force",
    "T1218": "System Binary Proxy Execution",
    "T1036": "Masquerading",
    "T1078": "Valid Accounts",
    "T1071": "Application Layer Protocol",
    "T1562": "Impair Defenses",
    "T1055": "Process Injection",
    "T1027": "Obfuscated Files or Information",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1087": "Account Discovery",
    "T1082": "System Information Discovery",
    "T1018": "Remote System Discovery",
    "T1007": "System Service Discovery",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1021": "Remote Services",
    "T1557": "Adversary-in-the-Middle",
    "T1593": "Search Open Technical Databases",
    "T1053": "Scheduled Task/Job",
}

_CRITICAL_ANOMALY_TYPES = {
    "privilege_escalation", "brute_force_attempt", "suspicious_domain",
    "multiple_source_ips", "lolbin_abuse", "renamed_attack_tool",
    "known_attack_script",
}


# ---------------------------------------------------------------------------
# Tool name extraction — pull specific tool names from anomaly details
# ---------------------------------------------------------------------------

# Regex to extract tool names from anomaly details like:
# "Known attack script: Cobalt Strike C2 framework (cobaltstrike)"
# "Renamed attack tool: Rubeus kerberoast (Rubeus)"
_TOOL_NAME_RE = re.compile(r'\((\w[\w.-]+)\)\s*$')


def _extract_tool_names(anomalies: list[dict]) -> list[str]:
    """Extract specific tool names from attack_script/renamed_tool anomalies.

    Uses the 'tool_display_name' field (human-readable like "Cobalt Strike beacon"),
    falling back to 'tool_name' (raw key like "beacon.exe"), then parsing 'details'.

    Args:
        anomalies: List of anomaly dicts.

    Returns:
        Deduplicated list of tool display names (e.g., ["Cobalt Strike", "Rubeus"]).
    """
    names = []
    seen = set()
    for a in anomalies:
        det = a.get("detection_method", a.get("type", ""))
        if det not in ("attack_script", "renamed_tool"):
            continue
        # Primary: use tool_display_name (human-readable)
        display = a.get("tool_display_name")
        if display:
            if display.lower() not in seen:
                seen.add(display.lower())
                names.append(display)
            continue
        # Secondary: use tool_name (raw key)
        tool_name = a.get("tool_name")
        if tool_name and tool_name.lower() not in seen:
            seen.add(tool_name.lower())
            names.append(tool_name)
            continue
        # Tertiary: parse from details string
        details = a.get("details", "")
        m = _TOOL_NAME_RE.search(details)
        if m:
            raw = m.group(1).lower()
            if raw not in seen:
                seen.add(raw)
                names.append(raw)
    return names


def _anomaly_ids(events: list) -> list[str]:
    """FR-3: deduped anomaly_ids from source anomalies, Nones dropped.

    The threat_findings block must carry the IDs the structured
    narrative is asked to cite — the model cannot cite IDs it cannot
    see, and the D-10 evidence resolver is unbuildable without them.
    """
    seen: list[str] = []
    for e in events:
        aid = e.get("anomaly_id") if isinstance(e, dict) else None
        if aid and aid not in seen:
            seen.append(aid)
    return seen


# ---------------------------------------------------------------------------
# Parsers — extract structured data from shared block text
# ---------------------------------------------------------------------------

def parse_anomaly_queue(queue_text: str) -> list[dict]:
    """Extract anomaly dicts from the anomaly_queue block text.

    Each anomaly is stored as a human-readable line followed by a JSON: line.
    We parse the JSON lines for structured data.

    Args:
        queue_text: Raw text from the anomaly_queue block.

    Returns:
        List of anomaly dicts parsed from JSON: lines.
    """
    if not queue_text or "none" in queue_text.lower():
        return []

    anomalies = []
    for line in queue_text.strip().split("\n"):
        line = line.strip()
        if line.startswith("JSON:"):
            try:
                entry = json.loads(line[5:])
                if isinstance(entry, dict):
                    anomalies.append(entry)
            except json.JSONDecodeError:
                pass  # silent by design: unparseable graph context JSON (2026-09 sweep)

    return anomalies


def parse_graph_context(graph_text: str) -> tuple[dict, dict, list, list]:
    """Extract entity lookups and raw data from the graph_context block.

    Args:
        graph_text: Raw text from the graph_context block.

    Returns:
        Tuple of (entity_communities, entity_chains, communities, chains).
        entity_communities: {entity_key: {community_id, anomaly_density, flagged, types, neighbors}}
        entity_chains: {entity_key: [{chain_id, phases, score, phase_coverage}]}
        communities: raw community dicts
        chains: raw chain dicts
    """
    entity_communities: dict = {}
    entity_chains: dict = {}
    communities: list = []
    chains: list = []

    if not graph_text or "not yet analyzed" in graph_text or "no provenance" in graph_text:
        return entity_communities, entity_chains, communities, chains

    for line in graph_text.split("\n"):
        line = line.strip()
        if line.startswith("JSON:"):
            try:
                data = json.loads(line[5:])
                if "communities" in data:
                    communities = data["communities"]
                if "chains" in data:
                    chains = data["chains"]
            except json.JSONDecodeError:
                pass  # silent by design: unparseable attack mapping JSON (2026-09 sweep)

    # Build entity-to-community lookup
    for comm in communities:
        for member in comm.get("members", []):
            entity_communities[member.lower()] = {
                "community_id": comm["id"],
                "anomaly_density": comm.get("anomaly_density", 0.0),
                "flagged": comm.get("flagged", False),
                "types": comm.get("types", []),
                "neighbors": comm.get("neighbors", {}).get(member, []),
            }

    # Build entity-to-chain lookup
    for chain in chains:
        for etype, entities in chain.get("entities", {}).items():
            for entity in entities:
                key = f"{etype}:{entity}".lower()
                if key not in entity_chains:
                    entity_chains[key] = []
                entity_chains[key].append({
                    "chain_id": chain["chain_id"],
                    "phases": chain.get("phases", []),
                    "score": chain.get("score", 0.0),
                    "phase_coverage": chain.get("phase_coverage", 0.0),
                })

    return entity_communities, entity_chains, communities, chains


def parse_attack_mapping(mapping_text: str) -> dict[str, list]:
    """Parse the attack_mapping block text into an anomaly_type → techniques lookup.

    The block format is:
        anomaly_type:
          T1110 | Brute Force | credential-access
          T1218 | System Binary Proxy Execution | defense-evasion

    Args:
        mapping_text: Raw text from the attack_mapping block.

    Returns:
        Dict mapping anomaly type names to lists of {id, name, tactic} dicts.
    """
    if not mapping_text or "not loaded" in mapping_text:
        return {}

    attack_lookup: dict[str, list] = {}
    current_type = None

    for line in mapping_text.split("\n"):
        line = line.rstrip()
        if not line:
            continue
        if not line.startswith(" "):
            current_type = line.rstrip(":")
            attack_lookup[current_type] = []
            continue
        line = line.strip()
        if line.startswith("Groups:") or line.startswith("Mitigations:"):
            continue
        if current_type and "|" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3:
                attack_lookup[current_type].append({
                    "id": parts[0],
                    "name": parts[1],
                    "tactic": parts[2],
                })

    return attack_lookup


# ---------------------------------------------------------------------------
# Correlation — group anomalies by entity and time window
# ---------------------------------------------------------------------------

def _lookup_graph_context(
    entity: str,
    entity_type: str,
    entity_communities: dict,
    entity_chains: dict,
) -> tuple[dict | None, list | None]:
    """Look up graph context for an entity.

    Args:
        entity: Entity identifier (IP, username, etc.).
        entity_type: Type of entity ("ip", "user", "process", "host").
        entity_communities: Entity-to-community lookup dict.
        entity_chains: Entity-to-chain lookup dict.

    Returns:
        Tuple of (graph_community, temporal_chains) or (None, None).
    """
    graph_community = None
    temporal_chains_found = None

    # Try multiple key formats
    keys = [f"{entity_type}:{entity}".lower(), entity.lower()]
    if entity_type == "ip":
        keys.extend([f"host:{entity}".lower()])
    elif entity_type == "user":
        keys.extend([f"host:{entity}".lower()])

    for key in keys:
        if key in entity_communities:
            c = entity_communities[key]
            graph_community = {
                "community_id": c["community_id"],
                "anomaly_density": c["anomaly_density"],
                "flagged": c["flagged"],
                "types": c.get("types", []),
            }
            if c.get("neighbors"):
                graph_community["neighbors"] = c["neighbors"][:5]
            break

    for key in keys:
        if key in entity_chains:
            temporal_chains_found = entity_chains[key]
            break

    return graph_community, temporal_chains_found


def correlate_anomalies(
    anomalies: list[dict],
    entity_communities: dict,
    entity_chains: dict,
) -> list[dict]:
    """Group anomalies by IP, user, and process; cluster within time windows.

    Correlation methods:
    - IP-based: anomalies sharing a source IP across log types
    - User-based: anomalies sharing a user across log types
    - Process-based: anomalies sharing a process name
    - Time-window: anomalies from the same entity within 30 minutes

    Args:
        anomalies: List of anomaly dicts (from parse_anomaly_queue or detect_anomalies).
        entity_communities: Entity-to-community lookup from parse_graph_context.
        entity_chains: Entity-to-chain lookup from parse_graph_context.

    Returns:
        List of correlation dicts, each with entity, entity_type, log_types,
        anomaly_types, severity, narrative, and optional graph context.
    """
    # Group by IP, user, process
    ip_events: dict[str, list] = defaultdict(list)
    user_events: dict[str, list] = defaultdict(list)
    process_events: dict[str, list] = defaultdict(list)

    for e in anomalies:
        ip = e.get("source_ip", e.get("src_ip", e.get("client_ip", "")))
        if ip:
            ip_events[ip].append(e)
        user = e.get("user", "")
        if user:
            user_events[user].append(e)
        # Extract process from details for process-based correlation
        process = _extract_process(e)
        if process:
            process_events[process].append(e)

    correlations = []

    # IP-based: find IPs with anomalies across multiple log types
    for ip, events in ip_events.items():
        if len(events) < 2:
            continue
        log_types = set(e.get("log_type", e.get("type", "unknown")) for e in events)
        anomalous = [e for e in events if e.get("type") or e.get("detection_method")]
        if len(log_types) >= 2 and anomalous:
            anomaly_types = set(
                e.get("detection_method", e.get("type", "unknown")) for e in anomalous
            )
            corr = {
                "entity": ip,
                "entity_type": "ip",
                "log_types": sorted(log_types),
                "anomaly_types": sorted(anomaly_types),
                "anomaly_ids": _anomaly_ids(anomalous),
                "total_events": len(events),
                "anomalous_events": len(anomalous),
                "severity": "critical" if len(log_types) >= 3 else "high",
                "narrative": f"IP {ip} has anomalies across {len(log_types)} log types: {', '.join(sorted(log_types))}",
            }
            graph_community, temporal_chains_found = _lookup_graph_context(
                ip, "ip", entity_communities, entity_chains,
            )
            if graph_community:
                corr["graph_community"] = graph_community
            if temporal_chains_found:
                corr["temporal_chains"] = temporal_chains_found
            correlations.append(corr)

    # User-based: find users with anomalies across multiple log types
    # or multiple detection methods within the same log type
    for user, events in user_events.items():
        if len(events) < 2:
            continue
        log_types = set(e.get("log_type", e.get("type", "unknown")) for e in events)
        anomalous = [e for e in events if e.get("type") or e.get("detection_method")]
        anomaly_types = set(
            e.get("detection_method", e.get("type", "unknown")) for e in anomalous
        )
        # Correlate if: cross-log-type OR multiple detection methods OR critical anomalies
        has_cross_type = len(log_types) >= 2
        has_multi_method = len(anomaly_types) >= 2
        has_critical = any(e.get("severity") == "critical" for e in anomalous)
        if (has_cross_type or has_multi_method or has_critical) and anomalous:
            corr = {
                "entity": user,
                "entity_type": "user",
                "log_types": sorted(log_types),
                "anomaly_types": sorted(anomaly_types),
                "anomaly_ids": _anomaly_ids(anomalous),
                "total_events": len(events),
                "anomalous_events": len(anomalous),
                "severity": "critical" if has_cross_type and len(log_types) >= 3 or has_critical else "high",
                "narrative": (
                    f"User {user} has anomalies across {len(log_types)} log types: {', '.join(sorted(log_types))}"
                    if has_cross_type
                    else (
                        f"User {user} flagged by {len(anomaly_types)} "
                        f"detection method(s): {', '.join(sorted(anomaly_types))}"
                    )
                ),
            }
            graph_community, temporal_chains_found = _lookup_graph_context(
                user, "user", entity_communities, entity_chains,
            )
            if graph_community:
                corr["graph_community"] = graph_community
            if temporal_chains_found:
                corr["temporal_chains"] = temporal_chains_found
            correlations.append(corr)

    # Process-based: find processes with multiple anomaly types
    # or multiple critical-severity anomalies
    for process, events in process_events.items():
        if len(events) < 2:
            continue
        anomaly_types = set(
            e.get("detection_method", e.get("type", "unknown")) for e in events
        )
        has_multi_method = len(anomaly_types) >= 2
        has_critical = any(e.get("severity") == "critical" for e in events)
        if not has_multi_method and not has_critical:
            continue
        corr = {
            "entity": process,
            "entity_type": "process",
            "anomaly_types": sorted(anomaly_types),
            "anomaly_ids": _anomaly_ids(events),
            "total_events": len(events),
            "anomalous_events": len(events),
            "severity": (
                "critical" if has_critical
                else "high" if has_multi_method and len(anomaly_types) >= 3
                else "medium"
            ),
            "narrative": (
                (
                    f"Process {process} flagged by {len(anomaly_types)} "
                    f"detection methods: {', '.join(sorted(anomaly_types))}"
                )
                if has_multi_method
                else f"Process {process} triggered {len(events)} critical anomaly alert(s)"
            ),
        }
        graph_community, temporal_chains_found = _lookup_graph_context(
            process, "process", entity_communities, entity_chains,
        )
        if graph_community:
            corr["graph_community"] = graph_community
        if temporal_chains_found:
            corr["temporal_chains"] = temporal_chains_found
        correlations.append(corr)

    # Time-window: cluster events within 30 minutes from the same IP
    for ip, events in ip_events.items():
        if len(events) < 2:
            continue
        parsed = []
        for e in events:
            ts = e.get("timestamp", "")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    parsed.append((dt, e))
                except (ValueError, TypeError):
                    pass  # silent by design: unparseable timestamp in correlation (2026-09 sweep)
        if len(parsed) < 2:
            continue
        parsed.sort(key=lambda x: x[0])

        cluster = [parsed[0]]
        for i in range(1, len(parsed)):
            if (parsed[i][0] - cluster[0][0]) <= timedelta(minutes=30):
                cluster.append(parsed[i])
            else:
                if len(cluster) >= 2:
                    cluster_types = set(
                        e.get("log_type", e.get("type", "unknown")) for _, e in cluster
                    )
                    if len(cluster_types) >= 2:
                        corr = {
                            "entity": ip,
                            "entity_type": "ip_time_window",
                            "anomaly_ids": _anomaly_ids([e for _, e in cluster]),
                            "log_types": sorted(cluster_types),
                            "time_window": f"{cluster[0][0].isoformat()} to {cluster[-1][0].isoformat()}",
                            "event_count": len(cluster),
                            "severity": "high",
                            "narrative": f"IP {ip} active across {len(cluster_types)} log types within 30 min",
                        }
                        graph_community, temporal_chains_found = _lookup_graph_context(
                            ip, "ip", entity_communities, entity_chains,
                        )
                        if graph_community:
                            corr["graph_community"] = graph_community
                        if temporal_chains_found:
                            corr["temporal_chains"] = temporal_chains_found
                        correlations.append(corr)
                cluster = [parsed[i]]

        # Check last cluster
        if len(cluster) >= 2:
            cluster_types = set(
                e.get("log_type", e.get("type", "unknown")) for _, e in cluster
            )
            if len(cluster_types) >= 2:
                corr = {
                    "entity": ip,
                    "entity_type": "ip_time_window",
                    "log_types": sorted(cluster_types),
                    "time_window": f"{cluster[0][0].isoformat()} to {cluster[-1][0].isoformat()}",
                    "event_count": len(cluster),
                    "severity": "high",
                    "narrative": f"IP {ip} active across {len(cluster_types)} log types within 30 min",
                }
                graph_community, temporal_chains_found = _lookup_graph_context(
                    ip, "ip", entity_communities, entity_chains,
                )
                if graph_community:
                    corr["graph_community"] = graph_community
                if temporal_chains_found:
                    corr["temporal_chains"] = temporal_chains_found
                correlations.append(corr)

    # Standalone critical: any critical-severity anomaly from a critical type
    # that wasn't already captured by the above correlation paths.
    correlated_entities = {
        (c["entity"], c["entity_type"]) for c in correlations
    }
    for e in anomalies:
        if e.get("severity") != "critical":
            continue
        det = e.get("detection_method", e.get("type", ""))
        if det not in _CRITICAL_ANOMALY_TYPES:
            continue
        # Check if already covered by a user or process correlation
        user = e.get("user", "")
        proc = _extract_process(e)
        already_covered = False
        if user and ("user", user) in correlated_entities:  # noqa: FURB132
            already_covered = True
        if proc and ("process", proc) in correlated_entities:
            already_covered = True
        if already_covered:
            continue
        corr = {
            "entity": user or proc or "unknown",
            "entity_type": "user" if user else "process" if proc else "unknown",
            "anomaly_types": [det],
            "total_events": 1,
            "anomalous_events": 1,
            "severity": "critical",
            "narrative": e.get("details", f"Critical anomaly: {det}"),
        }
        correlations.append(corr)

    # Enrich each correlation with specific tool names detected
    for corr in correlations:
        # Collect the anomalous events for this correlation
        corr_events = [e for e in anomalies
                       if e.get("user") == corr.get("entity")
                       or e.get("source_ip", e.get("src_ip", e.get("client_ip", ""))) == corr.get("entity")
                       or _extract_process(e) == corr.get("entity")]
        tools = _extract_tool_names(corr_events)
        if tools:
            corr["tools_detected"] = tools

    return correlations


def _extract_process(anomaly: dict) -> str:
    """Extract a normalized process name from an anomaly dict.

    Args:
        anomaly: Anomaly dict with 'details' field.

    Returns:
        Normalized process name (lowercase, no path), or empty string.
    """
    details = anomaly.get("details", "")
    # Try common patterns in details text
    patterns = [
        r"\(process: (\S+?)\)",  # "(process: rsynctool)" in renamed_tool details
        r"LOLBIN (.+?)(?: with|$)",  # "LOLBIN C:\Windows\System32\certutil.exe with"
        r"by ((?:[A-Za-z]:\\|/)\S+?)(?::\s|$)",  # "by C:\Intel\Build\LB3.exe: suspicious"
        r"Process from suspicious path: (.+?)(?: \(|$)",  # "Process from suspicious path: C:\Intel\Build\LB3.exe ("
    ]
    for pat in patterns:
        m = re.search(pat, details)
        if m:
            proc = m.group(1).strip()
            # Normalize: extract filename
            proc = proc.replace("/", "\\")
            parts = proc.split("\\")
            return parts[-1].lower().replace(".exe", "")

    return ""


# ---------------------------------------------------------------------------
# Assessment — score severity and enrich with ATT&CK
# ---------------------------------------------------------------------------

def assess_findings(
    correlations: list[dict],
    attack_lookup: dict[str, list],
) -> list[dict]:
    """Score severity, enrich with ATT&CK mappings, and boost for graph context.

    Args:
        correlations: List of correlation dicts from correlate_anomalies.
        attack_lookup: Anomaly type → [{id, name, tactic}] from parse_attack_mapping.

    Returns:
        List of finding dicts with severity, confidence, mitre_attack, and
        graph context boosts applied.
    """
    findings = []

    for corr in correlations:
        anomaly_types = set(corr.get("anomaly_types", []))
        log_types = set(corr.get("log_types", []))

        # Base severity score (1-4)
        score = 2  # medium base
        if len(log_types) >= 3:
            score = 4
        elif len(log_types) >= 2:
            score = 3

        # Boost for critical anomaly types
        if anomaly_types & _CRITICAL_ANOMALY_TYPES:
            score = min(score + 1, 4)

        # Boost for volume
        anomalous_count = corr.get("anomalous_events", corr.get("total_events", 1))
        if anomalous_count >= 5:
            score = min(score + 1, 4)

        # ATT&CK enrichment
        mitre_attack = []
        for atype in sorted(anomaly_types):
            for tech in attack_lookup.get(atype, []):
                mitre_attack.append(tech)

        # Graph context boosts
        graph_community = corr.get("graph_community")
        temporal_chains_found = corr.get("temporal_chains")
        if graph_community and graph_community.get("flagged"):
            score = min(score + 1, 4)
        if temporal_chains_found:
            score = min(score + 1, 4)

        severity = {1: "low", 2: "medium", 3: "high", 4: "critical"}.get(score, "medium")
        cross_type = "cross-type" if len(log_types) >= 2 else "single-type"

        finding = {
            "severity": severity,
            "type": ", ".join(sorted(anomaly_types)),
            "entity": corr["entity"],
            "entity_type": corr["entity_type"],
            "anomaly_ids": list(corr.get("anomaly_ids") or []),
            "cross_type": cross_type,
            "log_types": sorted(log_types),
            "confidence": min(0.5 + anomalous_count * 0.1, 1.0),
            "mitre_attack": mitre_attack,
        }
        if corr.get("tools_detected"):
            finding["tools_detected"] = corr["tools_detected"]
        if graph_community:
            finding["graph_community"] = graph_community
        if temporal_chains_found:
            finding["temporal_chains"] = temporal_chains_found
        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Formatting — write findings to block text
# ---------------------------------------------------------------------------

def format_findings(
    findings: list[dict],
    entity_profiles=None,
    anomalies: list[dict] | None = None,
) -> str:
    """Format findings as text for the threat_findings block.

    Args:
        findings: List of finding dicts from assess_findings.
        entity_profiles: Optional EntityProfileStore — adds a compact
            baseline clause to findings whose entity is warm (UI2b).
        anomalies: Optional anomaly list — adds a compact evidence
            excerpt (the contributing anomalies' details, capped) to
            each finding. D-11 (round 9): without this, the command
            lines — where injected instructions live — never reached
            the supervisor, so the narrative could not report the
            attempt.

    Returns:
        Formatted text for the threat_findings block.
    """
    from nabla.degradations import report_degradation

    capped_count = 0
    if len(findings) > MAX_BLOCK_FINDINGS:
        capped_count = len(findings) - MAX_BLOCK_FINDINGS
        report_degradation("threat_findings_capped")
        findings = findings[:MAX_BLOCK_FINDINGS]

    def _baseline_clause(entity: str) -> str:
        if entity_profiles is None:
            return ""
        profile = None
        for store in (getattr(entity_profiles, "users", None),
                      getattr(entity_profiles, "hosts", None),
                      getattr(entity_profiles, "ips", None)):
            if store and entity in store:
                profile = store[entity]
                break
        if profile is None or getattr(profile, "observation_count", 0) < 3:
            return ""
        parts = []
        tec = getattr(profile, "typical_event_count", None)
        if tec is not None and getattr(tec, "value", 0) > 0:
            parts.append(f"~{tec.value:.0f} events/run typical")
        tips = getattr(profile, "typical_ips", None)
        if tips:
            parts.append(f"{len(tips)} IPs typical")
        return f" [baseline: {'; '.join(parts)}]" if parts else ""
    if not findings:
        return "Confirmed threats: none"

    # D-11: anomaly_id -> details map for the evidence excerpts
    anomaly_details = {}
    if anomalies is not None:
        for a in anomalies:
            aid = a.get("anomaly_id")
            if aid and a.get("details"):
                anomaly_details[aid] = str(a["details"])

    lines = [f"Confirmed threats: {len(findings)}"]
    for f in findings:
        cross = f" ({f['cross_type']})" if f.get("cross_type") == "cross-type" else ""

        # ATT&CK technique string
        attack_str = ""
        if f.get("mitre_attack"):
            techs = ", ".join(f"{t['id']} {t['name']}" for t in f["mitre_attack"])
            attack_str = f" ({techs})"

        # Graph context string
        graph_str = ""
        if f.get("graph_community"):
            gc = f["graph_community"]
            graph_str = f" [Community {gc['community_id']}: density={gc['anomaly_density']:.2f}]"
        if f.get("temporal_chains"):
            chains = f["temporal_chains"]
            chain_strs = ", ".join(
                f"Chain {c['chain_id']} ({' → '.join(c.get('phases', []))})"
                for c in chains[:2]
            )
            graph_str += f" [{chain_strs}]"

        # Tool names string
        tools_str = ""
        if f.get("tools_detected"):
            tools_str = (
                # RR-1: tool names are attacker-influenced (the tertiary
                # fallback in _extract_tool_names parses them out of
                # anomaly details) — escape them like every other
                # log-derived string.
                f" [Tools: {', '.join(esc_block_value(t, 64) for t in f['tools_detected'])}]"
            )

        # FR-3: anomaly IDs — the evidence contract. The model cites
        # these in claims[]; the D-10 resolver checks them against
        # stored anomalies. Capped to keep the block's token budget.
        ids = f.get("anomaly_ids") or []
        ids_str = ""
        if ids:
            shown = ", ".join(ids[:8])
            more = f" (+{len(ids) - 8} more)" if len(ids) > 8 else ""
            ids_str = f" [anomaly_ids: {shown}{more}]"

        # D-11 (round 9): compact evidence excerpt — up to 2
        # contributing anomalies' details, capped. This is where
        # command lines (and any injected instructions inside them)
        # reach the supervisor. Bounded: 2 x 200 chars per finding
        # (200 keeps a full urlcache command line with an appended
        # instruction legible — a shorter cap cuts the tail, which is
        # exactly where injected text rides).
        evidence_str = ""
        if anomaly_details:
            excerpts = [
                # RR-1: escape the excerpt — truncate-then-escape (T-3)
                esc_block_value(anomaly_details[aid], 200)
                for aid in ids[:2]
                if aid in anomaly_details
            ]
            if excerpts:
                evidence_str = " [evidence: " + " | ".join(excerpts) + "]"

        lines.append(
            (
                f"\n[{f['severity'].upper()}] {f['type']} "
                # RR-1: entity names come from logs (usernames,
                # hostnames) — escape them.
                f"by {f['entity_type']} {esc_block_value(f['entity'], 128)}"
                f"{cross}{attack_str}{tools_str}{graph_str}{ids_str}{evidence_str}"
                f"{_baseline_clause(f['entity'])} "
                f"(confidence: {f['confidence']:.0%})"
            )
        )

    if capped_count:
        lines.append(
            f"\n[... {capped_count} more findings capped — "
            "see run detail for the full list]"
        )

    return "".join(lines)


# ---------------------------------------------------------------------------
# Timeline — chronological narrative
# ---------------------------------------------------------------------------

def _parse_ts(a: dict) -> datetime:
    """Parse timestamp from anomaly dict for sorting.

    Args:
        a: Anomaly dict with optional 'timestamp' key.

    Returns:
        Parsed datetime, or timezone-aware datetime.max if missing or invalid.
    """
    _max_aware = datetime.max.replace(tzinfo=timezone.utc)
    ts = a.get("timestamp", "")
    if not ts:
        return _max_aware
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return _max_aware


def _fmt_ts(ts_str: str) -> str:
    """Format ISO timestamp to human-readable.

    Args:
        ts_str: ISO format timestamp string.

    Returns:
        Human-readable time string.
    """
    if not ts_str or ts_str == "unknown":
        return "an unknown time"
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%H:%M UTC on %b %d")
    except (ValueError, TypeError):
        return ts_str


def _fmt_duration(start_str: str, end_str: str) -> str:
    """Format duration between two ISO timestamps.

    Args:
        start_str: Start ISO timestamp.
        end_str: End ISO timestamp.

    Returns:
        Human-readable duration string.
    """
    try:
        start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
        delta = end - start
        total_sec = int(delta.total_seconds())
        if total_sec < 60:
            return f"{total_sec} seconds"
        elif total_sec < 3600:
            return f"{total_sec // 60} minutes"
        else:
            hours = total_sec // 3600
            mins = (total_sec % 3600) // 60
            if mins:
                return f"{hours} hours and {mins} minutes"
            return f"{hours} hours"
    except (ValueError, TypeError):
        return "an unknown duration"


def _fmt_gap(prev_end_str: str, next_start_str: str) -> str:
    """Format time gap between two phases.

    Args:
        prev_end_str: End timestamp of previous phase.
        next_start_str: Start timestamp of next phase.

    Returns:
        Human-readable gap string.
    """
    try:
        prev = datetime.fromisoformat(prev_end_str.replace("Z", "+00:00"))
        next_ = datetime.fromisoformat(next_start_str.replace("Z", "+00:00"))
        delta = next_ - prev
        total_sec = int(delta.total_seconds())
        if total_sec < 60:
            return f"{total_sec} seconds later"
        elif total_sec < 3600:
            return f"{total_sec // 60} minutes later"
        else:
            hours = total_sec // 3600
            mins = (total_sec % 3600) // 60
            if mins:
                return f"{hours} hours and {mins} minutes later"
            return f"{hours} hours later"
    except (ValueError, TypeError):
        return "later"


def _describe_phase(phase: dict, is_first: bool, prev_phase: dict) -> str:
    """Build a detailed prose sentence for one phase of activity.

    Args:
        phase: Phase dict with user, count, events, start_ts, end_ts keys.
        is_first: Whether this is the first phase in the narrative.
        prev_phase: Previous phase dict, or empty dict for the first phase.

    Returns:
        Formatted prose sentence describing the phase.
    """
    user = phase["user"]
    count = phase["count"]
    events = phase["events"]
    types = sorted(set(e.get("type", e.get("detection_method", "unknown")) for e in events))
    severities = sorted(set(e.get("severity", "unknown") for e in events))
    highest = "critical" if "critical" in severities else (
        "high" if "high" in severities else (
            "medium" if "medium" in severities else "low"))
    first_ts = events[0].get("timestamp", "unknown")
    last_ts = events[-1].get("timestamp", "unknown")

    # --- Build the opening clause ---
    if is_first:
        start_text = _fmt_ts(first_ts)
        has_ts = bool(first_ts) and first_ts != "unknown"
        if has_ts and first_ts != last_ts:
            dur_text = _fmt_duration(first_ts, last_ts)
            opening = (
                f"Beginning at {start_text}, {user} triggered "
                f"{count} {highest}-severity anomalies spanning {dur_text}"
            )
        elif has_ts:
            if count == 1:
                opening = f"At {start_text}, {user} triggered a {highest}-severity anomaly"
            else:
                opening = f"At {start_text}, {user} triggered {count} {highest}-severity anomalies"
        else:
            if count == 1:
                opening = f"{user} triggered a {highest}-severity anomaly"
            else:
                opening = f"{user} triggered {count} {highest}-severity anomalies"
    else:
        prev_last_ts = (
            prev_phase.get("events", [{}])[-1].get("timestamp", "unknown")
            if prev_phase.get("events") else "unknown"
        )
        has_ts = bool(first_ts) and first_ts != "unknown"
        has_prev_ts = bool(prev_last_ts) and prev_last_ts != "unknown"
        if has_ts and has_prev_ts:
            gap_text = _fmt_gap(prev_last_ts, first_ts)
            if first_ts != last_ts:
                dur_text = _fmt_duration(first_ts, last_ts)
                opening = (
                    f"{gap_text.capitalize()}, {user} triggered "
                    f"{count} {highest}-severity anomalies lasting {dur_text}"
                )
            else:
                if count == 1:
                    opening = f"{gap_text.capitalize()}, {user} triggered a {highest}-severity anomaly"
                else:
                    opening = f"{gap_text.capitalize()}, {user} triggered {count} {highest}-severity anomalies"
        else:
            if count == 1:
                opening = f"Separately, {user} triggered a {highest}-severity anomaly"
            else:
                opening = f"Separately, {user} triggered {count} {highest}-severity anomalies"

    # --- Build detail clauses per anomaly type ---
    detail_clauses = []

    # LOLBIN abuse: list unique binaries and commands
    if "lolbin_abuse" in types:
        lolbin_events = [e for e in events if e.get("type") == "lolbin_abuse" or e.get("detection_method") == "lolbin"]
        binaries = set()
        commands = []
        mitre_set = set()
        for e in lolbin_events:
            d = e.get("details", "")
            bin_match = re.search(r"LOLBIN .+\\(.+?) with", d)
            if not bin_match:
                bin_match = re.search(r"LOLBIN .+/(.+?) with", d)
            if bin_match:
                binaries.add(bin_match.group(1))
            cmd_match = re.search(r"suspicious command: (.+)", d)
            if cmd_match:
                cmd = cmd_match.group(1).strip()
                if len(cmd) > 80:
                    cmd = cmd[:77] + "..."
                commands.append(cmd)
            for mid in e.get("mitre_ids", []):
                mitre_set.add(mid)

        if binaries:
            bin_list = sorted(binaries)
            if len(bin_list) == 1:
                bin_text = bin_list[0]
            elif len(bin_list) == 2:
                bin_text = f"{bin_list[0]} and {bin_list[1]}"
            else:
                bin_text = ", ".join(bin_list[:-1]) + ", and " + bin_list[-1]
            detail_clauses.append(f"using {bin_text}")

        if commands:
            unique_cmds = sorted(set(commands))[:2]
            cmd_texts = [f'"{cmd}"' for cmd in unique_cmds]
            if len(unique_cmds) == 1:
                detail_clauses.append(f"with the command {cmd_texts[0]}")
            else:
                detail_clauses.append(f"with commands including {', '.join(cmd_texts)}")

        if mitre_set:
            mitre_texts = []
            for mid in sorted(mitre_set):
                name = _MITRE_NAMES.get(mid, "")
                if name:
                    mitre_texts.append(f"{mid} ({name})")
                else:
                    mitre_texts.append(mid)
            detail_clauses.append(f"mapped to MITRE ATT&CK techniques {', '.join(mitre_texts)}")

    # Activity spike: include event counts
    if "activity_spike" in types:
        spike_events = [
            e for e in events
            if e.get("type") == "activity_spike"
            or e.get("detection_method") == "activity_spike"
        ]
        for e in spike_events:
            d = e.get("details", "")
            count_match = re.search(r"has (\d+) events vs mean ([\d.]+)", d)
            if count_match:
                evt_count = int(count_match.group(1))
                mean_val = count_match.group(2)
                detail_clauses.append(f"with {evt_count:,} events against a baseline mean of {mean_val}")
                break

    # Z-score spike: include z-value
    if "z_score_spike" in types:
        z_events = [e for e in events if e.get("type") == "z_score_spike" or e.get("detection_method") == "z_score"]
        for e in z_events:
            z = e.get("z_score")
            if z is not None:
                detail_clauses.append(f"with a z-score of {z:.1f}")
                break
            d = e.get("details", "")
            z_match = re.search(r"z=([\d.]+)", d)
            if z_match:
                detail_clauses.append(f"with a z-score of {z_match.group(1)}")
                break

    # Brute force: include failure ratio
    if "brute_force_attempt" in types or "failed_login_ratio" in types:
        bf_events = [
            e for e in events
            if e.get("type") in ("brute_force_attempt", "failed_login_ratio")
            or e.get("detection_method") in ("brute_force", "failed_login_ratio")
        ]
        for e in bf_events:
            d = e.get("details", "")
            ratio_match = re.search(r"(\d+\.?\d*%) failed", d)
            if ratio_match:
                detail_clauses.append(f"with a {ratio_match.group(1)} failure rate")
                break

    # Off-hours: include time range
    if "off_hours_activity" in types:
        detail_clauses.append("during off-hours (22:00-06:00 UTC)")

    # Impossible travel: include IP count and list
    if "multiple_source_ips" in types:
        it_events = [
            e for e in events
            if e.get("type") == "multiple_source_ips"
            or e.get("detection_method") == "multi_ip"
        ]
        for e in it_events:
            d = e.get("details", "")
            ip_match = re.search(r"(\d+) unique IPs", d)
            if ip_match:
                ip_count = ip_match.group(1)
                ip_list_match = re.search(r"unique IPs: (.+?) \(", d)
                if ip_list_match:
                    detail_clauses.append(f"across {ip_count} distinct IPs ({ip_list_match.group(1)})")
                else:
                    detail_clauses.append(f"across {ip_count} distinct IPs")
                break

    # Suspicious domain: include domain names
    if "suspicious_domain" in types:
        sd_events = [e for e in events if e.get("type") == "suspicious_domain"]
        domains = set()
        for e in sd_events:
            d = e.get("details", "")
            domain_match = re.search(r"domain[:\s]+(\S+)", d, re.IGNORECASE)
            if domain_match:
                domains.add(domain_match.group(1))
        if domains:
            domain_list = sorted(domains)[:3]
            detail_clauses.append(f"contacting {', '.join(domain_list)}")

    # Rapid action sequence: include host and time window
    if "rapid_action_sequence" in types:
        ra_events = [
            e for e in events
            if e.get("type") == "rapid_action_sequence"
            or e.get("detection_method") == "action_sequence"
        ]
        for e in ra_events:
            d = e.get("details", "")
            window_match = re.search(r"within (\w+)", d)
            host = e.get("host", "")
            parts = []
            if window_match:
                parts.append(f"completed within {window_match.group(1)}")
            if host:
                parts.append(f"on host {host}")
            if parts:
                detail_clauses.append(", ".join(parts))
            break

    # Compose the sentence
    if detail_clauses:
        details_text = ", ".join(detail_clauses)
        sentence = f"{opening} {details_text}."
    else:
        type_descriptions = [_TYPE_LABELS.get(t, t) for t in types]
        if len(type_descriptions) == 1:
            type_text = type_descriptions[0]
        elif len(type_descriptions) == 2:
            type_text = f"{type_descriptions[0]} and {type_descriptions[1]}"
        else:
            type_text = ", ".join(type_descriptions[:-1]) + ", and " + type_descriptions[-1]
        sentence = f"{opening} involving {type_text}."

    return sentence


def build_timeline(anomalies: list[dict]) -> str:
    """Build a chronological timeline of anomalous events.

    Sorts events by timestamp, groups consecutive events from the same user
    into phases, and produces a human-readable timeline narrative.

    Args:
        anomalies: List of anomaly dicts (from parse_anomaly_queue or detect_anomalies).

    Returns:
        Timeline narrative string.
    """
    if not anomalies:
        return "No anomalies found."

    # Sort by timestamp
    sorted_anomalies = sorted(anomalies, key=_parse_ts)

    # Build timeline entries
    timeline = []
    for a in sorted_anomalies:
        ts = a.get("timestamp", "unknown")
        severity = a.get("severity", "unknown")
        atype = a.get("type", a.get("detection_method", "unknown"))
        user = a.get("user", "")
        ip = a.get("source_ip", "")
        details = a.get("details", a.get("raw", ""))
        mitre = a.get("mitre_ids", [])

        entry = {
            "timestamp": ts,
            "severity": severity,
            "type": atype,
        }
        if user:
            entry["user"] = user
        if ip:
            entry["source_ip"] = ip
        if details:
            entry["details"] = details
        if mitre:
            entry["mitre_ids"] = mitre
        timeline.append(entry)

    # Build narrative by grouping events into phases by user
    phases = []
    current_user = None
    current_events = []

    for entry in timeline:
        user = entry.get("user", "unknown")

        if current_user is None or user != current_user:
            if current_events:
                phases.append({
                    "user": current_user,
                    "events": current_events,
                    "count": len(current_events),
                })
            current_user = user
            current_events = [entry]
        else:
            current_events.append(entry)

    # Flush last phase
    if current_events:
        phases.append({
            "user": current_user,
            "events": current_events,
            "count": len(current_events),
        })

    # Build narrative prose
    sentences = []
    for i, phase in enumerate(phases):
        sentence = _describe_phase(phase, is_first=(i == 0), prev_phase=phases[i - 1] if i > 0 else {})
        sentences.append(sentence)

    # Add a concluding summary
    total_events = sum(p["count"] for p in phases)
    all_users = sorted(set(p["user"] for p in phases))
    if len(all_users) == 1:
        user_summary = all_users[0]
    elif len(all_users) == 2:
        user_summary = f"{all_users[0]} and {all_users[1]}"
    else:
        user_summary = ", ".join(all_users[:-1]) + ", and " + all_users[-1]

    all_types = sorted(set(
        t for p in phases
        for t in set(
            e.get("type", e.get("detection_method", "unknown"))
            for e in p["events"]
        )
    ))
    type_summary = [_TYPE_LABELS.get(t, t) for t in all_types]
    if len(type_summary) == 1:
        type_sum_text = type_summary[0]
    elif len(type_summary) == 2:
        type_sum_text = f"{type_summary[0]} and {type_summary[1]}"
    else:
        type_sum_text = ", ".join(type_summary[:-1]) + ", and " + type_summary[-1]

    # Collect all MITRE techniques across all phases
    all_mitre = set()
    for p in phases:
        for e in p["events"]:
            for mid in e.get("mitre_ids", []):
                all_mitre.add(mid)
    mitre_summary = ""
    if all_mitre:
        mitre_texts = []
        for mid in sorted(all_mitre):
            name = _MITRE_NAMES.get(mid, "")
            if name:
                mitre_texts.append(f"{mid} ({name})")
            else:
                mitre_texts.append(mid)
        mitre_summary = f" The attack techniques observed include {', '.join(mitre_texts)}."

    # Compute overall duration
    all_timestamps = [
        e.get("timestamp", "")
        for p in phases
        for e in p["events"]
        if e.get("timestamp")
    ]
    if len(all_timestamps) >= 2:
        all_timestamps.sort()
        dur_seconds = 0
        try:
            first_dt = datetime.fromisoformat(all_timestamps[0].replace("Z", "+00:00"))
            last_dt = datetime.fromisoformat(all_timestamps[-1].replace("Z", "+00:00"))
            dur_seconds = int((last_dt - first_dt).total_seconds())
        except (ValueError, TypeError):
            pass  # silent by design: unparseable timestamp in correlation (2026-09 sweep)
        if dur_seconds <= 0:
            overall_dur = "a concentrated period"
        else:
            overall_dur = _fmt_duration(all_timestamps[0], all_timestamps[-1])
    elif len(all_timestamps) == 1:
        overall_dur = "a single point in time"
    else:
        overall_dur = "an unknown period"

    summary = (
        f"In total, {total_events} anomalous events were detected across {len(phases)} phases "
        f"over {overall_dur}, involving {user_summary}. "
        f"The activity consisted of {type_sum_text}.{mitre_summary}"
    )

    narrative = " ".join(sentences) + " " + summary if sentences else "No significant events."
    return narrative


# ---------------------------------------------------------------------------
# Orchestrator — run the full correlation pipeline
# ---------------------------------------------------------------------------

def run_correlation(
    anomalies: list[dict],
    graph_context_text: str = "",
    attack_mapping_text: str = "",
    entity_profiles=None,
) -> tuple[str, str]:
    """Run the full threat correlation pipeline.

    1. Parse graph context and attack mapping
    2. Correlate anomalies by entity and time window
    3. Assess findings with severity scores and ATT&CK enrichment
    4. Format findings and build timeline

    Args:
        anomalies: List of anomaly dicts (from detect_anomalies or parse_anomaly_queue).
        graph_context_text: Raw text from the graph_context block.
        attack_mapping_text: Raw text from the attack_mapping block.

    Returns:
        Tuple of (findings_text, timeline_text, findings, correlations, attack_lookup).
        The first two are formatted strings; the rest are structured data for
        the explainability layer.
    """
    if not anomalies:
        return "Confirmed threats: none", "No anomalies found.", [], [], {}

    # Parse graph context
    entity_communities, entity_chains, _, _ = parse_graph_context(graph_context_text)

    # Parse attack mapping
    attack_lookup = parse_attack_mapping(attack_mapping_text)

    # Correlate ALL anomalies (correlation needs full dataset for cross-type patterns)
    correlations = correlate_anomalies(anomalies, entity_communities, entity_chains)

    # Assess and enrich
    findings = assess_findings(correlations, attack_lookup)

    # Format
    findings_text = format_findings(
        findings, entity_profiles=entity_profiles, anomalies=anomalies
    )

    # Build timeline from a severity-stratified subset to keep output small
    from nabla.utils import SEVERITY_ORDER
    if len(anomalies) > _MAX_ANOMALIES_FOR_TIMELINE:
        # Stratified sampling: keep top anomalies per type, then fill by severity
        by_type: dict[str, list[dict]] = defaultdict(list)
        for a in anomalies:
            atype = a.get("type", a.get("detection_method", "unknown"))
            by_type[atype].append(a)
        per_type = max(1, _MAX_ANOMALIES_FOR_TIMELINE // max(len(by_type), 1))
        selected = []
        for atype, type_anomalies in by_type.items():
            sorted_type = sorted(type_anomalies, key=lambda a: SEVERITY_ORDER.get(a.get("severity", "medium"), 2))
            selected.extend(sorted_type[:per_type])
        # Fill remaining slots by severity
        remaining = _MAX_ANOMALIES_FOR_TIMELINE - len(selected)
        if remaining > 0:
            selected_ids = {id(a) for a in selected}
            leftovers = sorted(
                [a for a in anomalies if id(a) not in selected_ids],
                key=lambda a: SEVERITY_ORDER.get(a.get("severity", "medium"), 2),
            )
            selected.extend(leftovers[:remaining])
        timeline_anomalies = selected
    else:
        timeline_anomalies = anomalies

    timeline_text = build_timeline(timeline_anomalies)

    logger.info(
        "Correlation: %d anomalies → %d correlations → %d findings",
        len(anomalies), len(correlations), len(findings),
    )

    # Truncate combined output to fit within the supervisor's context window
    combined = findings_text + "\n\n--- TIMELINE ---\n" + timeline_text
    if len(combined) > _MAX_OUTPUT_CHARS:
        # Keep findings in full, truncate timeline
        findings_budget = len(findings_text)
        timeline_budget = _MAX_OUTPUT_CHARS - findings_budget - len("\n\n--- TIMELINE ---\n") - len("\n[...truncated]")
        if timeline_budget < 200:
            # Findings alone are too large — truncate findings too
            findings_text = findings_text[:_MAX_OUTPUT_CHARS // 2] + "\n[...truncated]"
            timeline_text = timeline_text[:_MAX_OUTPUT_CHARS // 2 - 30] + "\n[...truncated]"
        else:
            timeline_text = timeline_text[:timeline_budget] + "\n[...truncated]"
        logger.info(
            "Correlation output truncated: findings=%d chars, timeline=%d chars (limit=%d)",
            len(findings_text), len(timeline_text), _MAX_OUTPUT_CHARS,
        )

    return findings_text, timeline_text, findings, correlations, attack_lookup
