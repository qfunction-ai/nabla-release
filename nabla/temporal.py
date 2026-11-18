"""Temporal Correlation Engine (TCE).

Implements the SHIELD Temporal Correlation Engine:
1. Build temporal event chains from anomalies linked by shared entities
   (IP, user, host) within configurable time windows
2. Map chains to MITRE ATT&CK kill-chain phases
3. Score chains by phase coverage, temporal tightness, and entity overlap
4. Flag high-scoring chains as detection method 14

Pure Python — no external dependencies beyond the standard library.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from nabla.log import get_logger

logger = get_logger("temporal")


# ---------------------------------------------------------------------------
# Kill-Chain Phase Definitions
# ---------------------------------------------------------------------------

# MITRE ATT&CK kill-chain phases (simplified from full CKC)
PHASES = [
    "recon",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "lateral_movement",
    "exfiltration",
    "command_and_control",
]

# Anomaly type → kill-chain phase(s) mapping
# Each anomaly type maps to one or more phases it typically represents
ANOMALY_TO_PHASES: dict[str, list[str]] = {
    "pre_flagged": ["initial_access"],
    "z_score_spike": ["recon", "initial_access"],
    "brute_force_attempt": ["credential_access"],
    "failed_login_ratio": ["credential_access"],
    "off_hours_activity": ["initial_access"],
    "multiple_source_ips": ["initial_access", "lateral_movement"],
    "multi_ip": ["initial_access", "lateral_movement"],
    "activity_spike": ["execution"],
    "lolbin_abuse": ["execution", "defense_evasion"],
    "suspicious_parent_child": ["execution", "defense_evasion"],
    "parent_child": ["execution", "defense_evasion"],
    "critical_host_escalation": ["privilege_escalation"],
    "unusual_process": ["execution", "persistence"],
    "rapid_action_sequence": ["execution", "defense_evasion"],
    "action_sequence": ["execution", "defense_evasion"],
    "gcn_lof_anomaly": ["execution"],  # Generic — context-dependent
    "provenance_community": ["execution"],  # Generic — context-dependent
    "suspicious_domain": ["command_and_control"],
    "privilege_escalation": ["privilege_escalation"],
    "renamed_attack_tool": ["credential_access", "privilege_escalation"],
    "renamed_tool": ["credential_access", "privilege_escalation"],
}

# Log type + action → phase mapping (for raw entries without anomaly type)
LOG_TYPE_ACTION_TO_PHASE: dict[str, dict[str, list[str]]] = {
    "auth": {
        "login_failure": ["credential_access"],
        "login_success": ["initial_access"],
        "privilege_escalation": ["privilege_escalation"],
        "logoff": [],
    },
    "network": {
        "connect": ["command_and_control", "exfiltration"],
        "listen": ["command_and_control"],
        "accept": ["command_and_control"],
    },
    "dns": {
        "query": ["command_and_control"],
        "resolve": ["command_and_control"],
    },
    "endpoint": {
        "create": ["persistence"],
        "execute": ["execution"],
        "delete": ["defense_evasion"],
        "modify": ["persistence"],
        "read": ["credential_access"],
        "write": ["persistence"],
    },
}


def map_anomaly_to_phases(anomaly: dict[str, Any]) -> list[str]:
    """Map an anomaly to its kill-chain phase(s).

    Args:
        anomaly: Anomaly dict with 'type' and optional 'detection_method' keys.

    Returns:
        List of kill-chain phase strings.
    """
    # Try detection_method first (more specific)
    method = anomaly.get("detection_method", "")
    if method and method in ANOMALY_TO_PHASES:
        return ANOMALY_TO_PHASES[method]

    # Fall back to anomaly type
    atype = anomaly.get("type", "")
    if atype and atype in ANOMALY_TO_PHASES:
        return ANOMALY_TO_PHASES[atype]

    # Try log type + action from raw entry context
    log_type = anomaly.get("log_type", "")
    action = anomaly.get("action", "")
    if log_type in LOG_TYPE_ACTION_TO_PHASE:
        action_phases = LOG_TYPE_ACTION_TO_PHASE[log_type].get(action, [])
        if action_phases:
            return action_phases

    # Unknown — default to execution (most generic)
    return ["execution"]


# ---------------------------------------------------------------------------
# Temporal Chain
# ---------------------------------------------------------------------------

@dataclass
class TemporalChain:
    """A sequence of temporally-linked anomalies forming an attack chain.

    Attributes:
        chain_id: Unique identifier for this chain.
        events: Ordered list of anomaly dicts in the chain.
        entities: Shared entities by type (ip, user, host).
        phases: Kill-chain phases present in the chain.
        start_time: Timestamp of the earliest event.
        end_time: Timestamp of the latest event.
        duration_seconds: Time span of the chain in seconds.
        phase_coverage: Fraction of kill-chain phases covered (0-1).
        tightness: Inverse of normalized inter-event gap (0-1).
        score: Combined chain score.
    """
    chain_id: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)
    entities: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    phases: list[str] = field(default_factory=list)
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_seconds: float = 0.0
    phase_coverage: float = 0.0
    tightness: float = 0.0
    score: float = 0.0


def _parse_timestamp(ts_str: str) -> datetime | None:
    """Parse an ISO timestamp string to a timezone-aware datetime object.

    Delegates to the shared parse_iso_timestamp utility.

    Args:
        ts_str: ISO format timestamp string.

    Returns:
        Parsed timezone-aware datetime, or None if invalid.
    """
    from nabla.utils import parse_iso_timestamp
    return parse_iso_timestamp(ts_str)


def _extract_entities(anomaly: dict[str, Any]) -> dict[str, set[str]]:
    """Extract shared entities from an anomaly dict.

    Args:
        anomaly: Anomaly dict with optional source_ip, user, host keys.

    Returns:
        Dict mapping entity type to set of entity values.
    """
    entities: dict[str, set[str]] = defaultdict(set)
    ip = anomaly.get("source_ip", "")
    if ip:
        # Handle comma-separated IPs (e.g., from multi_ip anomalies)
        for part in ip.split(","):
            part = part.strip()
            if part:
                entities["ip"].add(part)
    user = anomaly.get("user", "")
    if user and user != "unknown":
        entities["user"].add(user)
    host = anomaly.get("host", "")
    if host:
        entities["host"].add(host)
    return entities


def _entities_overlap(e1: dict[str, set[str]], e2: dict[str, set[str]]) -> bool:
    """Check if two entity sets share at least one entity value.

    Args:
        e1: First entity dict.
        e2: Second entity dict.

    Returns:
        True if any entity value is shared.
    """
    for etype in set(e1.keys()) | set(e2.keys()):
        if e1.get(etype, set()) & e2.get(etype, set()):
            return True
    return False


# ---------------------------------------------------------------------------
# Union-Find for Chain Merging
# ---------------------------------------------------------------------------

class _UnionFind:
    """Union-Find data structure for merging overlapping anomaly pairs into chains.

    Attributes:
        parent: Mapping from element index to parent index.
        rank: Rank for union by rank optimization.
    """

    def __init__(self, n: int):
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        """Find the root representative of element x with path compression.

        Args:
            x: Element index.

        Returns:
            Root representative index.
        """
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]  # Path compression
            x = self.parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        """Merge the sets containing x and y.

        Args:
            x: First element index.
            y: Second element index.
        """
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]:
            self.rank[rx] += 1


# ---------------------------------------------------------------------------
# Chain Builder
# ---------------------------------------------------------------------------

def build_temporal_chains(
    anomalies: list[dict[str, Any]],
    time_window_minutes: float = 30.0,
) -> list[TemporalChain]:
    """Build temporal event chains from anomalies linked by shared entities.

    Two anomalies are linked if:
    1. They share at least one entity (IP, user, or host), AND
    2. Their timestamps are within time_window_minutes of each other

    Union-Find merges overlapping pairs into maximal chains.

    Args:
        anomalies: List of anomaly dicts (must have timestamp, source_ip, user, host).
        time_window_minutes: Maximum time gap between linked anomalies.

    Returns:
        List of TemporalChain objects, sorted by start_time.
    """
    if len(anomalies) < 2:
        return []

    # Parse timestamps and extract entities
    parsed: list[tuple[datetime | None, dict[str, set[str]], dict[str, Any]]] = []
    for a in anomalies:
        ts = _parse_timestamp(a.get("timestamp", ""))
        entities = _extract_entities(a)
        parsed.append((ts, entities, a))

    # Filter out anomalies with no entities at all
    parsed = [(ts, ent, a) for ts, ent, a in parsed if any(ent.values())]
    if len(parsed) < 2:
        return []

    # Sort by timestamp (None timestamps go to end)
    parsed.sort(key=lambda x: x[0] if x[0] is not None else datetime.max.replace(tzinfo=timezone.utc))

    n = len(parsed)
    uf = _UnionFind(n)

    # Link anomalies that share entities and are within the time window
    window_delta = time_window_minutes * 60  # Convert to seconds
    for i in range(n):
        ts_i, ent_i, _ = parsed[i]
        if ts_i is None:
            continue
        for j in range(i + 1, n):
            ts_j, ent_j, _ = parsed[j]
            if ts_j is None:
                continue
            # Time gap check
            gap = abs((ts_j - ts_i).total_seconds())
            if gap > window_delta:
                # Since sorted, if gap > window for this j, all later j's will also exceed
                # (unless there are None timestamps, but we skip those)
                break
            # Entity overlap check
            if _entities_overlap(ent_i, ent_j):
                uf.union(i, j)

    # Group by connected components
    components: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        root = uf.find(i)
        components[root].append(i)

    # Build TemporalChain objects (only chains with 2+ events)
    chains = []
    chain_id = 0
    for root, indices in components.items():
        if len(indices) < 2:
            continue

        chain_events = [parsed[i][2] for i in indices]
        chain_timestamps = [parsed[i][0] for i in indices if parsed[i][0] is not None]

        # Merge entities across all events in the chain
        merged_entities: dict[str, set[str]] = defaultdict(set)
        for i in indices:
            for etype, evals in parsed[i][1].items():
                merged_entities[etype].update(evals)

        # Map phases
        phase_set: set[str] = set()
        for a in chain_events:
            for phase in map_anomaly_to_phases(a):
                phase_set.add(phase)
        chain_phases = [p for p in PHASES if p in phase_set]

        # Compute temporal properties
        start_time = min(chain_timestamps) if chain_timestamps else None
        end_time = max(chain_timestamps) if chain_timestamps else None
        duration = (end_time - start_time).total_seconds() if start_time and end_time else 0.0

        # Phase coverage
        phase_coverage = len(chain_phases) / len(PHASES) if PHASES else 0.0

        # Tightness: inverse of normalized inter-event gap
        if len(chain_timestamps) >= 2 and duration > 0:
            sorted_ts = sorted(chain_timestamps)
            gaps = [(sorted_ts[i + 1] - sorted_ts[i]).total_seconds()
                    for i in range(len(sorted_ts) - 1)]
            avg_gap = sum(gaps) / len(gaps)
            tightness = 1.0 / (1.0 + avg_gap / 60.0)  # Normalize by minute
        else:
            tightness = 1.0  # Single point or no timestamps

        chain = TemporalChain(
            chain_id=chain_id,
            events=chain_events,
            entities=dict(merged_entities),
            phases=chain_phases,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            phase_coverage=phase_coverage,
            tightness=tightness,
        )
        chains.append(chain)
        chain_id += 1

    # Sort by start_time
    chains.sort(key=lambda c: c.start_time if c.start_time else datetime.max.replace(tzinfo=timezone.utc))

    return chains


# ---------------------------------------------------------------------------
# Chain Scoring
# ---------------------------------------------------------------------------

def score_chain(
    chain: TemporalChain,
    _min_chain_length: int = 3,
    _min_phase_coverage: float = 0.2,
) -> TemporalChain:
    """Score a temporal chain and determine if it should be flagged.

    Score = 0.4 * phase_coverage + 0.3 * tightness + 0.3 * entity_overlap

    entity_overlap = fraction of chain events that share at least one entity
    with at least one other event in the chain.

    Args:
        chain: TemporalChain to score.
        _min_chain_length: (Unused in scoring — used by should_flag_chain)
        _min_phase_coverage: (Unused in scoring — used by should_flag_chain)

    Returns:
        The same chain with score, entity_overlap, and flagging updated.
    """
    # Compute entity overlap
    n_events = len(chain.events)
    if n_events < 2:
        chain.score = 0.0
        return chain

    # Count events that share at least one entity with another event
    event_entities = [_extract_entities(e) for e in chain.events]
    overlapping = 0
    for i in range(n_events):
        for j in range(n_events):
            if i != j and _entities_overlap(event_entities[i], event_entities[j]):
                overlapping += 1
                break
    entity_overlap = overlapping / n_events

    # Combined score
    chain.score = (
        0.4 * chain.phase_coverage
        + 0.3 * chain.tightness
        + 0.3 * entity_overlap
    )

    # Store entity_overlap for external use
    chain.entity_overlap = entity_overlap  # type: ignore[attr-defined]

    return chain


def should_flag_chain(
    chain: TemporalChain,
    min_chain_length: int = 3,
    min_phase_coverage: float = 0.2,
) -> bool:
    """Determine if a temporal chain should be flagged as an anomaly.

    A chain is flagged if:
    - It has at least min_chain_length events, AND
    - Its phase coverage is at least min_phase_coverage, OR
    - It has 3+ kill-chain phases (strong indicator of multi-stage attack)

    Args:
        chain: Scored TemporalChain.
        min_chain_length: Minimum events to form a flaggable chain.
        min_phase_coverage: Minimum phase coverage to flag.

    Returns:
        True if the chain should be flagged.
    """
    # A14: chain length counts DISTINCT events (Phase 2 IDs dedup the same
    # underlying event re-detected by multiple methods), and single-source
    # chains need method diversity — three detectors firing on one event is
    # one signal, not a campaign
    distinct_ids = {e.get("anomaly_id") or id(e) for e in chain.events}
    if len(distinct_ids) < min_chain_length:
        return False
    methods = {e.get("detection_method", e.get("type", "")) for e in chain.events}
    if len(distinct_ids) == 1 and len(methods) < 2:
        return False
    if len(chain.events) < min_chain_length:
        return False

    # Flag if phase coverage meets threshold
    if chain.phase_coverage >= min_phase_coverage:
        return True

    # Flag if 3+ distinct phases (strong multi-stage indicator)
    if len(chain.phases) >= 3:
        return True

    return False


# ---------------------------------------------------------------------------
# Top-level Detection Function
# ---------------------------------------------------------------------------

def detect_temporal_chains(
    entries: list[dict[str, Any]],
    existing_anomalies: list[dict[str, Any]],
    thresholds: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    """Run full temporal correlation analysis pipeline.

    1. Build temporal chains from existing anomalies
    2. Map chains to kill-chain phases
    3. Score chains by phase coverage, tightness, and entity overlap
    4. Flag high-scoring chains

    Args:
        entries: List of log entry dicts (used for context, not directly).
        existing_anomalies: Anomalies from detect_anomalies(), GCN-LOF, and provenance.
        thresholds: Optional threshold overrides.

    Returns:
        List of anomaly dicts with detection_method="temporal_chain".
    """
    result = detect_temporal_chains_with_context(entries, existing_anomalies, thresholds)
    return result[0]


def detect_temporal_chains_with_context(
    _entries: list[dict[str, Any]],
    existing_anomalies: list[dict[str, Any]],
    thresholds: dict[str, float] | None = None,
) -> tuple[list[dict[str, Any]], list["TemporalChain"]]:
    """Run temporal analysis and return chain objects for context formatting.

    Same as detect_temporal_chains but also returns the TemporalChain
    objects so the pipeline can format temporal context for the LLM analyzer.

    Args:
        _entries: (Unused — temporal analysis operates on existing anomalies)
        existing_anomalies: Anomalies from detect_anomalies(), GCN-LOF, and provenance.
        thresholds: Optional threshold overrides.

    Returns:
        Tuple of (anomaly_list, chains). Chains is empty if analysis was skipped.
    """
    if thresholds is None:
        thresholds = {}

    time_window = thresholds.get("temporal_chain_window_minutes", 30.0)
    min_chain_length = int(thresholds.get("temporal_min_chain_length", 3))
    min_phase_coverage = 0.2  # Fixed threshold for phase coverage

    if len(existing_anomalies) < 2:
        logger.debug("Too few anomalies for temporal analysis (%d)", len(existing_anomalies))
        return [], []

    # Step 1: Build chains
    chains = build_temporal_chains(existing_anomalies, time_window_minutes=time_window)
    logger.debug("Built %d temporal chains from %d anomalies", len(chains), len(existing_anomalies))

    if not chains:
        return [], []

    # Step 2-3: Score and flag
    anomalies = []
    for chain in chains:
        score_chain(chain)
        if not should_flag_chain(chain, min_chain_length=min_chain_length, min_phase_coverage=min_phase_coverage):
            continue

        # Build anomaly output
        entity_summary: dict[str, list[str]] = {}
        for etype, evals in chain.entities.items():
            entity_summary[etype] = sorted(evals)

        # Build event summary for details
        event_types = [a.get("type", a.get("detection_method", "unknown")) for a in chain.events]
        event_summary = ", ".join(event_types[:5])
        if len(event_types) > 5:
            event_summary += f", +{len(event_types) - 5} more"

        # Build phase narrative
        phase_narrative = " → ".join(chain.phases) if chain.phases else "unknown"

        duration_str = ""
        if chain.duration_seconds > 0:
            if chain.duration_seconds < 60:
                duration_str = f"{chain.duration_seconds:.0f}s"
            elif chain.duration_seconds < 3600:
                duration_str = f"{chain.duration_seconds / 60:.0f}min"
            else:
                duration_str = f"{chain.duration_seconds / 3600:.1f}h"

        details = (
            f"Chain {chain.chain_id}: {len(chain.events)} events, "
            f"{len(chain.phases)} phases ({phase_narrative}), "
            f"score={chain.score:.3f}, "
            f"phase_coverage={chain.phase_coverage:.2f}, "
            f"tightness={chain.tightness:.2f}"
        )
        if duration_str:
            details += f", duration={duration_str}"

        anomaly = {
            "type": "temporal_chain",
            "severity": "high" if chain.phase_coverage >= 0.4 else "medium",
            "chain_id": chain.chain_id,
            "chain_length": len(chain.events),
            "phases": chain.phases,
            "phase_coverage": round(chain.phase_coverage, 3),
            "tightness": round(chain.tightness, 3),
            "score": round(chain.score, 3),
            "entities": entity_summary,
            "duration_seconds": round(chain.duration_seconds, 1),
            "detection_method": "temporal_chain",
            "details": details,
        }

        # Include user/IP from chain entities if available
        if chain.entities.get("user"):
            anomaly["user"] = sorted(chain.entities["user"])[0]
        if chain.entities.get("ip"):
            anomaly["source_ip"] = sorted(chain.entities["ip"])[0]
        if chain.start_time:
            anomaly["timestamp"] = chain.start_time.isoformat()

        anomalies.append(anomaly)

    logger.info(
        "Temporal: %d chains flagged out of %d total",
        len(anomalies), len(chains),
    )

    return anomalies, chains


# ---------------------------------------------------------------------------
# Temporal Context Formatting (for LLM analyzer)
# ---------------------------------------------------------------------------

def format_temporal_summary(chains: list["TemporalChain"]) -> str:
    """Format temporal chain context for the graph_context shared block.

    Produces human-readable chain summaries plus a JSON line for
    structured parsing by threat tools.

    Args:
        chains: List of TemporalChain objects (from build_temporal_chains).

    Returns:
        Formatted text for the graph_context block (temporal section).
    """
    if not chains:
        return "Temporal chains: none detected"

    flagged = [c for c in chains if c.phase_coverage >= 0.2 or len(c.phases) >= 3]
    lines = [
        f"Temporal chains: {len(flagged)} flagged out of {len(chains)} total"
    ]

    json_chains = []

    for chain in chains:
        # Only include flagged chains in detail
        is_flagged = chain.phase_coverage >= 0.2 or len(chain.phases) >= 3
        if not is_flagged:
            continue

        phase_narrative = " → ".join(chain.phases) if chain.phases else "unknown"

        duration_str = ""
        if chain.duration_seconds > 0:
            if chain.duration_seconds < 60:
                duration_str = f"{chain.duration_seconds:.0f}s"
            elif chain.duration_seconds < 3600:
                duration_str = f"{chain.duration_seconds / 60:.0f}min"
            else:
                duration_str = f"{chain.duration_seconds / 3600:.1f}h"

        entity_summary: dict[str, list[str]] = {}
        for etype, evals in chain.entities.items():
            entity_summary[etype] = sorted(evals)

        lines.append(
            f"Chain {chain.chain_id}: {len(chain.events)} events, "
            f"{len(chain.phases)} phases ({phase_narrative}), "
            f"score={chain.score:.3f}"
        )
        if duration_str:
            lines[-1] += f", duration={duration_str}"

        # Entity list
        entity_parts = []
        for etype, names in sorted(entity_summary.items()):
            entity_parts.append(f"{etype}: {', '.join(names[:3])}")
        if entity_parts:
            lines.append(f"  Entities: {'; '.join(entity_parts)}")

        json_chains.append({
            "chain_id": chain.chain_id,
            "events": len(chain.events),
            "phases": chain.phases,
            "phase_coverage": round(chain.phase_coverage, 3),
            "score": round(chain.score, 3),
            "entities": entity_summary,
            "duration_seconds": round(chain.duration_seconds, 1),
        })

    # Append JSON line
    lines.append(f"JSON:{json.dumps({'chains': json_chains}, separators=(',', ':'))}")

    return "\n".join(lines)
