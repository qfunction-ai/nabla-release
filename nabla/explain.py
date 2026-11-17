"""Explainability layer for Nabla findings.

Provides three levels of explanation for each finding:
1. Evidence traces — what specific anomalies, rules, and thresholds produced it
2. Rule counterfactuals — what minimal changes would alter the finding
3. Graph counterfactuals — which provenance graph edges are critical

Adapted from PROVX (counterfactual explanations for provenance graphs) and
ProvExplainer (structural feature explanations), but applied to Nabla's
deterministic detection pipeline instead of GNN black-box models.

The key insight: Nabla's detection is deterministic, so explanations are
exact (not approximate). We can re-run correlation with modified inputs
to compute precise counterfactuals.
"""

import re
from collections import defaultdict

from nabla.log import get_logger

logger = get_logger("explain")

# Maximum evidence entries per finding (to stay within context window budget)
_MAX_EVIDENCE_PER_FINDING = 5

# Maximum counterfactual entries per finding
_MAX_COUNTERFACTUALS_PER_FINDING = 4

# Maximum graph counterfactual edges to report
_MAX_GRAPH_CF_EDGES = 3


# ---------------------------------------------------------------------------
# Evidence extraction — parse structured evidence from anomaly dicts
# ---------------------------------------------------------------------------

# Threshold fields that appear in anomaly details strings
_THRESHOLD_PATTERNS = [
    # "threshold=2.0" or "threshold=3" — generic
    re.compile(r'threshold=([\d.]+)', re.IGNORECASE),
    # "z=3.2, mean=5.1, std=2.0, threshold=2.0"
    re.compile(r'z=([\d.]+)', re.IGNORECASE),
    # "5 events during off-hours (22:00-06:00 UTC, threshold=3)"
    re.compile(r'(\d+)\s+events\s+during\s+off-hours', re.IGNORECASE),
    # "3 unique IPs" or "5 distinct IPs"
    re.compile(r'(\d+)\s+(?:unique|distinct)\s+IPs?', re.IGNORECASE),
    # "75% failure rate" or "50%, threshold=0.5"
    re.compile(r'([\d.]+)%\s+failure\s+rate', re.IGNORECASE),
    # "score=0.850, lof=2.31, recon_err=0.0012"
    re.compile(r'score=([\d.]+)', re.IGNORECASE),
    # "S+=5.2 (h=4.0)" — CUSUM
    re.compile(r'S\+=([\d.]+)\s+\(h=([\d.]+)\)', re.IGNORECASE),
    # "ewma=3.1, threshold=5.2" — EWMA
    re.compile(r'ewma=([\d.]+),\s*threshold=([\d.]+)', re.IGNORECASE),
    # "Community 2: 8 nodes, anomaly_density=0.40"
    re.compile(r'anomaly_density=([\d.]+)', re.IGNORECASE),
    # "phase_coverage=0.500, tightness=0.800"
    re.compile(r'phase_coverage=([\d.]+)', re.IGNORECASE),
]


def _extract_evidence_from_anomaly(anomaly: dict) -> dict:
    """Extract structured evidence from a single anomaly dict.

    Uses the existing fields (detection_method, details, severity, etc.)
    to build an evidence record without requiring any schema changes to
    the anomaly dicts themselves.

    Args:
        anomaly: Anomaly dict from detect_anomalies or GCN-LOF/provenance/temporal.

    Returns:
        Evidence dict with keys: rule, threshold, actual, margin, summary.
    """
    method = anomaly.get("detection_method", anomaly.get("type", "unknown"))
    details = anomaly.get("details", "")
    severity = anomaly.get("severity", "unknown")

    evidence = {
        "rule": method,
        "severity": severity,
        "threshold": None,
        "actual": None,
        "margin": None,
        "summary": "",
    }

    # --- Method-specific evidence extraction ---

    if method == "z_score":
        z = anomaly.get("z_score")
        if z is not None:
            evidence["actual"] = f"z={z:.1f}"
            # Extract threshold from details
            m = re.search(r'threshold=([\d.]+)', details)
            if m:
                thresh = float(m.group(1))
                evidence["threshold"] = f"z>{thresh}"
                evidence["margin"] = f"+{z - thresh:.1f}σ"
            evidence["summary"] = f"z-score spike (z={z:.1f})"

    elif method in ("failed_login_ratio", "brute_force"):
        m = re.search(r'([\d.]+)%.*threshold=([\d.]+)', details)
        if m:
            actual_pct = float(m.group(1))
            thresh = float(m.group(2)) * 100
            evidence["actual"] = f"{actual_pct:.0f}%"
            evidence["threshold"] = f">{thresh:.0f}%"
            evidence["margin"] = f"+{actual_pct - thresh:.0f}pp"
        evidence["summary"] = "brute force login ratio"

    elif method == "off_hours":
        m = re.search(r'(\d+)\s+events.*threshold=(\d+)', details)
        if m:
            count = int(m.group(1))
            thresh = int(m.group(2))
            evidence["actual"] = f"{count} events"
            evidence["threshold"] = f"≥{thresh}"
            evidence["margin"] = f"+{count - thresh}"
        evidence["summary"] = "off-hours activity"

    elif method == "multi_ip":
        m = re.search(r'(\d+)\s+unique\s+IPs.*threshold=(\d+)', details)
        if m:
            count = int(m.group(1))
            thresh = int(m.group(2))
            evidence["actual"] = f"{count} IPs"
            evidence["threshold"] = f"≥{thresh}"
            evidence["margin"] = f"+{count - thresh}"
        evidence["summary"] = "impossible travel (multi-IP)"

    elif method == "activity_spike":
        m = re.search(r'(\d+)\s+events\s+vs\s+mean\s+([\d.]+).*threshold=([\d.]+)x', details)
        if m:
            count = int(m.group(1))
            mean = float(m.group(2))
            mult = float(m.group(3))
            actual_mult = count / mean if mean > 0 else 0
            evidence["actual"] = f"{actual_mult:.1f}x mean"
            evidence["threshold"] = f">{mult}x"
            evidence["margin"] = f"+{actual_mult - mult:.1f}x"
        evidence["summary"] = "activity spike"

    elif method == "lolbin":
        # Extract binary name from details
        m = re.search(r'LOLBIN\s+(\S+)', details)
        binary = m.group(1) if m else "unknown"
        evidence["actual"] = binary
        evidence["summary"] = f"LOLBIN abuse: {binary}"

    elif method == "parent_child":
        m = re.search(r'Suspicious parent-child:\s*(.+)', details)
        pair = m.group(1).strip() if m else ""
        evidence["actual"] = pair
        evidence["summary"] = f"suspicious parent-child: {pair}"

    elif method == "attack_script":
        tool_name = anomaly.get("tool_display_name") or anomaly.get("tool_name", "")
        evidence["actual"] = tool_name
        evidence["summary"] = f"known attack tool: {tool_name}" if tool_name else "known attack script"

    elif method == "renamed_tool":
        tool_name = anomaly.get("tool_name", "")
        m = re.search(r'\(process:\s*(\S+)\)', details)
        proc = m.group(1) if m else ""
        evidence["actual"] = f"{tool_name} (as {proc})" if tool_name and proc else tool_name or proc
        evidence["summary"] = f"renamed attack tool: {tool_name}" if tool_name else "renamed attack tool"

    elif method == "enumeration_behavior":
        m = re.search(r'Enumeration behavior:\s*(.+)', details)
        desc = m.group(1).strip() if m else details[:80]
        evidence["actual"] = desc
        evidence["summary"] = f"enumeration: {desc}"

    elif method == "action_sequence":
        m = re.search(r'within\s+([\d.]+)\s*min.*window=(\d+)min', details)
        if m:
            actual_min = float(m.group(1))
            window = int(m.group(2))
            evidence["actual"] = f"{actual_min:.0f}min"
            evidence["threshold"] = f"≤{window}min"
            evidence["margin"] = f"{window - actual_min:.0f}min under"
        evidence["summary"] = "rapid action sequence"

    elif method == "suspicious_path":
        m = re.search(r'patterns:\s*(.+)', details)
        patterns = m.group(1).strip() if m else ""
        evidence["actual"] = patterns
        evidence["summary"] = f"suspicious path: {patterns}" if patterns else "suspicious path"

    elif method == "integrity_anomaly":
        m = re.search(r'parent=(\S+)', details)
        parent = m.group(1) if m else ""
        evidence["actual"] = f"parent={parent}" if parent else ""
        evidence["summary"] = f"integrity anomaly: SYSTEM from {parent}" if parent else "integrity anomaly"

    elif method == "critical_host_escalation":
        m = re.search(r'host\s+(\S+)', details)
        host = m.group(1) if m else ""
        evidence["actual"] = details[:80]
        evidence["summary"] = f"privilege escalation on {host}" if host else "privilege escalation"

    elif method == "unusual_process":
        m = re.search(r'Process\s+(\S+)\s+first seen', details)
        proc = m.group(1) if m else ""
        evidence["actual"] = proc
        evidence["summary"] = f"unusual process: {proc}" if proc else "unusual process"

    elif method == "registry_abuse":
        m = re.search(r'Registry modification by\s+(\S+)', details)
        proc = m.group(1) if m else ""
        evidence["actual"] = proc
        evidence["summary"] = f"registry abuse: {proc}" if proc else "registry abuse"

    elif method == "network_anomaly":
        m = re.search(r'Network connection from\s+(\S+)\s+to\s+(\S+)', details)
        if m:
            evidence["actual"] = f"{m.group(1)} → {m.group(2)}"
        evidence["summary"] = "network anomaly from unusual process"

    elif method == "gcn_lof":
        score = anomaly.get("gcn_lof_score")
        lof = anomaly.get("lof_score")
        if score is not None:
            evidence["actual"] = f"score={score:.3f}"
        if lof is not None:
            evidence["threshold"] = f"lof>{0.5:.1f}"  # Approximate
        evidence["summary"] = f"GCN-LOF anomaly (score={score:.3f})" if score else "GCN-LOF anomaly"

    elif method == "provenance_community":
        density = anomaly.get("anomaly_density")
        comm_id = anomaly.get("community_id", "?")
        if density is not None:
            evidence["actual"] = f"density={density:.2f}"
            evidence["threshold"] = ">0.30"
            evidence["margin"] = f"+{density - 0.3:.2f}" if density > 0.3 else ""
        evidence["summary"] = (
            f"provenance community {comm_id} (density={density:.2f})"
            if density else f"provenance community {comm_id}"
        )

    elif method == "temporal_chain":
        coverage = anomaly.get("phase_coverage")
        chain_id = anomaly.get("chain_id", "?")
        phases = anomaly.get("phases", [])
        if coverage is not None:
            evidence["actual"] = f"coverage={coverage:.1%}"
            evidence["threshold"] = ">30%"
            evidence["margin"] = f"+{coverage - 0.3:.0%}" if coverage > 0.3 else ""
        phase_str = " → ".join(phases[:3]) if phases else "?"
        evidence["summary"] = f"temporal chain {chain_id}: {phase_str}"

    elif method == "ewma":
        m = re.search(r'ewma=([\d.]+),\s*threshold=([\d.]+)', details)
        if m:
            ewma = float(m.group(1))
            thresh = float(m.group(2))
            evidence["actual"] = f"ewma={ewma:.1f}"
            evidence["threshold"] = f">{thresh:.1f}"
            evidence["margin"] = f"+{ewma - thresh:.1f}"
        evidence["summary"] = "EWMA drift"

    elif method == "cusum":
        m = re.search(r'S\+=([\d.]+)\s+\(h=([\d.]+)\)', details)
        if m:
            s_plus = float(m.group(1))
            h = float(m.group(2))
            evidence["actual"] = f"S+={s_plus:.1f}"
            evidence["threshold"] = f"h={h:.1f}"
            evidence["margin"] = f"+{s_plus - h:.1f}"
        evidence["summary"] = "CUSUM sustained shift"

    elif method == "pre_flagged":
        evidence["actual"] = details[:80] if details else "pre-flagged by source"
        evidence["summary"] = "pre-flagged anomaly from log source"

    else:
        # Generic fallback
        evidence["actual"] = details[:80] if details else ""
        evidence["summary"] = f"{method}: {details[:60]}" if details else method

    return evidence


def format_evidence(anomalies: list[dict], max_entries: int = _MAX_EVIDENCE_PER_FINDING) -> str:
    """Format evidence traces for a list of anomalies.

    Groups anomalies by detection_method, showing the most impactful first.

    Args:
        anomalies: List of anomaly dicts contributing to a finding.
        max_entries: Maximum number of evidence entries to show.

    Returns:
        Formatted evidence string for the threat_findings block.
    """
    if not anomalies:
        return ""

    # Group by detection method
    by_method: dict[str, list[dict]] = defaultdict(list)
    for a in anomalies:
        method = a.get("detection_method", a.get("type", "unknown"))
        by_method[method].append(a)

    # Sort methods by severity (critical first), then count
    from nabla.utils import SEVERITY_ORDER
    sorted_methods = sorted(
        by_method.keys(),
        key=lambda m: (
            SEVERITY_ORDER.get(
                max((a.get("severity", "medium") for a in by_method[m]),
                    key=lambda s: SEVERITY_ORDER.get(s, 2)),
                2,
            ),
            -len(by_method[m]),
        ),
    )

    lines = []
    for method in sorted_methods[:max_entries]:
        method_anomalies = by_method[method]
        # Use the first anomaly as representative
        evidence = _extract_evidence_from_anomaly(method_anomalies[0])
        count = len(method_anomalies)

        # Build the evidence line
        parts = [evidence["rule"]]
        if evidence["threshold"]:
            parts.append(f"threshold={evidence['threshold']}")
        if evidence["actual"]:
            parts.append(f"actual={evidence['actual']}")
        if evidence["margin"]:
            parts.append(f"margin={evidence['margin']}")
        if count > 1:
            parts.append(f"({count} anomalies)")

        lines.append("    - " + ", ".join(parts))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Rule Counterfactuals — what minimal changes alter the finding
# ---------------------------------------------------------------------------

def compute_counterfactuals(
    finding: dict,
    correlations: list[dict],
    attack_lookup: dict[str, list],
) -> list[dict]:
    """Compute rule counterfactuals for a finding.

    For each anomaly type in the finding, compute what would happen if
    that type were removed (false positive scenario). Also compute what
    threshold changes would remove anomaly types.

    Args:
        finding: Finding dict from assess_findings.
        correlations: Full list of correlations (for re-assessment).
        attack_lookup: ATT&CK mapping for re-assessment.

    Returns:
        List of counterfactual dicts with keys: type, change, effect.
    """
    from nabla.correlation import assess_findings, _CRITICAL_ANOMALY_TYPES

    counterfactuals = []
    anomaly_types = set(finding.get("type", "").split(", "))

    # 1. Per-type removal: what if this anomaly type were a false positive?
    for atype in sorted(anomaly_types):
        atype = atype.strip()
        if not atype:
            continue

        # Find the matching correlation
        matching_corr = None
        for corr in correlations:
            if (corr.get("entity") == finding.get("entity") and
                    corr.get("entity_type") == finding.get("entity_type")):
                matching_corr = corr
                break

        if not matching_corr:
            continue

        # Simulate removal: filter out this anomaly type
        remaining_types = anomaly_types - {atype}
        if not remaining_types:
            counterfactuals.append({
                "type": "removal",
                "change": f"if {atype} were a false positive",
                "effect": "finding would disappear entirely",
                "new_severity": None,
            })
            continue

        # Re-assess with reduced types
        modified_corr = dict(matching_corr)
        modified_corr["anomaly_types"] = sorted(remaining_types)
        modified_findings = assess_findings([modified_corr], attack_lookup)

        if modified_findings:
            new_sev = modified_findings[0].get("severity", "unknown")
            old_sev = finding.get("severity", "unknown")
            if new_sev != old_sev:
                counterfactuals.append({
                    "type": "removal",
                    "change": f"if {atype} were a false positive",
                    "effect": f"severity drops from {old_sev.upper()} to {new_sev.upper()}",
                    "new_severity": new_sev,
                })
            else:
                counterfactuals.append({
                    "type": "removal",
                    "change": f"if {atype} were a false positive",
                    "effect": (
                        f"finding persists (severity unchanged at "
                        f"{old_sev.upper()}, {len(remaining_types)} types remain)"
                    ),
                    "new_severity": new_sev,
                })
        else:
            counterfactuals.append({
                "type": "removal",
                "change": f"if {atype} were a false positive",
                "effect": "finding would disappear",
                "new_severity": None,
            })

    # 2. Critical type check: does the finding depend on a single critical type?
    critical_types = anomaly_types & _CRITICAL_ANOMALY_TYPES
    if len(critical_types) == 1 and len(anomaly_types) == 1:
        ct = critical_types.pop()
        counterfactuals.append({
            "type": "critical_dependency",
            "change": f"finding depends entirely on {ct}",
            "effect": "single critical type — high false positive impact if dismissed",
            "new_severity": None,
        })

    return counterfactuals[:_MAX_COUNTERFACTUALS_PER_FINDING]


def format_counterfactuals(counterfactuals: list[dict]) -> str:
    """Format counterfactuals as text for the threat_findings block.

    Args:
        counterfactuals: List of counterfactual dicts from compute_counterfactuals.

    Returns:
        Formatted counterfactual string.
    """
    if not counterfactuals:
        return ""

    lines = []
    for cf in counterfactuals:
        lines.append(f"    - {cf['change']} → {cf['effect']}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Graph Counterfactuals — which provenance edges are critical
# ---------------------------------------------------------------------------

def compute_graph_counterfactuals(
    graph,  # ProvenanceGraph
    community: dict,
    anomaly_nodes: set,
    density_threshold: float = 0.3,
) -> list[dict]:
    """Identify critical edges whose removal dissolves an anomalous community.

    For each edge in the community, temporarily remove it and re-run
    Louvain to see if the community splits or its density drops below
    the threshold. This is the PROVX approach adapted for Louvain
    communities instead of GNN predictions.

    Args:
        graph: ProvenanceGraph instance.
        community: Community dict with 'id', 'members', 'anomaly_density'.
        anomaly_nodes: Set of (type, name) tuples that are anomalous.
        density_threshold: Minimum anomaly density for a community to be flagged.

    Returns:
        List of counterfactual dicts with keys: edge, effect, new_density.
    """
    from nabla.provenance import louvain_communities

    members = set(community.get("members", []))
    if not members or len(members) < 3:
        return []

    # Collect edges within the community
    community_edges = []
    for node in members:
        if node in graph.edges:
            for neighbor, edge_type in graph.edges[node]:
                if neighbor in members:
                    # Avoid double-counting (undirected graph)
                    edge_key = tuple(sorted([node, neighbor]))
                    community_edges.append((edge_key, edge_type))

    if not community_edges:
        return []

    # Deduplicate edges
    seen_edges = set()
    unique_edges = []
    for edge_key, edge_type in community_edges:
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            unique_edges.append((edge_key, edge_type))

    counterfactuals = []

    # Try removing each edge one at a time
    for edge_key, edge_type in unique_edges[:20]:  # Limit to 20 edges for performance
        node_a, node_b = edge_key

        # Temporarily remove the edge
        removed_a = []
        removed_b = []
        new_edges_a = []
        new_edges_b = []

        for neighbor, etype in graph.edges[node_a]:
            if neighbor == node_b and etype == edge_type:
                removed_a.append((neighbor, etype))
            else:
                new_edges_a.append((neighbor, etype))

        for neighbor, etype in graph.edges[node_b]:
            if neighbor == node_a and etype == edge_type:
                removed_b.append((neighbor, etype))
            else:
                new_edges_b.append((neighbor, etype))

        graph.edges[node_a] = new_edges_a
        graph.edges[node_b] = new_edges_b

        # Re-run Louvain on the modified graph
        try:
            partition = louvain_communities(graph)
            # Convert partition dict → community groups
            comm_groups: dict[int, set] = {}
            for node, cid in partition.items():
                comm_groups.setdefault(cid, set()).add(node)

            # Find the community that contains the most original members
            best_match = None
            best_overlap = 0
            for cid, comm_members_set in comm_groups.items():
                overlap = len(comm_members_set & members)
                if overlap > best_overlap:
                    best_overlap = overlap
                    best_match = comm_members_set

            if best_match is not None:
                anomalous_in_match = len(best_match & anomaly_nodes)
                new_density = anomalous_in_match / len(best_match) if best_match else 0.0

                # Check if the community split: more than 20% of original
                # members are now in other communities
                members_lost = len(members) - best_overlap
                split_fraction = members_lost / len(members) if members else 0
                if split_fraction > 0.2:
                    counterfactuals.append({
                        "edge": (node_a, node_b, edge_type),
                        "effect": "community splits",
                        "new_density": new_density,
                        "remaining_members": best_overlap,
                    })
                elif new_density < density_threshold:
                    counterfactuals.append({
                        "edge": (node_a, node_b, edge_type),
                        "effect": f"density drops from {community.get('anomaly_density', 0):.2f} to {new_density:.2f}",
                        "new_density": new_density,
                        "remaining_members": best_overlap,
                    })
        except Exception:
            pass  # silent by design: Louvain may fail on degenerate graphs (2026-09 sweep)

        # Restore the edge
        graph.edges[node_a] = new_edges_a + removed_a
        graph.edges[node_b] = new_edges_b + removed_b

    # Sort by impact (splits first, then density drops)
    counterfactuals.sort(key=lambda cf: (0 if cf["effect"] == "community splits" else 1,))

    return counterfactuals[:_MAX_GRAPH_CF_EDGES]


def format_graph_counterfactuals(counterfactuals: list[dict]) -> str:
    """Format graph counterfactuals as text for the threat_findings block.

    Args:
        counterfactuals: List of graph counterfactual dicts.

    Returns:
        Formatted graph counterfactual string.
    """
    if not counterfactuals:
        return ""

    lines = []
    for cf in counterfactuals:
        node_a, node_b, edge_type = cf["edge"]
        # Format node names for readability
        a_name = node_a[1] if isinstance(node_a, tuple) else str(node_a)
        b_name = node_b[1] if isinstance(node_b, tuple) else str(node_b)
        lines.append(f"    - Removing edge ({a_name} → {b_name}, \"{edge_type}\") {cf['effect']}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Full explanation — combine all three layers
# ---------------------------------------------------------------------------

def explain_findings(
    findings: list[dict],
    anomalies: list[dict],
    correlations: list[dict],
    attack_lookup: dict[str, list],
    graph=None,
    communities: list[dict] | None = None,
    anomaly_nodes: set | None = None,
) -> str:
    """Generate full explanations for all findings.

    Combines evidence traces, rule counterfactuals, and graph counterfactuals
    into a single text block for the threat_findings shared memory.

    Args:
        findings: List of finding dicts from assess_findings.
        anomalies: Full list of anomaly dicts.
        correlations: Full list of correlation dicts.
        attack_lookup: ATT&CK mapping for counterfactual re-assessment.
        graph: Optional ProvenanceGraph for graph counterfactuals.
        communities: Optional list of community dicts.
        anomaly_nodes: Optional set of anomalous (type, name) tuples.

    Returns:
        Explanation text to append to the threat_findings block.
    """
    if not findings:
        return ""

    lines = ["\n\n--- EVIDENCE ---"]

    for finding in findings:
        entity = finding.get("entity", "unknown")
        entity_type = finding.get("entity_type", "unknown")
        anomaly_types = set(finding.get("type", "").split(", "))

        # Find contributing anomalies for this finding
        contributing = [
            a for a in anomalies
            if (a.get("user") == entity or
                a.get("source_ip", a.get("src_ip", a.get("client_ip", ""))) == entity or
                a.get("detection_method", a.get("type", "")) in anomaly_types)
        ]

        # Evidence trace
        evidence_text = format_evidence(contributing)
        if evidence_text:
            lines.append(f"\n  [{entity_type}] {entity}:")
            lines.append(evidence_text)

        # Rule counterfactuals
        cfs = compute_counterfactuals(finding, correlations, attack_lookup)
        cf_text = format_counterfactuals(cfs)
        if cf_text:
            lines.append("\n  Counterfactuals:")
            lines.append(cf_text)

        # Graph counterfactuals (if provenance data available)
        if graph and communities and anomaly_nodes:
            # Find the community for this finding
            gc = finding.get("graph_community")
            if gc:
                comm_id = gc.get("community_id")
                matching_comm = None
                for c in communities:
                    if c.get("id") == comm_id:
                        matching_comm = c
                        break
                if matching_comm:
                    graph_cfs = compute_graph_counterfactuals(
                        graph, matching_comm, anomaly_nodes,
                    )
                    gcf_text = format_graph_counterfactuals(graph_cfs)
                    if gcf_text:
                        lines.append("\n  Graph Counterfactuals:")
                        lines.append(gcf_text)

    # Truncate if too long (budget: ~2K chars for evidence section)
    result = "\n".join(lines)
    if len(result) > 2000:
        result = result[:1997] + "..."

    return result
