"""Provenance graph construction and Louvain community detection.

Implements the SHIELD Graph Analyzer module:
1. Build a provenance graph from log entries (nodes = entities, edges = relationships)
2. Prune benign nodes (well-known system processes with no anomalous neighbors)
3. Run Louvain community detection on the reduced graph
4. Flag anomalous communities (high anomaly density, cross-type clusters)

Pure Python — no NetworkX dependency. Louvain implemented from scratch for
consistency with GCN-LOF's pure-numpy approach.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from nabla.log import get_logger
from nabla.utils import esc_block_value

logger = get_logger("provenance")

# --- Node types ---
NODE_PROCESS = "process"
NODE_FILE = "file"
NODE_IP = "ip"
NODE_USER = "user"
NODE_HOST = "host"
NODE_REGISTRY = "registry"
NODE_DOMAIN = "domain"

# --- Edge types ---
EDGE_PARENT_OF = "parent_of"
EDGE_EXECUTED_ON = "executed_on"
EDGE_CREATED = "created"
EDGE_READ = "read"
EDGE_WROTE = "wrote"
EDGE_CONNECTED_TO = "connected_to"
EDGE_LOGGED_IN_AS = "logged_in_as"
EDGE_QUERIED = "queried"

# Well-known benign processes — pruned from the graph unless they have
# anomalous neighbors. Case-insensitive matching. Stored WITHOUT .exe
# suffix since process names are normalized on extraction.
BENIGN_PROCESSES = {
    "explorer", "svchost", "services", "winlogon",
    "lsass", "csrss", "smss", "wininit",
    "dwm", "taskhostw", "sihost", "ctfmon",
    "runtimebroker", "searchindexer", "spoolsv",
    "conhost", "fontdrvhost", "dllhost",
    "system", "system idle process", "registry",
    "sshd", "cron", "systemd", "journald",
}

# Default thresholds for community detection
DEFAULT_PROVENANCE_THRESHOLDS = {
    "provenance_anomaly_density": 0.3,
    "provenance_min_community_size": 3,
}


# ---------------------------------------------------------------------------
# Provenance Graph
# ---------------------------------------------------------------------------

class ProvenanceGraph:
    """Provenance graph built from security log entries.

    Nodes are (type, name) tuples. Edges are undirected with a type label.
    The graph is stored as an adjacency list for efficient traversal.

    Attributes:
        nodes: Set of (type, name) tuples.
        edges: Dict mapping node -> list of (neighbor, edge_type).
        node_entries: Dict mapping node -> list of log entry indices.
        node_anomaly: Set of nodes that appear in the anomaly list.
    """

    def __init__(self) -> None:
        self.nodes: set[tuple[str, str]] = set()
        self.edges: dict[tuple[str, str], list[tuple[tuple[str, str], str]]] = defaultdict(list)
        self.node_entries: dict[tuple[str, str], list[int]] = defaultdict(list)
        self.node_anomaly: set[tuple[str, str]] = set()

    def add_node(self, node_type: str, name: str) -> tuple[str, str]:
        """Add a node to the graph.

        Args:
            node_type: One of NODE_* constants.
            name: Node identifier (process name, IP, etc.).

        Returns:
            The (type, name) tuple used as the node key.
        """
        node = (node_type, name.lower().strip())
        if node[1]:  # Skip empty names
            self.nodes.add(node)
        return node

    def add_edge(
        self,
        node_a: tuple[str, str],
        node_b: tuple[str, str],
        edge_type: str,
    ) -> None:
        """Add an undirected edge between two nodes.

        Args:
            node_a: First node (type, name).
            node_b: Second node (type, name).
            edge_type: One of EDGE_* constants.
        """
        if node_a in self.nodes and node_b in self.nodes and node_a != node_b:
            self.edges[node_a].append((node_b, edge_type))
            self.edges[node_b].append((node_a, edge_type))

    def neighbors(self, node: tuple[str, str]) -> list[tuple[tuple[str, str], str]]:
        """Get neighbors of a node.

        Args:
            node: (type, name) tuple.

        Returns:
            List of (neighbor_node, edge_type) pairs.
        """
        return self.edges.get(node, [])

    def degree(self, node: tuple[str, str]) -> int:
        """Get the degree of a node.

        Args:
            node: (type, name) tuple.

        Returns:
            Number of edges incident to the node.
        """
        return len(self.edges.get(node, []))

    def node_count(self) -> int:
        """Return the number of nodes in the graph."""
        return len(self.nodes)

    def edge_count(self) -> int:
        """Return the number of unique edges (each undirected edge counted once)."""
        seen: set[tuple[tuple[str, str], tuple[str, str]]] = set()
        count = 0
        for node, neighbors in self.edges.items():
            for neighbor, _ in neighbors:
                key = (node, neighbor) if node < neighbor else (neighbor, node)
                if key not in seen:
                    seen.add(key)
                    count += 1
        return count


def build_from_entries(
    entries: list[dict[str, Any]],
    anomalies: list[dict[str, Any]] | None = None,
) -> ProvenanceGraph:
    """Build a provenance graph from log entries.

    Extracts nodes and edges from all 4 log types (auth, network, dns, endpoint).
    Marks nodes that appear in the anomaly list.

    Args:
        entries: List of log entry dicts.
        anomalies: Optional list of anomaly dicts from detect_anomalies().

    Returns:
        ProvenanceGraph with nodes, edges, and anomaly markers.
    """
    graph = ProvenanceGraph()

    # Build anomaly lookup: which entities are anomalous
    anomaly_entities: set[tuple[str, str]] = set()
    if anomalies:
        for a in anomalies:
            user = a.get("user", "")
            if user:
                anomaly_entities.add((NODE_USER, user.lower()))
            host = a.get("host", "")
            if host:
                anomaly_entities.add((NODE_HOST, host.upper()))
            ip = a.get("source_ip", a.get("src_ip", a.get("client_ip", "")))
            if ip:
                anomaly_entities.add((NODE_IP, ip.lower()))
            proc = a.get("process", "")
            if proc:
                anomaly_entities.add((NODE_PROCESS, proc.lower().replace(".exe", "")))

    for idx, entry in enumerate(entries):
        log_type = entry.get("type", "unknown")

        if log_type == "auth":
            _extract_auth_nodes(graph, entry, idx)
        elif log_type == "network":
            _extract_network_nodes(graph, entry, idx)
        elif log_type == "dns":
            _extract_dns_nodes(graph, entry, idx)
        elif log_type == "endpoint":
            _extract_endpoint_nodes(graph, entry, idx)

    # Mark anomalous nodes
    for node in graph.nodes:
        if node in anomaly_entities:
            graph.node_anomaly.add(node)

    return graph


def _extract_auth_nodes(
    graph: ProvenanceGraph,
    entry: dict[str, Any],
    idx: int,
) -> None:
    """Extract nodes and edges from an auth log entry.

    Args:
        graph: ProvenanceGraph to add to.
        entry: Auth log entry dict.
        idx: Entry index for node_entries tracking.
    """
    user = entry.get("user", "")
    src_ip = entry.get("source_ip", entry.get("src_ip", ""))
    dest_host = entry.get("dest_host", entry.get("host", ""))

    user_node = graph.add_node(NODE_USER, user) if user else None
    ip_node = graph.add_node(NODE_IP, src_ip) if src_ip else None
    host_node = graph.add_node(NODE_HOST, dest_host) if dest_host else None

    if user_node:
        graph.node_entries[user_node].append(idx)
    if ip_node:
        graph.node_entries[ip_node].append(idx)
    if host_node:
        graph.node_entries[host_node].append(idx)

    if user_node and ip_node:
        graph.add_edge(user_node, ip_node, EDGE_LOGGED_IN_AS)
    if user_node and host_node:
        graph.add_edge(user_node, host_node, EDGE_EXECUTED_ON)


def _extract_network_nodes(
    graph: ProvenanceGraph,
    entry: dict[str, Any],
    idx: int,
) -> None:
    """Extract nodes and edges from a network log entry.

    Args:
        graph: ProvenanceGraph to add to.
        entry: Network log entry dict.
        idx: Entry index for node_entries tracking.
    """
    src_ip = entry.get("src_ip", entry.get("source_ip", ""))
    dst_ip = entry.get("dst_ip", entry.get("dest_ip", ""))
    host = entry.get("host", "")

    src_node = graph.add_node(NODE_IP, src_ip) if src_ip else None
    dst_node = graph.add_node(NODE_IP, dst_ip) if dst_ip else None
    host_node = graph.add_node(NODE_HOST, host) if host else None

    if src_node:
        graph.node_entries[src_node].append(idx)
    if dst_node:
        graph.node_entries[dst_node].append(idx)
    if host_node:
        graph.node_entries[host_node].append(idx)

    if src_node and dst_node:
        graph.add_edge(src_node, dst_node, EDGE_CONNECTED_TO)
    if src_node and host_node:
        graph.add_edge(src_node, host_node, EDGE_EXECUTED_ON)


def _extract_dns_nodes(
    graph: ProvenanceGraph,
    entry: dict[str, Any],
    idx: int,
) -> None:
    """Extract nodes and edges from a DNS log entry.

    Args:
        graph: ProvenanceGraph to add to.
        entry: DNS log entry dict.
        idx: Entry index for node_entries tracking.
    """
    client_ip = entry.get("client_ip", entry.get("source_ip", ""))
    domain = entry.get("domain", "")

    ip_node = graph.add_node(NODE_IP, client_ip) if client_ip else None
    domain_node = graph.add_node(NODE_DOMAIN, domain) if domain else None

    if ip_node:
        graph.node_entries[ip_node].append(idx)
    if domain_node:
        graph.node_entries[domain_node].append(idx)

    if ip_node and domain_node:
        graph.add_edge(ip_node, domain_node, EDGE_QUERIED)


def _extract_endpoint_nodes(
    graph: ProvenanceGraph,
    entry: dict[str, Any],
    idx: int,
) -> None:
    """Extract nodes and edges from an endpoint log entry.

    Args:
        graph: ProvenanceGraph to add to.
        entry: Endpoint log entry dict.
        idx: Entry index for node_entries tracking.
    """
    proc = (entry.get("process", "") or entry.get("Image", "") or "").lower().replace(".exe", "")
    parent = (entry.get("parent_process", "") or entry.get("ParentImage", "") or "").lower().replace(".exe", "")
    host = (entry.get("host", "") or entry.get("Computer", "") or "").upper()
    user = entry.get("user", "")
    action = entry.get("action", "")
    target_file = entry.get("target_file", "")
    target_registry = entry.get("target_registry", "")
    network_connection = entry.get("network_connection", "")

    proc_node = graph.add_node(NODE_PROCESS, proc) if proc else None
    parent_node = graph.add_node(NODE_PROCESS, parent) if parent else None
    host_node = graph.add_node(NODE_HOST, host) if host else None
    user_node = graph.add_node(NODE_USER, user) if user else None
    file_node = graph.add_node(NODE_FILE, target_file) if target_file else None
    reg_node = graph.add_node(NODE_REGISTRY, target_registry) if target_registry else None
    net_node = graph.add_node(NODE_IP, network_connection) if network_connection else None

    if proc_node:
        graph.node_entries[proc_node].append(idx)
    if parent_node:
        graph.node_entries[parent_node].append(idx)
    if host_node:
        graph.node_entries[host_node].append(idx)
    if user_node:
        graph.node_entries[user_node].append(idx)
    if file_node:
        graph.node_entries[file_node].append(idx)
    if reg_node:
        graph.node_entries[reg_node].append(idx)
    if net_node:
        graph.node_entries[net_node].append(idx)

    # Parent-child edge
    if parent_node and proc_node:
        graph.add_edge(parent_node, proc_node, EDGE_PARENT_OF)

    # Process executed on host
    if proc_node and host_node:
        graph.add_edge(proc_node, host_node, EDGE_EXECUTED_ON)

    # Process run by user
    if proc_node and user_node:
        graph.add_edge(proc_node, user_node, EDGE_LOGGED_IN_AS)

    # Action-based edges
    if proc_node and file_node:
        if action == "create":
            graph.add_edge(proc_node, file_node, EDGE_CREATED)
        elif action == "modify" or action == "read":
            graph.add_edge(proc_node, file_node, EDGE_READ)
        elif action == "delete":
            graph.add_edge(proc_node, file_node, EDGE_WROTE)
        else:
            graph.add_edge(proc_node, file_node, EDGE_READ)

    if proc_node and reg_node:
        if action == "create":
            graph.add_edge(proc_node, reg_node, EDGE_CREATED)
        else:
            graph.add_edge(proc_node, reg_node, EDGE_WROTE)

    if proc_node and net_node:
        graph.add_edge(proc_node, net_node, EDGE_CONNECTED_TO)


# ---------------------------------------------------------------------------
# Benign Pruning
# ---------------------------------------------------------------------------

def prune_benign_nodes(graph: ProvenanceGraph) -> ProvenanceGraph:
    """Remove benign nodes that have no anomalous neighbors.

    Prunes well-known system processes (explorer.exe, svchost.exe, etc.)
    unless they are directly connected to an anomalous node. Also removes
    isolated nodes (degree 0) after pruning.

    Args:
        graph: Input ProvenanceGraph.

    Returns:
        New ProvenanceGraph with benign nodes removed.
    """
    pruned = ProvenanceGraph()

    # Determine which nodes to keep
    keep: set[tuple[str, str]] = set()
    for node in graph.nodes:
        node_type, node_name = node

        # Always keep anomalous nodes
        if node in graph.node_anomaly:
            keep.add(node)
            continue

        # Keep non-process nodes (IPs, users, hosts, files, domains, registry)
        if node_type != NODE_PROCESS:
            keep.add(node)
            continue

        # For process nodes: keep if not in benign list
        if node_name not in BENIGN_PROCESSES:
            keep.add(node)
            continue

        # Benign process: keep if it has anomalous neighbors
        has_anomalous_neighbor = False
        for neighbor, _ in graph.neighbors(node):
            if neighbor in graph.node_anomaly:
                has_anomalous_neighbor = True
                break
        if has_anomalous_neighbor:
            keep.add(node)

    # Build pruned graph
    for node in keep:
        pruned.nodes.add(node)
        pruned.node_entries[node] = graph.node_entries.get(node, [])
        if node in graph.node_anomaly:
            pruned.node_anomaly.add(node)

    # Copy edges (only between kept nodes)
    for node in keep:
        for neighbor, edge_type in graph.neighbors(node):
            if neighbor in keep:
                pruned.edges[node].append((neighbor, edge_type))

    # Remove isolated nodes (degree 0 after pruning)
    isolated = {n for n in pruned.nodes if pruned.degree(n) == 0 and n not in pruned.node_anomaly}
    pruned.nodes -= isolated
    for node in list(pruned.edges):
        if node in isolated:
            del pruned.edges[node]
        else:
            pruned.edges[node] = [
                (nb, et) for nb, et in pruned.edges[node] if nb not in isolated
            ]

    return pruned


# ---------------------------------------------------------------------------
# Louvain Community Detection
# ---------------------------------------------------------------------------

def _compute_modularity(
    nodes: list[tuple[str, str]],
    adj: dict[tuple[str, str], list[tuple[tuple[str, str], str]]],
    partition: dict[tuple[str, str], int],
) -> float:
    """Compute modularity of a partition.

    Q = (1/2m) * sum_ij [ A_ij - k_i*k_j/(2m) ] * delta(c_i, c_j)

    Args:
        nodes: List of node keys.
        adj: Adjacency list.
        partition: Dict mapping node -> community_id.

    Returns:
        Modularity value (range [-0.5, 1.0], higher is better).
    """
    # Total edge weight (each undirected edge counted once in 2m)
    m = sum(len(adj.get(n, [])) for n in nodes) / 2.0
    if m == 0:
        return 0.0

    # Degree of each node
    degree: dict[tuple[str, str], float] = {n: len(adj.get(n, [])) for n in nodes}

    # Community internal edge weight and total degree
    community_sigma: dict[int, float] = defaultdict(float)  # sum of internal edges
    community_k: dict[int, float] = defaultdict(float)  # sum of degrees

    for node in nodes:
        c = partition[node]
        community_k[c] += degree[node]
        for neighbor, _ in adj.get(node, []):
            if partition[neighbor] == c:
                community_sigma[c] += 1.0

    # Each internal edge counted twice (once from each end)
    Q = 0.0
    for c in set(partition.values()):
        Q += community_sigma[c] / (2.0 * m) - (community_k[c] / (2.0 * m)) ** 2

    return Q


def _modularity_gain(
    node: tuple[str, str],
    target_community: int,
    adj: dict[tuple[str, str], list[tuple[tuple[str, str], str]]],
    partition: dict[tuple[str, str], int],
    degree: dict[tuple[str, str], float],
    m: float,
) -> float:
    """Compute modularity gain from moving a node to a target community.

    ΔQ = [k_i,in / m - Σ_tot * k_i / (2m²)] - [k_i,in_old / m - Σ_tot_old * k_i / (2m²)]

    Simplified: ΔQ = (k_i,in_new - k_i,in_old) / m - k_i * (Σ_tot_new - Σ_tot_old) / (2m²)

    Args:
        node: Node to move.
        target_community: Target community ID.
        adj: Adjacency list.
        partition: Current partition.
        degree: Node degree dict.
        m: Total edge weight / 2.

    Returns:
        Modularity gain (positive = improvement).
    """
    if m == 0:
        return 0.0

    k_i = degree.get(node, 0)
    current_community = partition[node]

    # Edges to target community
    k_i_in_new = 0.0
    k_i_in_old = 0.0
    for neighbor, _ in adj.get(node, []):
        if partition[neighbor] == target_community:
            k_i_in_new += 1.0
        if partition[neighbor] == current_community:
            k_i_in_old += 1.0

    # Total degree of communities
    sigma_tot_new = sum(degree.get(n, 0) for n in partition if partition[n] == target_community)
    sigma_tot_old = sum(degree.get(n, 0) for n in partition if partition[n] == current_community)

    # Remove self from old community total
    sigma_tot_old -= k_i

    delta_q = (k_i_in_new - k_i_in_old) / m - k_i * (sigma_tot_new - sigma_tot_old) / (2.0 * m * m)
    return delta_q


def louvain_communities(
    graph: ProvenanceGraph,
    max_iterations: int = 50,
) -> dict[tuple[str, str], int]:
    """Run Louvain community detection on the provenance graph.

    Two-phase algorithm:
    1. Local moves: each node moves to the neighbor community that
       maximizes modularity gain. Repeat until no improvement.
    2. Aggregation: collapse communities into super-nodes, rebuild graph,
       repeat from step 1.

    Args:
        graph: ProvenanceGraph to analyze.
        max_iterations: Maximum iterations per phase.

    Returns:
        Dict mapping each node to its community ID (0-indexed).
    """
    nodes = list(graph.nodes)
    if len(nodes) == 0:
        return {}
    if len(nodes) == 1:
        return {nodes[0]: 0}

    adj: dict[tuple[str, str], list[tuple[tuple[str, str], str]]] = {}
    for node in nodes:
        adj[node] = graph.neighbors(node)

    # Initialize: each node in its own community
    partition: dict[tuple[str, str], int] = {n: i for i, n in enumerate(nodes)}
    degree: dict[tuple[str, str], float] = {n: len(adj.get(n, [])) for n in nodes}
    m = sum(degree.values()) / 2.0

    if m == 0:
        # No edges — all nodes in one community
        return {n: 0 for n in nodes}

    # Phase 1: local moves
    improved = True
    iteration = 0
    while improved and iteration < max_iterations:
        improved = False
        iteration += 1

        for node in nodes:
            current_community = partition[node]

            # Find neighbor communities
            neighbor_communities: set[int] = set()
            for neighbor, _ in adj.get(node, []):
                neighbor_communities.add(partition[neighbor])

            if not neighbor_communities:
                continue

            # Try each neighbor community, pick the best gain
            best_community = current_community
            best_gain = 0.0

            for comm in neighbor_communities:
                if comm == current_community:
                    continue
                gain = _modularity_gain(node, comm, adj, partition, degree, m)
                if gain > best_gain:
                    best_gain = gain
                    best_community = comm

            if best_community != current_community:
                partition[node] = best_community
                improved = True

    # Renumber communities to 0..k-1
    unique_communities = sorted(set(partition.values()))
    remap = {old: new for new, old in enumerate(unique_communities)}
    return {n: remap[c] for n, c in partition.items()}


# ---------------------------------------------------------------------------
# Anomalous Community Detection
# ---------------------------------------------------------------------------

def detect_anomalous_communities(
    graph: ProvenanceGraph,
    communities: dict[tuple[str, str], int],
    thresholds: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    """Flag communities that are likely part of an attack.

    A community is flagged if:
    - anomaly_density > provenance_anomaly_density threshold, OR
    - type_diversity >= 3 AND anomaly_density > provenance_anomaly_density / 3

    Args:
        graph: ProvenanceGraph (should be pruned).
        communities: Dict from louvain_communities().
        thresholds: Optional threshold overrides.

    Returns:
        List of anomaly dicts with detection_method="provenance_community".
    """
    if not communities:
        return []

    thresh = {**DEFAULT_PROVENANCE_THRESHOLDS, **(thresholds or {})}
    min_density = thresh["provenance_anomaly_density"]
    min_size = int(thresh["provenance_min_community_size"])

    # Group nodes by community
    community_nodes: dict[int, list[tuple[str, str]]] = defaultdict(list)
    for node, comm_id in communities.items():
        community_nodes[comm_id].append(node)

    anomalies: list[dict[str, Any]] = []

    for comm_id, members in community_nodes.items():
        if len(members) < min_size:
            continue

        # Compute metrics
        anomaly_count = sum(1 for n in members if n in graph.node_anomaly)
        anomaly_density = anomaly_count / len(members) if members else 0.0

        node_types = set(n[0] for n in members)
        type_diversity = len(node_types)

        # Compute edge density within community
        internal_edges = 0
        for node in members:
            for neighbor, _ in graph.neighbors(node):
                if neighbor in members and node < neighbor:
                    internal_edges += 1
        max_edges = len(members) * (len(members) - 1) / 2
        edge_density = internal_edges / max_edges if max_edges > 0 else 0.0

        # Flag criteria
        flagged = False
        reason = ""

        if anomaly_density >= min_density:
            flagged = True
            reason = f"anomaly_density={anomaly_density:.2f}>={min_density}"
        elif type_diversity >= 3 and anomaly_density >= min_density / 3:
            flagged = True
            reason = (
                f"cross-type cluster: type_diversity={type_diversity}, "
                f"anomaly_density={anomaly_density:.2f}"
            )

        if flagged:
            # Build member summary
            member_summary: dict[str, list[str]] = defaultdict(list)
            for ntype, nname in members:
                member_summary[ntype].append(nname)

            anomalies.append({
                "type": "provenance_community",
                "severity": "high" if anomaly_density >= 0.5 else "medium",
                "community_id": comm_id,
                "community_size": len(members),
                "anomaly_density": round(anomaly_density, 3),
                "type_diversity": type_diversity,
                "edge_density": round(edge_density, 3),
                "node_types": dict(member_summary),
                "detection_method": "provenance_community",
                "details": (
                    f"Community {comm_id}: {len(members)} nodes, "
                    f"{reason}, types={sorted(node_types)}, "
                    f"edge_density={edge_density:.2f}"
                ),
            })

    return anomalies


# ---------------------------------------------------------------------------
# Graph Context Formatting (for LLM analyzer)
# ---------------------------------------------------------------------------

def format_provenance_summary(
    graph: ProvenanceGraph,
    communities: dict[tuple[str, str], int],
    provenance_anomalies: list[dict[str, Any]],
) -> str:
    """Format provenance graph context for the graph_context shared block.

    Produces human-readable community summaries plus a JSON line for
    structured parsing by threat tools.

    Args:
        graph: Pruned ProvenanceGraph (after benign node removal).
        communities: Community assignments from Louvain.
        provenance_anomalies: Anomaly dicts from detect_anomalous_communities().

    Returns:
        Formatted text for the graph_context block (provenance section).
    """
    if not communities:
        return "Provenance graph: no communities detected"

    # Group nodes by community
    community_nodes: dict[int, list[tuple[str, str]]] = defaultdict(list)
    for node, comm_id in communities.items():
        community_nodes[comm_id].append(node)

    # Build anomaly lookup by community_id
    anomaly_by_community: dict[int, dict[str, Any]] = {}
    for a in provenance_anomalies:
        cid = a.get("community_id")
        if cid is not None:
            anomaly_by_community[cid] = a

    # Human-readable summary
    lines = [
        f"Provenance graph: {graph.node_count()} nodes, "
        f"{graph.edge_count()} edges, {len(community_nodes)} communities "
        f"({len(anomaly_by_community)} flagged)"
    ]

    # JSON-serializable community data — only flagged communities
    json_communities = []

    for comm_id in sorted(community_nodes.keys()):
        members = community_nodes[comm_id]
        anomaly_count = sum(1 for n in members if n in graph.node_anomaly)
        anomaly_density = anomaly_count / len(members) if members else 0.0
        node_types = sorted(set(n[0] for n in members))
        member_names = sorted(f"{n[0]}:{n[1]}" for n in members)
        anomalous_names = sorted(f"{n[0]}:{n[1]}" for n in members if n in graph.node_anomaly)
        is_flagged = comm_id in anomaly_by_community

        # Human-readable: show all communities briefly, flagged ones in detail
        lines.append(
            f"Community {comm_id}: {len(members)} nodes "
            f"({anomaly_count} anomalous), types: {', '.join(node_types)}, "
            f"density={anomaly_density:.2f}"
        )
        if anomalous_names:
            # RR-1: node names come from logs (usernames, hostnames,
            # process names) — escape them or a hostile name forges
            # block structure. The JSON entry below is json.dumps'd
            # and needs no escaping.
            lines.append(
                f"  Anomalous: {', '.join(esc_block_value(n, 128) for n in anomalous_names[:10])}"
            )

        # Only include flagged communities in JSON (saves context window)
        if not is_flagged:
            continue

        # Build entity-to-neighbor mapping for anomalous entities only
        neighbor_map: dict[str, list[str]] = {}
        for node in members:
            if node in graph.node_anomaly:
                neighbors = [f"{nb[0]}:{nb[1]} ({etype})" for nb, etype in graph.neighbors(node) if nb in members]
                if neighbors:
                    key = f"{node[0]}:{node[1]}"
                    neighbor_map[key] = neighbors[:3]  # Cap at 3 neighbors

        # Build JSON entry — limit member lists to keep size manageable
        json_entry = {
            "id": comm_id,
            "size": len(members),
            "anomaly_density": round(anomaly_density, 3),
            "types": node_types,
            "members": member_names[:20],  # Cap at 20 members
            "anomalous": anomalous_names[:10],  # Cap at 10 anomalous
            "flagged": True,
        }
        if neighbor_map:
            json_entry["neighbors"] = neighbor_map
        json_communities.append(json_entry)

    # Append JSON line
    lines.append(f"JSON:{json.dumps({'communities': json_communities}, separators=(',', ':'))}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Top-level Detection Function
# ---------------------------------------------------------------------------

def detect_provenance_anomalies(
    entries: list[dict[str, Any]],
    existing_anomalies: list[dict[str, Any]],
    thresholds: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    """Run full provenance graph analysis pipeline.

    1. Build provenance graph from entries
    2. Prune benign nodes
    3. Run Louvain community detection
    4. Flag anomalous communities

    Args:
        entries: List of log entry dicts.
        existing_anomalies: Anomalies from detect_anomalies() and GCN-LOF.
        thresholds: Optional threshold overrides.

    Returns:
        List of anomaly dicts with detection_method="provenance_community".
    """
    result = detect_provenance_anomalies_with_context(entries, existing_anomalies, thresholds)
    return result[0]


def detect_provenance_anomalies_with_context(
    entries: list[dict[str, Any]],
    existing_anomalies: list[dict[str, Any]],
    thresholds: dict[str, float] | None = None,
) -> tuple[list[dict[str, Any]], ProvenanceGraph | None, dict[tuple[str, str], int] | None]:
    """Run provenance analysis and return graph objects for context formatting.

    Same as detect_provenance_anomalies but also returns the graph and
    community assignments so the pipeline can format graph context for
    the LLM analyzer.

    Args:
        entries: List of log entry dicts.
        existing_anomalies: Anomalies from detect_anomalies() and GCN-LOF.
        thresholds: Optional threshold overrides.

    Returns:
        Tuple of (anomaly_list, graph, communities). Graph and communities
        are None if analysis was skipped.
    """
    if len(entries) < 3:
        logger.debug("Too few entries for provenance analysis (%d)", len(entries))
        return [], None, None

    # Step 1: Build graph
    graph = build_from_entries(entries, existing_anomalies)
    logger.debug(
        "Provenance graph: %d nodes, %d edges, %d anomalous",
        graph.node_count(), graph.edge_count(), len(graph.node_anomaly),
    )

    # Step 2: Prune benign nodes
    graph = prune_benign_nodes(graph)
    logger.debug(
        "After pruning: %d nodes, %d edges",
        graph.node_count(), graph.edge_count(),
    )

    if graph.node_count() < 3:
        logger.debug("Graph too small after pruning (%d nodes)", graph.node_count())
        return [], None, None

    # Step 3: Louvain community detection
    communities = louvain_communities(graph)
    n_communities = len(set(communities.values())) if communities else 0
    logger.debug("Louvain: %d communities detected", n_communities)

    # Step 4: Flag anomalous communities
    anomalies = detect_anomalous_communities(graph, communities, thresholds)
    logger.info(
        "Provenance: %d anomalous communities out of %d total",
        len(anomalies), n_communities,
    )

    return anomalies, graph, communities


def build_community_dicts(
    graph: ProvenanceGraph,
    communities: dict[tuple[str, str], int],
    provenance_anomalies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build community dicts from Louvain assignments for explainability.

    Converts the raw Louvain community mapping (node → community_id) into
    a list of community dicts with id, members, anomaly_density, etc.
    This format is needed by the explainability layer (explain_findings).

    Args:
        graph: Pruned ProvenanceGraph.
        communities: Community assignments from Louvain.
        provenance_anomalies: Anomaly dicts from detect_anomalous_communities().

    Returns:
        List of community dicts with keys: id, size, anomaly_density,
        types, members, anomalous, flagged.
    """
    if not communities:
        return []

    # Group nodes by community
    community_nodes: dict[int, list[tuple[str, str]]] = defaultdict(list)
    for node, comm_id in communities.items():
        community_nodes[comm_id].append(node)

    # Build anomaly lookup by community_id
    anomaly_by_community: set[int] = set()
    for a in provenance_anomalies:
        cid = a.get("community_id")
        if cid is not None:
            anomaly_by_community.add(cid)

    result = []
    for comm_id in sorted(community_nodes.keys()):
        members = community_nodes[comm_id]
        anomaly_count = sum(1 for n in members if n in graph.node_anomaly)
        anomaly_density = anomaly_count / len(members) if members else 0.0
        member_names = [f"{n[0]}:{n[1]}" for n in members]
        anomalous_names = [f"{n[0]}:{n[1]}" for n in members if n in graph.node_anomaly]
        is_flagged = comm_id in anomaly_by_community

        result.append({
            "id": comm_id,
            "size": len(members),
            "anomaly_density": round(anomaly_density, 3),
            "types": sorted(set(n[0] for n in members)),
            "members": member_names,
            "anomalous": anomalous_names,
            "flagged": is_flagged,
        })

    return result
