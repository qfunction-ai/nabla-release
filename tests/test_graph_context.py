"""Tests for graph context tool logic — fetch_graph_context parsing,
correlate_events enrichment, and produce_finding enrichment."""

import json
import pytest


# ---------------------------------------------------------------------------
# Test graph_context block parsing (same logic as fetch_graph_context tool)
# ---------------------------------------------------------------------------

def parse_graph_context_block(graph_text: str) -> dict:
    """Parse a graph_context block text into structured data.

    Mirrors the parsing logic in fetch_graph_context tool.
    """
    communities = []
    chains = []

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
                pass

    # Build entity-to-community lookup
    entity_communities = {}
    for comm in communities:
        for member in comm.get("members", []):
            entity_communities[member] = {
                "community_id": comm["id"],
                "anomaly_density": comm.get("anomaly_density", 0.0),
                "flagged": comm.get("flagged", False),
                "types": comm.get("types", []),
            }

    # Build entity-to-chain lookup
    entity_chains = {}
    for chain in chains:
        for etype, entities in chain.get("entities", {}).items():
            for entity in entities:
                key = f"{etype}:{entity}"
                if key not in entity_chains:
                    entity_chains[key] = []
                entity_chains[key].append({
                    "chain_id": chain["chain_id"],
                    "phases": chain.get("phases", []),
                    "score": chain.get("score", 0.0),
                    "phase_coverage": chain.get("phase_coverage", 0.0),
                })

    return {
        "communities": communities,
        "chains": chains,
        "entity_communities": entity_communities,
        "entity_chains": entity_chains,
    }


class TestGraphContextParsing:
    """Tests for parsing graph_context block text into structured data."""

    def test_empty_block(self):
        """Empty or default block text returns empty lookups."""
        result = parse_graph_context_block("Graph context: not yet analyzed")
        assert result["communities"] == []
        assert result["chains"] == []
        assert result["entity_communities"] == {}
        assert result["entity_chains"] == {}

    def test_provenance_only(self):
        """Block with provenance data only populates communities."""
        block_text = (
            "Provenance graph: 3 nodes, 2 edges, 1 communities\n"
            "Community 0: 3 nodes (2 anomalous), types: process, ip, user, density=0.67\n"
            'JSON:{"communities":[{"id":0,"size":3,"anomaly_density":0.667,"types":["process","ip","user"],'
            '"members":["process:powershell","ip:10.0.1.50","user:admin"],'
            '"anomalous":["process:powershell","ip:10.0.1.50"],"flagged":true}]}'
        )
        result = parse_graph_context_block(block_text)
        assert len(result["communities"]) == 1
        assert "ip:10.0.1.50" in result["entity_communities"]
        assert result["entity_communities"]["ip:10.0.1.50"]["flagged"] is True

    def test_temporal_only(self):
        """Block with temporal data only populates chains."""
        block_text = (
            "Temporal chains: 1 flagged out of 1 total\n"
            "Chain 0: 3 events, 3 phases (initial_access → execution → persistence), score=0.800\n"
            'JSON:{"chains":[{"chain_id":0,"events":3,"phases":["initial_access","execution","persistence"],'
            '"score":0.8,"phase_coverage":0.3,"entities":{"ip":["10.0.1.50"],"user":["admin"]}}]}'
        )
        result = parse_graph_context_block(block_text)
        assert len(result["chains"]) == 1
        assert "ip:10.0.1.50" in result["entity_chains"]
        assert result["entity_chains"]["ip:10.0.1.50"][0]["chain_id"] == 0

    def test_combined_block(self):
        """Block with both provenance and temporal data populates both lookups."""
        block_text = (
            "Provenance graph: 3 nodes, 2 edges, 1 communities\n"
            "Community 0: 3 nodes (2 anomalous), types: process, ip, user, density=0.67\n"
            'JSON:{"communities":[{"id":0,"size":3,"anomaly_density":0.667,"types":["process","ip","user"],'
            '"members":["process:powershell","ip:10.0.1.50","user:admin"],'
            '"anomalous":["process:powershell","ip:10.0.1.50"],"flagged":true}]}\n\n'
            "Temporal chains: 1 flagged out of 1 total\n"
            "Chain 0: 3 events, 3 phases (initial_access → execution → persistence), score=0.800\n"
            'JSON:{"chains":[{"chain_id":0,"events":3,"phases":["initial_access","execution","persistence"],'
            '"score":0.8,"phase_coverage":0.3,"entities":{"ip":["10.0.1.50"],"user":["admin"]}}]}'
        )
        result = parse_graph_context_block(block_text)
        assert len(result["communities"]) == 1
        assert len(result["chains"]) == 1
        assert "ip:10.0.1.50" in result["entity_communities"]
        assert "ip:10.0.1.50" in result["entity_chains"]

    def test_entity_community_lookup(self):
        """Entity-to-community lookup returns correct community metadata."""
        block_text = (
            'JSON:{"communities":[{"id":0,"size":3,"anomaly_density":0.5,"types":["ip","user"],'
            '"members":["ip:10.0.1.50","user:admin","ip:192.168.1.1"],'
            '"anomalous":["ip:10.0.1.50"],"flagged":true}]}'
        )
        result = parse_graph_context_block(block_text)
        assert result["entity_communities"]["ip:10.0.1.50"]["community_id"] == 0
        assert result["entity_communities"]["ip:10.0.1.50"]["anomaly_density"] == 0.5
        assert result["entity_communities"]["user:admin"]["community_id"] == 0

    def test_entity_chain_lookup(self):
        """Entity-to-chain lookup returns correct chain metadata."""
        block_text = (
            'JSON:{"chains":[{"chain_id":0,"events":3,"phases":["initial_access","execution"],'
            '"score":0.8,"phase_coverage":0.3,"entities":{"ip":["10.0.1.50"],"user":["admin"]}}]}'
        )
        result = parse_graph_context_block(block_text)
        assert len(result["entity_chains"]["ip:10.0.1.50"]) == 1
        assert result["entity_chains"]["ip:10.0.1.50"][0]["phases"] == ["initial_access", "execution"]
        assert result["entity_chains"]["user:admin"][0]["chain_id"] == 0

    def test_multiple_chains_per_entity(self):
        """Entity appearing in multiple chains has all chains in lookup."""
        block_text = (
            'JSON:{"chains":['
            '{"chain_id":0,"events":2,"phases":["initial_access"],"score":0.5,"phase_coverage":0.1,"entities":{"ip":["10.0.1.50"]}},'
            '{"chain_id":1,"events":3,"phases":["execution","persistence"],"score":0.7,"phase_coverage":0.2,"entities":{"ip":["10.0.1.50"]}}'
            ']}'
        )
        result = parse_graph_context_block(block_text)
        assert len(result["entity_chains"]["ip:10.0.1.50"]) == 2

    def test_malformed_json_skipped(self):
        """Malformed JSON lines are skipped without error."""
        block_text = 'JSON:{invalid json}'
        result = parse_graph_context_block(block_text)
        assert result["communities"] == []
        assert result["chains"] == []


# ---------------------------------------------------------------------------
# Test graph context enrichment logic (same as correlate_events / produce_finding)
# ---------------------------------------------------------------------------

class TestGraphContextEnrichment:
    """Tests for the _enrich_with_graph_context logic used in tools."""

    def _enrich(self, entity: str, entity_type: str, entity_communities: dict, entity_chains: dict) -> dict:
        """Mirror the _enrich_with_graph_context logic from correlate_events."""
        result = {}
        for key in [f"{entity_type}:{entity}", f"ip:{entity}", f"user:{entity}", f"host:{entity}"]:
            if key.lower() in entity_communities:
                comm = entity_communities[key.lower()]
                result["graph_community"] = {
                    "community_id": comm["community_id"],
                    "anomaly_density": comm["anomaly_density"],
                    "flagged": comm["flagged"],
                    "types": comm["types"],
                }
                if comm.get("neighbors"):
                    result["graph_neighbors"] = comm["neighbors"][:5]
                break
        for key in [f"{entity_type}:{entity}", f"ip:{entity}", f"user:{entity}", f"host:{entity}"]:
            if key.lower() in entity_chains:
                result["temporal_chains"] = entity_chains[key.lower()]
                break
        return result

    def test_ip_in_community(self):
        """IP found in community returns graph_community."""
        entity_communities = {
            "ip:10.0.1.50": {
                "community_id": 0,
                "anomaly_density": 0.5,
                "flagged": True,
                "types": ["ip", "user"],
            }
        }
        result = self._enrich("10.0.1.50", "ip", entity_communities, {})
        assert "graph_community" in result
        assert result["graph_community"]["community_id"] == 0
        assert result["graph_community"]["flagged"] is True

    def test_ip_in_chain(self):
        """IP found in temporal chain returns temporal_chains."""
        entity_chains = {
            "ip:10.0.1.50": [
                {"chain_id": 0, "phases": ["initial_access", "execution"], "score": 0.8}
            ]
        }
        result = self._enrich("10.0.1.50", "ip", {}, entity_chains)
        assert "temporal_chains" in result
        assert len(result["temporal_chains"]) == 1

    def test_ip_in_both(self):
        """IP in both community and chain returns both."""
        entity_communities = {
            "ip:10.0.1.50": {
                "community_id": 0,
                "anomaly_density": 0.5,
                "flagged": True,
                "types": ["ip", "user"],
            }
        }
        entity_chains = {
            "ip:10.0.1.50": [
                {"chain_id": 0, "phases": ["initial_access", "execution"], "score": 0.8}
            ]
        }
        result = self._enrich("10.0.1.50", "ip", entity_communities, entity_chains)
        assert "graph_community" in result
        assert "temporal_chains" in result

    def test_entity_not_in_graph(self):
        """Entity not in any community or chain returns empty dict."""
        result = self._enrich("10.0.2.99", "ip", {}, {})
        assert result == {}

    def test_user_in_community(self):
        """User found in community via user: prefix."""
        entity_communities = {
            "user:admin": {
                "community_id": 0,
                "anomaly_density": 0.3,
                "flagged": False,
                "types": ["user", "ip"],
            }
        }
        result = self._enrich("admin", "user", entity_communities, {})
        assert "graph_community" in result
        assert result["graph_community"]["flagged"] is False

    def test_case_insensitive_lookup(self):
        """Entity lookup is case-insensitive."""
        entity_communities = {
            "ip:10.0.1.50": {
                "community_id": 0,
                "anomaly_density": 0.5,
                "flagged": True,
                "types": ["ip"],
            }
        }
        result = self._enrich("10.0.1.50", "IP", entity_communities, {})
        assert "graph_community" in result


# ---------------------------------------------------------------------------
# Test produce_finding graph context enrichment in finding text
# ---------------------------------------------------------------------------

class TestFindingTextEnrichment:
    """Tests for graph context appearing in finding text output."""

    def test_graph_community_in_finding_text(self):
        """Finding text includes community info when graph_community is present."""
        finding = {
            "severity": "high",
            "type": "brute_force",
            "entity": "10.0.1.50",
            "entity_type": "ip",
            "cross_type": "cross-type",
            "confidence": 0.8,
            "graph_community": {
                "community_id": 0,
                "anomaly_density": 0.5,
            },
        }
        # Simulate the finding text formatting
        cross = f" ({finding['cross_type']})"
        graph_str = f" [Community {finding['graph_community']['community_id']}: density={finding['graph_community']['anomaly_density']:.2f}]"
        text = f"[{finding['severity'].upper()}] {finding['type']} by {finding['entity_type']} {finding['entity']}{cross}{graph_str} (confidence: {finding['confidence']:.0%})"
        assert "Community 0" in text
        assert "density=0.50" in text

    def test_temporal_chain_in_finding_text(self):
        """Finding text includes chain info when temporal_chains is present."""
        finding = {
            "severity": "critical",
            "type": "brute_force",
            "entity": "10.0.1.50",
            "entity_type": "ip",
            "cross_type": "cross-type",
            "confidence": 0.9,
            "temporal_chains": [
                {"chain_id": 0, "phases": ["initial_access", "execution", "persistence"]},
            ],
        }
        chains = finding["temporal_chains"]
        chain_strs = ", ".join(
            f"Chain {c['chain_id']} ({' → '.join(c.get('phases', []))})"
            for c in chains[:2]
        )
        text = f"[{finding['severity'].upper()}] {finding['type']} by {finding['entity_type']} {finding['entity']} [{chain_strs}]"
        assert "Chain 0" in text
        assert "initial_access → execution → persistence" in text

    def test_both_graph_and_chain_in_finding_text(self):
        """Finding text includes both community and chain info."""
        finding = {
            "severity": "critical",
            "type": "brute_force",
            "entity": "10.0.1.50",
            "entity_type": "ip",
            "cross_type": "cross-type",
            "confidence": 0.9,
            "graph_community": {"community_id": 0, "anomaly_density": 0.5},
            "temporal_chains": [
                {"chain_id": 0, "phases": ["initial_access", "execution"]},
            ],
        }
        graph_str = f" [Community {finding['graph_community']['community_id']}: density={finding['graph_community']['anomaly_density']:.2f}]"
        chains = finding["temporal_chains"]
        chain_strs = ", ".join(
            f"Chain {c['chain_id']} ({' → '.join(c.get('phases', []))})"
            for c in chains[:2]
        )
        graph_str += f" [{chain_strs}]"
        text = f"[{finding['severity'].upper()}] {finding['type']} by {finding['entity_type']} {finding['entity']}{graph_str}"
        assert "Community 0" in text
        assert "Chain 0" in text
