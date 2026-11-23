"""Pipeline correlation — correlate anomalies into findings and generate explainability evidence."""

from __future__ import annotations

from dataclasses import dataclass, field

from letta_client import Letta

from nabla.log import get_logger
from nabla.pipeline.helpers import _read_supervisor_blocks

logger = get_logger("pipeline.correlation")


@dataclass
class CorrelationResult:
    """Result from the correlation step."""
    findings_text: str = ""
    timeline_text: str = ""
    findings: list[dict] = field(default_factory=list)
    correlations: list[dict] = field(default_factory=list)
    attack_lookup: dict = field(default_factory=dict)
    explanation_text: str = ""
    findings_count: int = 0
    findings_shown: int = 0
    shown_keys: list[tuple[str, str]] = field(default_factory=list)


def run_correlation(
    client: Letta,
    agents: dict[str, str],
    anomalies: list[dict],
    graph_context_text: str,
    provenance_graph=None,
    provenance_communities=None,
    provenance_anomalies: list[dict] | None = None,
    entity_profiles=None,
) -> CorrelationResult:
    """Step 3: Threat Correlation — deterministic (no LLM).

    Args:
        client: Letta client instance.
        agents: Dict mapping role → agent_id.
        anomalies: List of anomaly dicts from detection.
        graph_context_text: Formatted graph context string.
        provenance_graph: Provenance graph object (or None).
        provenance_communities: Community assignments (or None).
        provenance_anomalies: Provenance anomaly list (or None).

    Returns:
        CorrelationResult with findings, timeline, and evidence.
    """
    from nabla.correlation import run_correlation as _run_correlation

    result = CorrelationResult()
    logger.info("Threat Correlation: correlating %d anomalies...", len(anomalies))

    # Read attack_mapping block for ATT&CK enrichment
    blocks = _read_supervisor_blocks(client, agents["supervisor"], "attack_mapping")
    attack_mapping_text = blocks["attack_mapping"]

    result.findings_text, result.timeline_text, result.findings, result.correlations, result.attack_lookup, findings_shown = _run_correlation(
        entity_profiles=entity_profiles,
        anomalies=anomalies,
        graph_context_text=graph_context_text,
        attack_mapping_text=attack_mapping_text,
    )

    # F-1 (round 11): the count is a VALUE from the correlation step —
    # never regexed out of block text. findings_count is the TRUE count
    # (what the run record reports); findings_shown is how many reached
    # the review prompt; shown_keys identifies WHICH findings were shown
    # so incidents beyond the cap can be marked "capped", not "invalid".
    result.findings_count = len(result.findings)
    result.findings_shown = len(findings_shown)
    result.shown_keys = [
        (f.get("entity", ""), f.get("type", "")) for f in findings_shown
    ]

    # Generate explainability evidence + counterfactuals
    if result.findings:
        from nabla.explain import explain_findings
        anomaly_nodes = set()
        community_dicts = None
        if provenance_graph is not None:
            for a in anomalies:
                user = a.get("user", "")
                ip = a.get("source_ip", "")
                if user:
                    anomaly_nodes.add(("user", user.lower()))
                if ip:
                    anomaly_nodes.add(("ip", ip.lower()))
            if provenance_communities is not None:
                from nabla.provenance import build_community_dicts
                community_dicts = build_community_dicts(
                    provenance_graph, provenance_communities, provenance_anomalies or [],
                )
        try:
            result.explanation_text = explain_findings(
                findings=result.findings,
                anomalies=anomalies,
                correlations=result.correlations,
                attack_lookup=result.attack_lookup,
                graph=provenance_graph,
                communities=community_dicts,
                anomaly_nodes=anomaly_nodes,
            )
        except Exception as e:
            logger.warning("Explainability layer failed (non-fatal): %s", e)

    # Write findings + timeline + evidence to the threat_findings block
    combined_text = result.findings_text + "\n\n--- TIMELINE ---\n" + result.timeline_text + result.explanation_text
    client.agents.blocks.update(
        agent_id=agents["supervisor"],
        block_label="threat_findings",
        value=combined_text,
    )

    logger.info("Threat Correlation completed — %d findings", result.findings_count)
    return result
