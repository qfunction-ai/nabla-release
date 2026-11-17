"""Pipeline detection — anomaly detection, GCN-LOF, provenance, and temporal analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from letta_client import Letta

from nabla.log import get_logger
from nabla.pipeline.helpers import (
    _read_baseline_host_procs,
    _read_supervisor_blocks,
)
from nabla.pipeline.env_context import (
    _auto_detect_network_ranges,
    _auto_detect_new_accounts,
    _load_environment_context,
    _format_env_context_block,
)

if TYPE_CHECKING:
    from nabla.baselines import EntityProfileStore
    from nabla.connectors.base import Watchlist

logger = get_logger("pipeline.detection")


@dataclass
class DetectionResult:
    """Result from the detection step."""
    anomalies: list[dict] = field(default_factory=list)
    baselines: dict = field(default_factory=dict)
    gcn_lof_anomalies: list[dict] = field(default_factory=list)
    provenance_anomalies: list[dict] = field(default_factory=list)
    provenance_graph: object = None
    provenance_communities: object = None
    temporal_anomalies: list[dict] = field(default_factory=list)
    exfiltration_count: int = 0
    temporal_chains: list = field(default_factory=list)
    graph_context_text: str = ""
    anomalous_entities: set[str] = field(default_factory=set)
    env_context: dict = field(default_factory=dict)
    auto_ranges: list[str] = field(default_factory=list)
    auto_new_accounts: dict[str, str] = field(default_factory=dict)
    entity_profiles: object = None
    sys_state: dict = field(default_factory=dict)
    phase: str = "detection"
    warm_up_info: object = None
    explanation_text: str = ""


def run_detection(
    client: Letta,
    agents: dict[str, str],
    settings,
    all_entries: list[dict],
    watchlist: Watchlist,
    siem_entries_ingested: int = 0,
    effective_source: str = "synthetic",
    skip_graph: bool = False,
) -> DetectionResult:
    """Step 2: Anomaly Detection — deterministic analysis (no LLM).

    Args:
        client: Letta client instance.
        agents: Dict mapping role → agent_id.
        settings: Application settings.
        all_entries: All log entries from ingestion.
        watchlist: Watchlist for detection.
        siem_entries_ingested: Count of entries from real SIEM.
        effective_source: The resolved ingestion source.

    Returns:
        DetectionResult with all anomalies and context.
    """
    result = DetectionResult()
    logger.info("Anomaly Detection: analyzing %d log entries...", len(all_entries))

    from nabla.detection import (
        detect_anomalies, parse_rl_thresholds, parse_lolbin_block,
        format_anomaly_queue,
    )

    # Read RL thresholds from shared block
    blocks = _read_supervisor_blocks(client, agents["supervisor"], "rl_thresholds", "lolbin_db")
    rl_thresholds_text = blocks["rl_thresholds"]
    lolbin_db_text = blocks["lolbin_db"]

    thresholds = parse_rl_thresholds(rl_thresholds_text)
    lolbin_sigs = parse_lolbin_block(lolbin_db_text)

    # Read historical baseline for unusual-process detection
    baseline_host_procs = _read_baseline_host_procs()

    # Load entity baseline profiles
    try:
        from nabla.baselines import EntityProfileStore
        result.entity_profiles = EntityProfileStore(settings.entity_profiles_file)
        logger.info(
            "Loaded entity profiles: %d users, %d hosts, %d IPs",
            len(result.entity_profiles.users), len(result.entity_profiles.hosts), len(result.entity_profiles.ips),
        )
    except Exception as e:
        logger.warning("Failed to load entity profiles (non-fatal): %s", e)

    # Compute warm-up summary
    try:
        from nabla.system_state import warm_up_summary
        result.warm_up_info = warm_up_summary(result.entity_profiles)
    except Exception as e:
        logger.warning("attack index load failed (non-fatal): %s", e, exc_info=True)

    # Build attack tool name index from STIX bundle
    attack_tool_index = None
    try:
        from nabla.attack import download_attack_bundle, build_tool_name_index
        stix_path = download_attack_bundle(settings.data_dir)
        attack_tool_index = build_tool_name_index(stix_path)
        logger.info("Loaded attack tool index: %d entries", len(attack_tool_index))
    except Exception as e:
        logger.warning("Failed to load attack tool index (using fallback): %s", e)

    # Load environment context
    result.env_context = _load_environment_context(settings.effective_env_context_path)
    user_declared_new = result.env_context.get("new_accounts", set())

    # Auto-detect new accounts
    result.auto_new_accounts = _auto_detect_new_accounts(
        all_entries,
        entity_profiles=result.entity_profiles,
        grace_days=settings.new_account_grace_days,
    )

    # Merge user-declared + auto-detected
    new_accounts = user_declared_new | set(result.auto_new_accounts.keys())
    if new_accounts:
        logger.info(
            "New accounts (grace period): %d user-declared, %d auto-detected, %d total",
            len(user_declared_new), len(result.auto_new_accounts), len(new_accounts),
        )

    # Load system phase state
    from nabla.system_state import load_system_state, record_ingestion, save_system_state
    result.sys_state = load_system_state(settings.system_state_file)
    result.phase = result.sys_state.get("phase", "detection")
    if effective_source in ("splunk", "sumologic") and siem_entries_ingested > 0:
        result.sys_state = record_ingestion(
            result.sys_state,
            effective_source,
            entry_timestamps=[e.get("timestamp") for e in all_entries if e.get("timestamp")],
        )
        save_system_state(settings.system_state_file, result.sys_state)
        result.phase = result.sys_state["phase"]
    logger.info("System phase: %s", result.phase)

    # Run all detection methods
    result.anomalies, result.baselines = detect_anomalies(
        entries=all_entries,
        thresholds=thresholds,
        watchlist=watchlist,
        lolbin_sigs=lolbin_sigs,
        baseline_host_procs=baseline_host_procs,
        attack_tool_index=attack_tool_index,
        entity_profiles=result.entity_profiles,
        new_accounts=new_accounts,
        phase=result.phase,
    )

    # GCN-LOF relational scoring (skippable: nabla ingest --no-graph bulk mode)
    if not skip_graph and len(all_entries) >= 3:
        try:
            from nabla.gcn_lof import GCNLOFDetector
            gcn_lof = GCNLOFDetector.load(settings.gcn_lof_model_file)
            gcn_lof.alpha = thresholds.get("gcn_lof_alpha", 0.5)
            gcn_lof_threshold = thresholds.get("gcn_lof_threshold", 0.75)
            result.gcn_lof_anomalies = gcn_lof.detect(
                all_entries,
                baselines=result.baselines,
                threshold=gcn_lof_threshold,
                _existing_anomalies=result.anomalies,
            )
            result.anomalies.extend(result.gcn_lof_anomalies)
            gcn_lof.save(settings.gcn_lof_model_file)
            logger.info("GCN-LOF: %d relational anomalies detected", len(result.gcn_lof_anomalies))
        except Exception as e:
            logger.warning("GCN-LOF detection failed (non-fatal): %s", e)

    # Provenance Graph Analysis (skippable: --no-graph)
    if not skip_graph and len(all_entries) >= 3:
        try:
            from nabla.provenance import detect_provenance_anomalies_with_context
            provenance_thresholds = {
                "provenance_anomaly_density": thresholds.get("provenance_anomaly_density", 0.3),
                "provenance_min_community_size": thresholds.get("provenance_min_community_size", 3),
            }
            (
                result.provenance_anomalies,
                result.provenance_graph,
                result.provenance_communities,
            ) = detect_provenance_anomalies_with_context(
                entries=all_entries,
                existing_anomalies=result.anomalies,
                thresholds=provenance_thresholds,
            )
            result.anomalies.extend(result.provenance_anomalies)
            logger.info("Provenance: %d anomalous communities detected", len(result.provenance_anomalies))
        except Exception as e:
            logger.warning("Provenance detection failed (non-fatal): %s", e)

    # Temporal Correlation Engine (skippable: --no-graph)
    if not skip_graph and len(result.anomalies) >= 2:
        try:
            from nabla.temporal import detect_temporal_chains_with_context
            temporal_thresholds = {
                "temporal_chain_window_minutes": thresholds.get("temporal_chain_window_minutes", 30),
                "temporal_min_chain_length": thresholds.get("temporal_min_chain_length", 3),
            }
            result.temporal_anomalies, result.temporal_chains = detect_temporal_chains_with_context(
                all_entries,
                result.anomalies,
                temporal_thresholds,
            )
            result.anomalies.extend(result.temporal_anomalies)
            logger.info("Temporal: %d chains detected", len(result.temporal_anomalies))
        except Exception as e:
            logger.warning("Temporal correlation failed (non-fatal): %s", e)

    # Data Exfiltration Detection
    if len(all_entries) >= 2:
        try:
            from nabla.exfiltration import detect_exfiltration
            exfil_anomalies = detect_exfiltration(
                entries=all_entries,
                entity_profiles=result.entity_profiles,
                thresholds=thresholds,
            )
            result.exfiltration_count = len(exfil_anomalies)
            if exfil_anomalies:
                result.anomalies.extend(exfil_anomalies)
                logger.info("Exfiltration: %d anomalies detected", len(exfil_anomalies))
        except Exception as e:
            logger.warning("Exfiltration detection failed (non-fatal): %s", e)

    # Collect anomalous entities and attach entity context
    entity_facts = result.env_context.get("entities", {})
    if entity_facts:
        for a in result.anomalies:
            user = a.get("user", "")
            host = a.get("host", "")
            ip = a.get("source_ip", "")
            if user:
                result.anomalous_entities.add(user)
            if host:
                result.anomalous_entities.add(host)
            if ip:
                result.anomalous_entities.add(ip)
            if user and user in entity_facts:
                a["entity_context"] = entity_facts[user]
            elif host and host in entity_facts:
                a["entity_context"] = entity_facts[host]

    # Write anomaly_queue block
    queue_text = format_anomaly_queue(result.anomalies)
    client.agents.blocks.update(
        agent_id=agents["supervisor"],
        block_label="anomaly_queue",
        value=queue_text,
    )

    # Write graph_context block
    _write_graph_context_block(client, agents, result)

    # Write environment_context block
    _write_environment_context_block(client, agents, result, all_entries=all_entries)

    # Write system_phase block
    _write_system_phase_block(client, agents, result)

    logger.info(
        "Anomaly Detection completed — %d anomalies "
        "(%d via GCN-LOF, %d via provenance, %d via temporal)",
        len(result.anomalies), len(result.gcn_lof_anomalies),
        len(result.provenance_anomalies), len(result.temporal_anomalies),
    )

    return result


def _write_graph_context_block(client: Letta, agents: dict, result: DetectionResult) -> None:
    """Write graph_context block to supervisor agent."""
    try:
        graph_context_parts = []
        if result.provenance_graph is not None and result.provenance_communities is not None:
            from nabla.provenance import format_provenance_summary
            graph_context_parts.append(format_provenance_summary(
                result.provenance_graph, result.provenance_communities, result.provenance_anomalies,
            ))
        if result.temporal_chains:
            from nabla.temporal import format_temporal_summary
            graph_context_parts.append(format_temporal_summary(result.temporal_chains))
        if graph_context_parts:
            result.graph_context_text = "\n\n".join(graph_context_parts)
            _MAX_GRAPH_CONTEXT = 10_000
            if len(result.graph_context_text) > _MAX_GRAPH_CONTEXT:
                logger.warning(
                    "Graph context block too large (%d bytes), truncating to %d",
                    len(result.graph_context_text), _MAX_GRAPH_CONTEXT,
                )
                result.graph_context_text = result.graph_context_text[:_MAX_GRAPH_CONTEXT] + "\n[TRUNCATED]"
            client.agents.blocks.update(
                agent_id=agents["supervisor"],
                block_label="graph_context",
                value=result.graph_context_text,
            )
            logger.info("Graph context block written (%d bytes)", len(result.graph_context_text))
        else:
            client.agents.blocks.update(
                agent_id=agents["supervisor"],
                block_label="graph_context",
                value="Graph context: no provenance or temporal data available",
            )
    except Exception as e:
        logger.warning("Failed to write graph_context block (non-fatal): %s", e)


def _write_environment_context_block(client: Letta, agents: dict, result: DetectionResult, all_entries: list[dict] | None = None) -> None:
    """Write environment_context block to supervisor agent."""
    try:
        all_entries = all_entries or []
        result.auto_ranges = _auto_detect_network_ranges(all_entries) if all_entries else []

        # Per-entity this-run stats for the baseline section (UI2b)
        run_stats: dict[str, dict] = {}
        if all_entries:
            from collections import defaultdict

            events_by_entity: dict[str, int] = defaultdict(int)
            ips_by_entity: dict[str, set] = defaultdict(set)
            offhours_by_entity: dict[str, int] = defaultdict(int)
            for e in all_entries:
                ent = e.get("user", "") or e.get("entity", "")
                if not ent:
                    continue
                events_by_entity[ent] += 1
                ip = e.get("source_ip") or e.get("src_ip")
                if ip:
                    ips_by_entity[ent].add(ip)
                ts = str(e.get("timestamp", ""))
                if ts[11:13].isdigit():
                    hour = int(ts[11:13])
                    if hour < 6 or hour >= 22:
                        offhours_by_entity[ent] += 1
            for ent, count in events_by_entity.items():
                if ent in (result.anomalous_entities or set()):
                    run_stats[ent] = {
                        "events": count,
                        "new_ips": len(ips_by_entity.get(ent, set())),
                        "off_hours": offhours_by_entity.get(ent, 0),
                    }

        risk_store = None
        try:
            from nabla.risk import EntityRiskStore
            from nabla.config import get_settings
            risk_store = EntityRiskStore(get_settings().entity_risk_scores_file)
        except Exception as e:
            logger.warning("block write failed (non-fatal): %s", e, exc_info=True)

        env_block_text = _format_env_context_block(
            result.env_context,
            result.auto_ranges,
            auto_new_accounts=result.auto_new_accounts,
            anomalous_entities=result.anomalous_entities,
            entity_profiles=result.entity_profiles,
            run_stats=run_stats,
            risk_store=risk_store,
        )
        client.agents.blocks.update(
            agent_id=agents["supervisor"],
            block_label="environment_context",
            value=env_block_text,
        )
        entity_facts = result.env_context.get("entities", {})
        logger.info(
            "Environment context block written (%d auto-ranges, %d new accounts, %d entity contexts)",
            len(result.auto_ranges), len(result.auto_new_accounts),
            len(result.anomalous_entities & set(entity_facts.keys())),
        )
    except Exception as e:
        logger.warning("Failed to write environment_context block (non-fatal): %s", e)


def _write_system_phase_block(client: Letta, agents: dict, result: DetectionResult) -> None:
    """Write system_phase block to supervisor agent."""
    try:
        from nabla.system_state import format_system_phase_block
        phase_block_text = format_system_phase_block(result.sys_state, result.warm_up_info)
        client.agents.blocks.update(
            agent_id=agents["supervisor"],
            block_label="system_phase",
            value=phase_block_text,
        )
        logger.info("System phase block written (%s)", result.phase)
    except Exception as e:
        logger.warning("Failed to write system_phase block (non-fatal): %s", e)
