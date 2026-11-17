"""Shared memory blocks for multi-agent coordination."""

from letta_client import Letta

from nabla.log import get_logger

logger = get_logger("blocks")

# Block labels and their initial values
SHARED_BLOCKS = {
    "ingestion_status": "Status: idle\nLast batch: none\nRecord count: 0\nErrors: none",
    "anomaly_queue": "Pending anomalies: none",
    "threat_findings": "Confirmed threats: none",
    "rl_thresholds": "z_score_sigma: 2.0\nbrute_force_ratio: 0.5\noff_hours_count: 3\nmulti_ip_count: 3\nspike_multiplier: 3.0\nlolbin_sensitivity: 0.7\nparent_child_sensitivity: 0.7\ncritical_host_sensitivity: 0.7\nunusual_process_sensitivity: 0.5\naction_sequence_window_minutes: 30\ngcn_lof_alpha: 0.5\ngcn_lof_threshold: 0.75\nprovenance_anomaly_density: 0.3\nprovenance_min_community_size: 3\ntemporal_chain_window_minutes: 30\ntemporal_min_chain_length: 3",
    "graph_context": "Graph context: not yet analyzed",
    "attack_mapping": "ATT&CK mapping: not loaded",
    "lolbin_db": "LOLBIN database: not loaded",
    "environment_context": "Environment context: not configured",
    "system_phase": "Phase: BASELINE\nActive methods: signature-based only\nSuppressed: statistical methods (waiting for baselines)",
}


def find_shared_blocks(client: Letta) -> dict[str, str] | None:
    """Find existing shared blocks by label. Returns {label: block_id} or None if missing."""
    result = {}
    for label in SHARED_BLOCKS:
        blocks = client.blocks.list(label=label, limit=1)
        first = next(iter(blocks), None)
        if first is None:
            logger.debug("Block '%s' not found", label)
            return None
        result[label] = first.id
    logger.debug("Found %d existing blocks", len(result))
    return result


def get_or_create_shared_blocks(client: Letta) -> dict[str, str]:
    """Get existing shared blocks, creating only missing ones. Returns {label: block_id}."""
    existing = find_shared_blocks(client)
    if existing is not None and len(existing) == len(SHARED_BLOCKS):
        return existing

    # Create only the missing blocks
    if existing is None:
        existing = {}

    for label, value in SHARED_BLOCKS.items():
        if label not in existing:
            block = client.blocks.create(label=label, value=value)
            existing[label] = block.id
            logger.info("Created missing block '%s' (id=%s)", label, block.id)

    return existing
