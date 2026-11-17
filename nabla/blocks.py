"""Shared memory blocks for multi-agent coordination."""

from letta_client import Letta

from nabla.log import get_logger

logger = get_logger("blocks")

# Block labels and their initial values
SHARED_BLOCKS = {
    "ingestion_status": "Status: idle\nLast batch: none\nRecord count: 0\nErrors: none",
    "anomaly_queue": "Pending anomalies: none",
    "threat_findings": "Confirmed threats: none",
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
