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


def find_block_by_label_exact(client: Letta, label: str) -> str | None:
    """Find the ONE block with this label. Loud on ambiguity (T-5).

    The legacy find_shared_blocks used limit=1 and silently took the
    first match — a duplicate-label block would shadow the real one
    with no trace. This helper is the replacement for single-block
    lookups outside bootstrap: zero matches returns None (callers own
    the degradation), exactly one returns its id, more than one RAISES
    because the block identity itself is ambiguous and any silent
    choice would be wrong some of the time.
    """
    blocks = list(client.blocks.list(label=label, limit=10))
    if not blocks:
        return None
    if len(blocks) > 1:
        raise RuntimeError(
            f"Multiple blocks share label '{label}' ({len(blocks)} found, ids: "
            + ", ".join(b.id for b in blocks)
            + ") — block identity is ambiguous; delete the stale one"
        )
    return blocks[0].id


def read_shared_block_value(client: Letta, label: str) -> str | None:
    """Read a shared block's current value by label (exact-match, loud).

    RR-2 companion: detection code reads lolbin_db by label, not via
    the supervisor agent's block list — the block is shared state, and
    after the detach no agent carries it in its window.
    """
    block_id = find_block_by_label_exact(client, label)
    if block_id is None:
        return None
    block = client.blocks.retrieve(block_id=block_id)
    return block.value if block is not None else None
