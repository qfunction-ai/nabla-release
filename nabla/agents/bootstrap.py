"""Bootstrap — create the full Nabla system (blocks, agents)."""

from letta_client import Letta

from nabla.blocks import get_or_create_shared_blocks
from nabla.agents.supervisor import create_supervisor
from nabla.config import get_settings
from nabla.agents.env import set_agent_compaction_model, fix_embedding_model_prefix  # noqa: F401
from nabla.log import get_logger

logger = get_logger("bootstrap")


def bootstrap(client: Letta | None = None) -> dict[str, str]:
    """Create the full Nabla system. Returns {role: agent_id}.

    Order matters: blocks → supervisor agent.
    """
    if client is None:
        from nabla.client import get_client
        client = get_client()

    settings = get_settings()

    # 1. Shared blocks
    logger.info("Creating shared blocks...")
    block_ids = get_or_create_shared_blocks(client)

    # 1b. Populate attack_mapping block with ATT&CK technique data
    try:
        from nabla.attack import download_attack_bundle, build_attack_index, format_attack_block
        data_dir = settings.data_dir
        stix_path = download_attack_bundle(data_dir)
        attack_index = build_attack_index(stix_path)
        attack_text = format_attack_block(attack_index)
        # Update the block with real ATT&CK data
        client.blocks.update(block_id=block_ids["attack_mapping"], value=attack_text)
        logger.info("Populated attack_mapping block with %d bytes of ATT&CK data", len(attack_text))
    except Exception as e:
        logger.warning("Could not populate attack_mapping block: %s (findings will lack ATT&CK enrichment)", e)
        attack_index = {}

    # 1c. Populate lolbin_db block with LOLBAS + GTFOBins data
    lolbin_index = {}
    try:
        from nabla.lolbin_db import fetch_lolbin_data, build_lolbin_index, format_lolbin_block
        lolbin_data = fetch_lolbin_data(data_dir)
        lolbin_index = build_lolbin_index(lolbin_data)
        lolbin_text = format_lolbin_block(lolbin_index)
        client.blocks.update(block_id=block_ids["lolbin_db"], value=lolbin_text)
        logger.info("Populated lolbin_db block with %d bytes (%d Windows, %d Unix entries)",
                    len(lolbin_text), len(lolbin_index["windows"]), len(lolbin_index["unix"]))
    except Exception as e:
        logger.warning("Could not populate lolbin_db block: %s (LOLBIN detection will use fallback signatures)", e)

    # 1d. Enrich attack_mapping with LOLBIN-specific technique IDs
    if attack_index and lolbin_index:
        try:
            from nabla.attack import enrich_lolbin_attack_mapping
            attack_index = enrich_lolbin_attack_mapping(attack_index, lolbin_index)
            attack_text = format_attack_block(attack_index)
            client.blocks.update(block_id=block_ids["attack_mapping"], value=attack_text)
            logger.info("Enriched attack_mapping with LOLBIN-specific technique IDs")
        except Exception as e:
            logger.warning("Could not enrich attack_mapping with LOLBIN IDs: %s", e)

    # Blocks the supervisor agent needs access to
    supervisor_block_ids = [
        block_ids["ingestion_status"],
        block_ids["threat_findings"],
        block_ids["anomaly_queue"],
        block_ids["rl_thresholds"],
        block_ids["lolbin_db"],
        block_ids["graph_context"],
        block_ids["attack_mapping"],
        block_ids["environment_context"],
        block_ids["system_phase"],
    ]

    # 2. Supervisor agent (reads blocks directly, no tools needed)
    logger.info("Creating supervisor agent...")
    supervisor_id = create_supervisor(
        client=client,
        model=settings.llm_model,
        embedding=settings.embedding_model,
        block_ids=supervisor_block_ids,
        letta_base_url=settings.effective_tool_url,
        embedding_endpoint=settings.embedding_endpoint,
    )

    # 3. Letta bug workarounds — set compaction model to match inference model
    # Works around bug #3270: compaction tokenizer mismatch
    compaction_model = settings.letta_compaction_model or settings.llm_model
    logger.info("Setting compaction model workaround (%s)...", compaction_model)
    set_agent_compaction_model(supervisor_id, compaction_model, letta_base_url=settings.letta_base_url)

    # 4. Fix embedding model prefix — Letta SDK adds 'ollama/' but Ollama expects bare name
    # Works around: Ollama /v1/embeddings returns 404 for 'ollama/embeddinggemma:latest'
    embedding_model = settings.embedding_model
    if embedding_model:
        # Always strip 'ollama/' prefix — Ollama doesn't understand it
        if embedding_model.startswith("ollama/"):
            embedding_model = embedding_model[len("ollama/"):]
            logger.info("Stripped 'ollama/' prefix from embedding model: %s", embedding_model)
        logger.info("Fixing embedding model prefix (%s)...", embedding_model)
        fix_embedding_model_prefix(
            supervisor_id, embedding_model,
            embedding_endpoint=settings.embedding_endpoint,
            letta_base_url=settings.letta_base_url,
        )

    logger.info("Bootstrap complete — supervisor: %s", supervisor_id[:8])

    return {
        "supervisor": supervisor_id,
    }


def teardown(client: Letta | None = None) -> int:
    """Delete all Nabla agents, tools, and shared blocks. Returns count deleted."""
    if client is None:
        from nabla.client import get_client
        client = get_client()

    deleted = 0

    # Delete agents
    logger.info("Tearing down Nabla agents...")
    agents = client.agents.list(limit=100)
    for agent in agents:
        if agent.name and agent.name.startswith("nabla-"):
            try:
                client.agents.delete(agent.id)
                deleted += 1
            except Exception:
                logger.debug("Could not delete agent %s (may already be gone)", agent.id)

    # Delete tools (so re-bootstrap gets fresh source code)
    from nabla.tools.register import LEGACY_TOOL_NAMES
    all_tool_names = LEGACY_TOOL_NAMES
    tools = client.tools.list(limit=100)
    for tool in tools:
        if tool.name in all_tool_names:
            try:
                client.tools.delete(tool.id)
                deleted += 1
            except Exception:
                logger.debug("Could not delete tool %s (may already be gone)", tool.id)

    # Delete shared blocks + the fork's canary block (auto-attached to every
    # agent by letta-local; deleting here keeps teardown/bootstrap cycles clean)
    from nabla.blocks import SHARED_BLOCKS
    for label in list(SHARED_BLOCKS) + ["__canary__"]:
        blocks = client.blocks.list(label=label, limit=100)
        for block in blocks:
            try:
                client.blocks.delete(block.id)
                deleted += 1
            except Exception:
                logger.debug("Could not delete block %s (may already be gone)", block.id)

    logger.info("Deleted %d resources.", deleted)
    return deleted
