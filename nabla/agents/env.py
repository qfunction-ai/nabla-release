"""Agent configuration overrides via the Letta SDK client.

MR-2 (migration review): ONE authenticated HTTP path to Letta. These two
overrides were raw httpx.patch calls with no auth header — a 401 under
v0.16.38 secure mode that killed bootstrap, and the pattern that caused
it (a raw call skipping the client's authentication). letta-client
1.10.3 exposes both fields on agents.update, so they route through the
shared client: base URL, timeout and authentication all come from one
place, and the no-raw-Letta-HTTP guard (tests/test_no_raw_letta_http.py)
keeps the pattern dead.
"""

from nabla.client import get_client
from nabla.log import get_logger

logger = get_logger("env")


def set_agent_compaction_model(agent_id: str, model: str) -> None:
    """Override the compaction model for an agent.

    Works around Letta bug #3270: compaction uses a different tokenizer
    than the inference model, causing incorrect token counting and
    premature context truncation. Setting compaction_settings.model
    to the same model handle fixes this.

    The SDK serializes exactly what the old raw patch sent —
    {"compaction_settings": {"model": model}} — witnessed on the wire
    (W3). Unpassed fields are omitted (Fern omit semantics), so this
    is a partial update that cannot wipe the agent (W4).
    """
    try:
        get_client().agents.update(
            agent_id=agent_id,
            compaction_settings={"model": model},
        )
    except Exception:
        logger.error(
            "Failed to set compaction model for agent %s", agent_id[:8],
            exc_info=True,
        )
        raise
    logger.info("Set compaction model for agent %s to %s", agent_id[:8], model)


def fix_embedding_model_prefix(
    agent_id: str,
    correct_model: str,
    embedding_endpoint: str = "http://host.docker.internal:11434/v1",
) -> None:
    """Fix the embedding model name to remove the 'ollama/' prefix.

    The Letta SDK adds 'ollama/' to the model handle when creating agents,
    but Ollama's /v1/embeddings endpoint expects just the model name
    (e.g., 'embeddinggemma:latest', not 'ollama/embeddinggemma:latest').
    This causes 404 errors when creating passages.

    letta-client 1.10.3 exposes embedding_config on agents.update, so the
    raw REST call is gone; the payload is byte-identical (W3).
    """
    try:
        get_client().agents.update(
            agent_id=agent_id,
            embedding_config={
                "embedding_model": correct_model,
                "embedding_endpoint": embedding_endpoint,
                "embedding_endpoint_type": "ollama",
                "embedding_dim": 4096,
            },
        )
    except Exception:
        logger.error(
            "Failed to fix embedding model for agent %s", agent_id[:8],
            exc_info=True,
        )
        raise
    logger.info("Fixed embedding model for agent %s to %s", agent_id[:8], correct_model)
