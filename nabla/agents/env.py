"""Agent configuration overrides via the Letta REST API."""

import httpx

from nabla.log import get_logger

logger = get_logger("env")


def set_agent_compaction_model(
    agent_id: str,
    model: str,
    letta_base_url: str = "http://localhost:8284",
) -> None:
    """Override the compaction model for an agent.

    Works around Letta bug #3270: compaction uses a different tokenizer
    than the inference model, causing incorrect token counting and
    premature context truncation. Setting compaction_settings.model
    to the same model handle fixes this.
    """
    resp = httpx.patch(
        f"{letta_base_url}/v1/agents/{agent_id}",
        json={"compaction_settings": {"model": model}},
        timeout=30.0,
    )
    if resp.status_code >= 400:
        logger.error(
            "Failed to set compaction model for agent %s: %s",
            agent_id[:8], resp.text[:200],
        )
        resp.raise_for_status()
    else:
        logger.info("Set compaction model for agent %s to %s", agent_id[:8], model)


def fix_embedding_model_prefix(
    agent_id: str,
    correct_model: str,
    embedding_endpoint: str = "http://host.docker.internal:11434/v1",
    letta_base_url: str = "http://localhost:8284",
) -> None:
    """Fix the embedding model name to remove the 'ollama/' prefix.

    The Letta SDK adds 'ollama/' to the model handle when creating agents,
    but Ollama's /v1/embeddings endpoint expects just the model name
    (e.g., 'embeddinggemma:latest', not 'ollama/embeddinggemma:latest').
    This causes 404 errors when creating passages.

    Must be called after agent creation via the REST API since the SDK
    doesn't expose a way to set the raw embedding_model string.
    """
    resp = httpx.patch(
        f"{letta_base_url}/v1/agents/{agent_id}",
        json={
            "embedding_config": {
                "embedding_model": correct_model,
                "embedding_endpoint": embedding_endpoint,
                "embedding_endpoint_type": "ollama",
                "embedding_dim": 4096,
            },
        },
        timeout=30.0,
    )
    if resp.status_code >= 400:
        logger.error(
            "Failed to fix embedding model for agent %s: %s",
            agent_id[:8], resp.text[:200],
        )
        resp.raise_for_status()
    else:
        logger.info("Fixed embedding model for agent %s to %s", agent_id[:8], correct_model)
