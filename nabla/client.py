"""Singleton Letta client factory."""

import httpx
from letta_client import Letta

from nabla.config import get_settings
from nabla.log import get_logger

_client: Letta | None = None

# Long timeout — agent tool chains can take minutes
DEFAULT_TIMEOUT = httpx.Timeout(300.0, connect=10.0)

logger = get_logger("client")


def get_client() -> Letta:
    """Return a shared Letta client instance (created once)."""
    global _client
    if _client is None:
        settings = get_settings()
        logger.info("Creating Letta client (base_url=%s)", settings.letta_base_url)
        kwargs = {
            "base_url": settings.letta_base_url,
            "timeout": DEFAULT_TIMEOUT,
        }
        if settings.letta_api_key:
            kwargs["token"] = settings.letta_api_key
            logger.info("Using Letta API key authentication")
        _client = Letta(**kwargs)
    return _client


def reset_client() -> None:
    """Reset the singleton (useful for testing)."""
    global _client
    _client = None
