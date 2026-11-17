"""Rate limiting configuration for the Nabla API.

Uses slowapi with per-route limits to prevent abuse of
expensive endpoints (pipeline runs, LLM inference, file uploads).
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["30/minute"],
    enabled=True,
)


def reset_rate_limits() -> None:
    """Reset all rate limit counters.

    Called between test runs to prevent rate limits from interfering
    with sequential test execution.
    """
    limiter.reset()
