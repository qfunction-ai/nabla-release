"""Synthetic log connector — wraps the existing synthetic log generator.

This connector produces the same synthetic logs as the original pipeline,
preserving the dev/testing workflow.
"""

from __future__ import annotations

from typing import Any

from nabla.connectors.base import ConnectorConfig, Watchlist
from nabla.log import get_logger

logger = get_logger("connectors.synthetic")


class SyntheticConnector:
    """Generate synthetic security logs for testing."""

    def __init__(self, config: ConnectorConfig) -> None:
        self.config = config
        self._count = 20  # default per type

    def set_count(self, count: int) -> None:
        """Set the number of logs to generate per type."""
        self._count = count

    def fetch_logs(
        self,
        watchlist: Watchlist,
        log_type: str,
        since: str | None,
        until: str | None,
    ) -> list[dict[str, Any]]:
        """Generate synthetic logs for the given type.

        Note: watchlist and since/until are ignored for synthetic generation.
        All logs are generated fresh each time.
        """
        from nabla.ingest import generate_synthetic_logs

        logger.debug("Generating %d synthetic %s logs", self._count, log_type)
        logs = generate_synthetic_logs(log_type, count=self._count)
        logger.info("Generated %d synthetic %s logs", len(logs), log_type)
        return logs

    def available_log_types(self) -> list[str]:
        return ["auth", "network", "dns", "endpoint"]
