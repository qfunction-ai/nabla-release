"""Tests for rate limiting configuration."""

from unittest.mock import patch

import pytest

from nabla.rate_limit import limiter, reset_rate_limits


class TestRateLimiter:
    """Tests for the rate limiter configuration."""

    def test_limiter_exists(self):
        """Limiter is a valid slowapi Limiter instance."""
        from slowapi import Limiter
        assert isinstance(limiter, Limiter)

    def test_limiter_enabled(self):
        """Limiter is enabled by default."""
        assert limiter.enabled is True

    def test_default_limit(self):
        """Default limit is 30/minute."""
        limits = list(limiter._default_limits[0])
        assert len(limits) == 1
        assert "30 per 1 minute" in str(limits[0].limit)

    def test_reset_rate_limits(self):
        """Reset clears rate limit counters."""
        # This should not raise
        reset_rate_limits()

    def test_key_function(self):
        """Key function uses remote address."""
        from slowapi.util import get_remote_address
        assert limiter._key_func is get_remote_address
