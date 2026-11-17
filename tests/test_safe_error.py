"""Tests for safe_error — error message sanitization."""

from unittest.mock import patch

import pytest

from nabla.safe_error import safe_error


class TestSafeError:
    """Tests for safe_error function."""

    @patch("nabla.safe_error.logger")
    def test_generic_error_returns_sanitized_message(self, mock_logger):
        """Non-ValueError exceptions get generic messages."""
        e = RuntimeError("database connection to db.admin.internal:5432 failed")
        result = safe_error(e, "Export")
        assert "db.admin.internal" not in result
        assert "Export failed" in result
        assert "check server logs" in result

    @patch("nabla.safe_error.logger")
    def test_value_error_passes_through(self, mock_logger):
        """ValueError messages are user-actionable and passed through."""
        e = ValueError("Invalid log type: 'fakedns', must be one of auth, network, dns, endpoint")
        result = safe_error(e, "Pipeline")
        assert "Invalid log type" in result
        assert "fakedns" in result

    @patch("nabla.safe_error.logger")
    def test_value_error_truncated_at_200(self, mock_logger):
        """ValueError message is truncated at 200 characters."""
        e = ValueError("x" * 300)
        result = safe_error(e, "Pipeline")
        assert len(result) == 200

    @patch("nabla.safe_error.logger")
    def test_generic_error_hides_file_paths(self, mock_logger):
        """Generic errors don't leak file paths."""
        e = FileNotFoundError("/etc/shadow not found")
        result = safe_error(e, "Import")
        assert "/etc/shadow" not in result
        assert "Import failed" in result

    @patch("nabla.safe_error.logger")
    def test_generic_error_hides_connection_strings(self, mock_logger):
        """Generic errors don't leak connection details."""
        e = ConnectionError("Connection refused: postgres://admin:pass@10.0.0.1:5432")
        result = safe_error(e, "Bootstrap")
        assert "postgres://" not in result
        assert "admin:pass" not in result
        assert "10.0.0.1" not in result

    @patch("nabla.safe_error.logger")
    def test_logs_real_error(self, mock_logger):
        """The real error is logged server-side."""
        e = RuntimeError("sensitive internal details")
        safe_error(e, "Pipeline")
        mock_logger.error.assert_called_once()
        assert "sensitive internal details" in str(mock_logger.error.call_args)

    @patch("nabla.safe_error.logger")
    def test_custom_context(self, mock_logger):
        """Context is used in the generic message."""
        e = OSError("disk full")
        result = safe_error(e, "Chat stream")
        assert "Chat stream failed" in result

    @patch("nabla.safe_error.logger")
    def test_key_error_sanitized(self, mock_logger):
        """KeyError doesn't leak internal dict structure."""
        e = KeyError("api_secret_key")
        result = safe_error(e, "Config")
        assert "api_secret_key" not in result
        assert "Config failed" in result
