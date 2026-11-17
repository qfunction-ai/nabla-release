"""Tests for security hardening — NABLA-008 through NABLA-013, VULN-001, VULN-002."""

import io
import os
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient


class TestUploadPathTraversal:
    """NABLA-008: Upload filename sanitization prevents path traversal."""

    def test_traversal_dotdot_stripped(self, app_client, temp_data_dir):
        """Filename with ../ is sanitized to just the basename."""
        content = b"test"
        resp = app_client.post(
            "/api/upload",
            files={"file": ("../../../etc/cron.d/malicious", io.BytesIO(content), "text/csv")},
        )
        assert resp.status_code == 200
        data = resp.json()
        # The saved file should be in the uploads dir, not /etc/cron.d/
        assert "/etc/" not in data["path"]
        assert "uploads" in data["path"]

    def test_traversal_backslash_stripped(self, app_client, temp_data_dir):
        """Filename with backslash path separators is sanitized."""
        content = b"test"
        resp = app_client.post(
            "/api/upload",
            files={"file": ("..\\..\\windows\\system32\\evil", io.BytesIO(content), "text/csv")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "system32" not in data["path"]
        assert "uploads" in data["path"]

    def test_traversal_absolute_path_stripped(self, app_client, temp_data_dir):
        """Absolute path in filename is sanitized to basename."""
        content = b"test"
        resp = app_client.post(
            "/api/upload",
            files={"file": ("/etc/passwd", io.BytesIO(content), "text/csv")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "/etc/" not in data["path"]

    def test_normal_filename_preserved(self, app_client, temp_data_dir):
        """Normal filenames are preserved after sanitization."""
        content = b"test"
        resp = app_client.post(
            "/api/upload",
            files={"file": ("logs.csv", io.BytesIO(content), "text/csv")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "logs.csv" in data["path"] or "logs_csv" in data["path"]

    def test_filename_with_spaces(self, app_client, temp_data_dir):
        """Spaces in filenames are replaced with underscores."""
        content = b"test"
        resp = app_client.post(
            "/api/upload",
            files={"file": ("my log file.csv", io.BytesIO(content), "text/csv")},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Spaces should be replaced with underscores
        assert " " not in os.path.basename(data["path"])

    def test_sanitize_filename_unit(self):
        """Unit test for _sanitize_filename helper."""
        from nabla.api.upload import _sanitize_filename

        assert _sanitize_filename("../../../etc/passwd") == "passwd"
        assert _sanitize_filename("/etc/shadow") == "shadow"
        assert _sanitize_filename("normal.log") == "normal.log"
        assert _sanitize_filename("my file.csv") == "my_file.csv"
        assert _sanitize_filename("...") == "upload"
        assert _sanitize_filename("") == "upload"
        assert _sanitize_filename("a/b/c") == "c"
        assert _sanitize_filename("..\\..\\windows\\system32\\evil") == "evil"


class TestSafeError:
    """NABLA-010: Error message sanitization prevents information disclosure."""

    def test_generic_error_message(self):
        """Non-ValueError exceptions get generic messages."""
        from nabla.safe_error import safe_error

        e = RuntimeError("Connection refused to postgres:5432 at /var/run/postgresql")
        msg = safe_error(e, "Bootstrap")
        assert "postgres" not in msg
        assert "/var/run" not in msg
        assert "5432" not in msg
        assert "failed" in msg

    def test_valueerror_passthrough(self):
        """ValueError messages are passed through (user-actionable)."""
        from nabla.safe_error import safe_error

        e = ValueError("Invalid log_type: 'fishing'")
        msg = safe_error(e, "Pipeline")
        assert "Invalid log_type" in msg
        assert "fishing" in msg

    def test_oserror_generic(self):
        """OSError messages are not leaked to clients."""
        from nabla.safe_error import safe_error

        e = OSError("Permission denied: /data/secret_keys.json")
        msg = safe_error(e, "Environment context write")
        assert "secret_keys" not in msg
        assert "failed" in msg

    def test_long_valueerror_truncated(self):
        """ValueError messages longer than 200 chars are truncated."""
        from nabla.safe_error import safe_error

        e = ValueError("x" * 500)
        msg = safe_error(e, "Test")
        assert len(msg) <= 200


class TestSecurityHeaders:
    """NABLA-012: Security headers are present on API responses."""

    def test_x_content_type_options(self, app_client):
        """X-Content-Type-Options: nosniff is set."""
        resp = app_client.get("/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self, app_client):
        """X-Frame-Options: DENY is set."""
        resp = app_client.get("/health")
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_referrer_policy(self, app_client):
        """Referrer-Policy is set."""
        resp = app_client.get("/health")
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"


class TestCORSRestriction:
    """NABLA-013: CORS only allows specific methods and headers."""

    def test_cors_preflight_allows_post(self, app_client):
        """POST method is allowed in CORS preflight."""
        resp = app_client.options(
            "/api/pipeline/run",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization,Content-Type",
            },
        )
        assert resp.status_code == 200
        allow_methods = resp.headers.get("access-control-allow-methods", "")
        assert "POST" in allow_methods

    def test_cors_preflight_rejects_patch(self, app_client):
        """PATCH method is not in CORS allowed methods."""
        resp = app_client.options(
            "/api/pipeline/run",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "PATCH",
            },
        )
        # Either 200 with PATCH not in allowed methods, or 400
        if resp.status_code == 200:
            allow_methods = resp.headers.get("access-control-allow-methods", "")
            assert "PATCH" not in allow_methods

    def test_cors_wrong_origin_rejected(self, app_client):
        """Requests from non-allowed origins are rejected."""
        resp = app_client.options(
            "/api/pipeline/run",
            headers={
                "Origin": "http://evil.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert resp.headers.get("access-control-allow-origin") is None


class TestErrorSanitizationInEndpoints:
    """NABLA-010: API endpoints don't leak internal error details."""

    def test_bootstrap_error_generic(self, app_client):
        """Bootstrap failure returns generic message, not internal details."""
        # The mock client will cause a real error from the bootstrap function
        # because it doesn't have the right methods. But the error message
        # should be generic.
        resp = app_client.post("/api/system/bootstrap")
        # Either succeeds (mock) or fails with generic message
        if resp.status_code == 500:
            detail = resp.json().get("detail", "")
            # Should not contain internal paths, connection strings, etc.
            assert "postgres" not in detail.lower()
            assert "connection" not in detail.lower() or "failed" in detail.lower()

    def test_health_check_no_internal_details(self, app_client):
        """Health check failures don't expose internal connection details."""
        resp = app_client.get("/api/system/health")
        data = resp.json()
        # Letta and Ollama health details should be generic
        if not data.get("letta", {}).get("healthy", True):
            detail = data["letta"].get("detail", "")
            # Should not contain URLs, IPs, or connection strings
            assert "http://" not in detail
            assert "localhost" not in detail


class TestPipelineFilePathRestriction:
    """VULN-001: Pipeline file parameter restricted to uploads directory."""

    def test_file_path_traversal_rejected(self, app_client):
        """Path traversal via ../ is rejected by the validator."""
        resp = app_client.post(
            "/api/pipeline/run",
            json={"source": "file", "file": "/etc/passwd"},
        )
        # Should be 422 (validation error) because /etc/passwd is
        # not in the uploads directory
        assert resp.status_code == 422

    def test_file_path_source_dir_rejected(self, app_client):
        """Reading source code files via /app is rejected."""
        resp = app_client.post(
            "/api/pipeline/run",
            json={"source": "file", "file": "/app/nabla/config.py"},
        )
        assert resp.status_code == 422

    def test_file_path_data_dir_rejected(self, app_client):
        """Reading data directory files directly is rejected."""
        resp = app_client.post(
            "/api/pipeline/run",
            json={"source": "file", "file": "/data/rl_state.json"},
        )
        assert resp.status_code == 422

    def test_file_path_uploads_dir_accepted(self, app_client, temp_data_dir):
        """Files in the uploads directory are accepted."""
        import os
        upload_dir = os.path.join(temp_data_dir, "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        # Create a dummy file in uploads
        with open(os.path.join(upload_dir, "test.jsonl"), "w") as f:
            f.write('{"timestamp":"2024-01-01","user":"test","action":"login"}')
        resp = app_client.post(
            "/api/pipeline/run",
            json={"source": "file", "file": os.path.join(upload_dir, "test.jsonl")},
        )
        # Should be accepted (200 or 202) — not a 422 validation error
        assert resp.status_code in (200, 202, 409)  # 409 = already running

    def test_file_path_none_accepted(self, app_client):
        """No file path is accepted (not required when source != file)."""
        resp = app_client.post(
            "/api/pipeline/run",
            json={"source": "synthetic"},
        )
        # Should be accepted — not a 422 validation error
        assert resp.status_code in (200, 202, 409)


class TestAuthOpenAccessGuard:
    """VULN-002: API rejects requests when no token is set and dev mode is off."""

    def test_no_token_no_dev_mode_rejected(self, temp_data_dir, mock_letta_client):
        """Requests are rejected when no token is set and dev_mode is false."""
        from nabla.config import Settings
        from nabla.server import app
        from nabla.auth import require_user
        from nabla.rate_limit import reset_rate_limits

        locked_settings = Settings(
            data_dir=temp_data_dir,
            letta_base_url="http://localhost:9999",
            setup_token="",
            dev_mode=False,
            embedding_endpoint="http://localhost:11434/v1",
            splunk_host="",
            sumologic_host="",
            splunk_validate_url=False,
            sumologic_validate_url=False,
        )

        reset_rate_limits()
        # Don't override the auth dependency — let it run
        app.dependency_overrides.pop(require_user, None)

        with patch("nabla.config.get_settings", return_value=locked_settings), \
             patch("nabla.config._settings", locked_settings), \
             patch("nabla.client.get_client", return_value=mock_letta_client), \
             patch("nabla.client._client", mock_letta_client):

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/system/health")
            assert resp.status_code == 401
            assert "Authentication required" in resp.json().get("detail", "")

        app.dependency_overrides.clear()

    def test_dev_mode_allows_access(self, temp_data_dir, mock_letta_client):
        """Dev mode allows access without a token."""
        from nabla.config import Settings
        from nabla.server import app
        from nabla.auth import require_user
        from nabla.rate_limit import reset_rate_limits

        dev_settings = Settings(
            data_dir=temp_data_dir,
            letta_base_url="http://localhost:9999",
            setup_token="",
            dev_mode=True,
            embedding_endpoint="http://localhost:11434/v1",
            splunk_host="",
            sumologic_host="",
            splunk_validate_url=False,
            sumologic_validate_url=False,
        )

        reset_rate_limits()
        app.dependency_overrides.pop(require_user, None)

        with patch("nabla.config.get_settings", return_value=dev_settings), \
             patch("nabla.config._settings", dev_settings), \
             patch("nabla.client.get_client", return_value=mock_letta_client), \
             patch("nabla.client._client", mock_letta_client):

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/system/health")
            assert resp.status_code == 200

        app.dependency_overrides.clear()

    def test_token_set_enforces_auth(self, temp_data_dir, mock_letta_client):
        """Setup token set + user exists: only session cookies authenticate.

        The setup token no longer grants API access (cookie model); it
        gates first-user registration only.
        """
        from nabla.config import Settings
        from nabla.server import app
        from nabla.auth import require_user
        from nabla.rate_limit import reset_rate_limits

        token_settings = Settings(
            data_dir=temp_data_dir,
            letta_base_url="http://localhost:9999",
            setup_token="secret-token-456",
            dev_mode=False,
            embedding_endpoint="http://localhost:11434/v1",
            splunk_host="",
            sumologic_host="",
            splunk_validate_url=False,
            sumologic_validate_url=False,
        )

        reset_rate_limits()
        app.dependency_overrides.pop(require_user, None)

        with patch("nabla.config.get_settings", return_value=token_settings), \
             patch("nabla.config._settings", token_settings), \
             patch("nabla.client.get_client", return_value=mock_letta_client), \
             patch("nabla.client._client", mock_letta_client):

            client = TestClient(app, raise_server_exceptions=False, base_url="https://testserver")

            # No cookie
            resp = client.get("/api/system/health")
            assert resp.status_code == 401

            # Bearer tokens no longer authenticate (old model removed)
            resp = client.get(
                "/api/system/health",
                headers={"Authorization": "Bearer secret-token-456"},
            )
            assert resp.status_code == 401

            # Register the first user (setup token gates it) — cookie flows
            resp = client.post("/api/auth/register", json={
                "username": "admin_user", "password": "password123",
                "setup_token": "secret-token-456"})
            assert resp.status_code == 201

            # Now authenticated via cookie
            resp = client.get("/api/system/health")
            assert resp.status_code == 200

        app.dependency_overrides.clear()

        app.dependency_overrides.clear()
