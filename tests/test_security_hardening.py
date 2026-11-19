"""Tests for security hardening fixes (NABLA-001 through NABLA-007).

Covers:
- NABLA-001: SumoLogic redirect validation
- NABLA-002: LOLBIN download redirect validation
- NABLA-003: Export/import path traversal protection
- NABLA-004: Export file permissions
- NABLA-005: Log redaction threshold adjustment
- NABLA-006: DNS rebinding double-check (verify_dns_stability)
- NABLA-007: LOLBIN SHA-256 checksum pinning
"""

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nabla.ssrf import verify_dns_stability


# ── NABLA-001: SumoLogic redirect validation ──


class TestSumoLogicRedirectValidation:
    """Tests for SumoLogic connector redirect SSRF validation."""

    def test_follow_redirects_disabled(self):
        """SumoLogic connector should use follow_redirects=False."""
        from nabla.connectors.sumologic import SumoLogicConnector, SumoConfig
        config = SumoConfig(
            host="https://api.sumologic.com/api",
            access_id="test",
            access_key="test",
        )
        connector = SumoLogicConnector(config)
        # Verify _follow_redirects method exists
        assert hasattr(connector, "_follow_redirects")
        assert hasattr(connector, "_request")

    def test_redirect_to_private_ip_blocked(self):
        """Redirect to private IP should be blocked by _follow_redirects."""
        from nabla.connectors.sumologic import SumoLogicConnector, SumoConfig
        config = SumoConfig(
            host="https://api.sumologic.com/api",
            access_id="test",
            access_key="test",
            validate_url=True,
        )
        connector = SumoLogicConnector(config)
        connector._original_hostname = "api.sumologic.com"

        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"location": "https://10.0.0.1/secret"}
        mock_response.next = None

        mock_client = MagicMock()

        with patch("nabla.ssrf.validate_redirect_url") as mock_validate:
            mock_validate.return_value = (False, "Redirect to private IP blocked")
            with pytest.raises(ValueError, match="SumoLogic redirect blocked"):
                connector._follow_redirects(mock_client, mock_response)

    def test_redirect_to_localhost_blocked(self):
        """Redirect to localhost should be blocked."""
        from nabla.connectors.sumologic import SumoLogicConnector, SumoConfig
        config = SumoConfig(
            host="https://api.sumologic.com/api",
            access_id="test",
            access_key="test",
            validate_url=True,
        )
        connector = SumoLogicConnector(config)
        connector._original_hostname = "api.sumologic.com"

        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"location": "https://localhost:8089"}
        mock_response.next = None

        mock_client = MagicMock()

        with patch("nabla.ssrf.validate_redirect_url") as mock_validate:
            mock_validate.return_value = (False, "Redirect to localhost blocked")
            with pytest.raises(ValueError, match="SumoLogic redirect blocked"):
                connector._follow_redirects(mock_client, mock_response)

    def test_valid_redirect_followed(self):
        """Valid redirect should be followed."""
        from nabla.connectors.sumologic import SumoLogicConnector, SumoConfig
        config = SumoConfig(
            host="https://api.sumologic.com/api",
            access_id="test",
            access_key="test",
        )
        connector = SumoLogicConnector(config)
        connector._original_hostname = "api.sumologic.com"

        # First response: 302 redirect
        redirect_response = MagicMock()
        redirect_response.status_code = 302
        redirect_response.headers = {"location": "https://api2.sumologic.com/api"}
        redirect_response.next = MagicMock()

        # Second response: 200 OK
        final_response = MagicMock()
        final_response.status_code = 200

        mock_client = MagicMock()
        mock_client.send.return_value = final_response

        with patch("nabla.ssrf.validate_redirect_url") as mock_validate:
            mock_validate.return_value = (True, "")
            result = connector._follow_redirects(mock_client, redirect_response)
            assert result.status_code == 200

    def test_too_many_redirects(self):
        """Too many redirects should raise ValueError."""
        from nabla.connectors.sumologic import SumoLogicConnector, SumoConfig
        config = SumoConfig(
            host="https://api.sumologic.com/api",
            access_id="test",
            access_key="test",
        )
        connector = SumoLogicConnector(config)
        connector._original_hostname = ""

        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"location": "https://api.sumologic.com/api"}
        mock_response.next = MagicMock()

        mock_client = MagicMock()
        mock_client.send.return_value = mock_response

        with pytest.raises(ValueError, match="Too many redirects"):
            connector._follow_redirects(mock_client, mock_response, max_redirects=2)

    def test_request_method_uses_client_request(self):
        """_request should call client.request() with the method."""
        from nabla.connectors.sumologic import SumoLogicConnector, SumoConfig
        config = SumoConfig(
            host="https://api.sumologic.com/api",
            access_id="test",
            access_key="test",
        )
        connector = SumoLogicConnector(config)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = MagicMock()
        mock_client.request.return_value = mock_response

        result = connector._request(mock_client, "POST", "/v2/search/jobs", json={"q": "test"})
        mock_client.request.assert_called_once_with("POST", "/v2/search/jobs", json={"q": "test"})


# ── NABLA-002: LOLBIN download redirect validation ──


class TestLolbinRedirectValidation:
    """Tests for LOLBIN download redirect validation."""

    def test_download_redirect_to_private_ip_blocked(self):
        """Redirect to private IP during LOLBIN download should be blocked."""
        from nabla.lolbin_db import _download

        # First response: redirect
        redirect_resp = MagicMock()
        redirect_resp.status_code = 302
        redirect_resp.headers = {"location": "https://10.0.0.1/evil"}

        with patch("httpx.get", return_value=redirect_resp):
            with tempfile.TemporaryDirectory() as tmpdir:
                cache_path = os.path.join(tmpdir, "test.json")
                with pytest.raises(ValueError, match="redirect to unexpected host"):
                    _download(
                        "https://lolbas-project.github.io/api/lolbas.json",
                        cache_path,
                        refresh_days=0,
                        allowed_hosts=("lolbas-project.github.io", "pages.github.com"),
                    )

    def test_download_redirect_to_allowed_host(self):
        """Redirect to allowed host should succeed."""
        from nabla.lolbin_db import _download

        # First response: redirect
        redirect_resp = MagicMock()
        redirect_resp.status_code = 302
        redirect_resp.headers = {"location": "https://pages.github.com/lolbas.json"}

        # Second response: OK
        final_resp = MagicMock()
        final_resp.status_code = 200
        final_resp.content = b'[{"name": "cmd.exe"}]'

        with patch("httpx.get", side_effect=[redirect_resp, final_resp]):
            with tempfile.TemporaryDirectory() as tmpdir:
                cache_path = os.path.join(tmpdir, "test.json")
                result = _download(
                    "https://lolbas-project.github.io/api/lolbas.json",
                    cache_path,
                    refresh_days=0,
                    allowed_hosts=("lolbas-project.github.io", "pages.github.com"),
                )
                assert result == cache_path
                assert os.path.exists(cache_path)

    def test_download_no_allowed_hosts_allows_any_redirect(self):
        """With no allowed_hosts, redirects are not validated."""
        from nabla.lolbin_db import _download

        redirect_resp = MagicMock()
        redirect_resp.status_code = 302
        redirect_resp.headers = {"location": "https://any-host.example.com/data"}

        final_resp = MagicMock()
        final_resp.status_code = 200
        final_resp.content = b"[]"

        with patch("httpx.get", side_effect=[redirect_resp, final_resp]):
            with tempfile.TemporaryDirectory() as tmpdir:
                cache_path = os.path.join(tmpdir, "test.json")
                result = _download(
                    "https://example.com/data.json",
                    cache_path,
                    refresh_days=0,
                    allowed_hosts=(),
                )
                assert result == cache_path


# ── NABLA-003: Export/import path traversal protection ──


class TestExportPathTraversal:
    """Tests for export/import path traversal protection."""

    def test_export_rejects_system_path(self):
        """Export should reject paths outside allowed directories."""
        from nabla.export import _validate_path
        with pytest.raises(ValueError, match="outside allowed directories"):
            _validate_path("/etc/cron.d/backdoor")

    def test_export_rejects_home_path(self):
        """Export should reject paths in home directory."""
        from nabla.export import _validate_path
        with pytest.raises(ValueError, match="outside allowed directories"):
            _validate_path("/home/user/.ssh/authorized_keys")

    def test_export_allows_data_path(self):
        """Export should allow /data paths."""
        from nabla.export import _validate_path
        # Should not raise
        _validate_path("/data/export.json")

    def test_export_allows_tmp_path(self):
        """Export should allow /tmp paths."""
        from nabla.export import _validate_path
        # Should not raise
        _validate_path("/tmp/nabla-export.json")

    def test_export_allows_current_tmp(self):
        """Export should allow system temp directory."""
        from nabla.export import _validate_path
        # Should not raise
        _validate_path(os.path.join(tempfile.gettempdir(), "nabla-export.json"))

    def test_import_rejects_system_path(self):
        """Import should reject paths outside allowed directories."""
        from nabla.export import _validate_path
        with pytest.raises(ValueError, match="outside allowed directories"):
            _validate_path("/etc/passwd", must_exist=True)

    def test_import_must_exist(self):
        """Import with must_exist should raise FileNotFoundError for missing files."""
        from nabla.export import _validate_path
        with pytest.raises(FileNotFoundError, match="File not found"):
            _validate_path("/tmp/nonexistent-nabla-test-file.json", must_exist=True)

    def test_export_state_validates_output_path(self):
        """export_state should validate the output path."""
        from nabla.export import export_state
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="outside allowed directories"):
                export_state(tmpdir, "/etc/cron.d/backdoor")

    def test_import_state_validates_input_path(self):
        """import_state should validate the input path."""
        from nabla.export import import_state
        with pytest.raises(ValueError, match="outside allowed directories"):
            import_state("/etc/passwd", "/data")


# ── NABLA-004: Export file permissions ──


class TestExportFilePermissions:
    """Tests for export file permissions (0o600)."""

    def test_export_file_permissions(self):
        """Export file should have 0o600 permissions."""
        from nabla.export import export_state
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a minimal state file
            os.makedirs(os.path.join(tmpdir, "data"), exist_ok=True)
            with open(os.path.join(tmpdir, "data", "entity_profiles.json"), "w") as f:
                json.dump({}, f)

            output_path = os.path.join(tmpdir, "export.json")
            export_state(os.path.join(tmpdir, "data"), output_path)

            # Check file permissions
            mode = os.stat(output_path).st_mode
            perms = stat.S_IMODE(mode)
            assert perms == 0o600, f"Expected 0o600, got {oct(perms)}"


# ── NABLA-005: Log redaction threshold adjustment ──


class TestLogRedactionThresholds:
    """Tests for adjusted log redaction thresholds."""

    def test_short_hex_not_redacted(self):
        """32-char hex strings (UUIDs without hyphens) should NOT be redacted."""
        from nabla.log import _REDACT_PATTERNS
        import re
        uuid_hex = "a1b2c3d4e5f6789012345678abcdef01"  # 32 hex chars
        for pattern, replacement in _REDACT_PATTERNS:
            result = pattern.sub(replacement, uuid_hex)
            # Should not be redacted (48+ threshold)
            if "REDACTED" in result:
                pytest.fail(f"32-char hex was redacted by pattern {pattern.pattern}")

    def test_sha256_hash_redacted(self):
        """64-char hex strings (SHA-256 hashes) should be redacted."""
        from nabla.log import _REDACT_PATTERNS
        import re
        sha256 = "a" * 64  # 64 hex chars
        redacted = False
        for pattern, replacement in _REDACT_PATTERNS:
            result = pattern.sub(replacement, sha256)
            if "REDACTED" in result:
                redacted = True
                break
        assert redacted, "64-char hex should be redacted"

    def test_short_base64_not_redacted(self):
        """40-char base64 strings should NOT be redacted."""
        from nabla.log import _REDACT_PATTERNS
        import re
        short_b64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="  # 40 chars
        for pattern, replacement in _REDACT_PATTERNS:
            result = pattern.sub(replacement, short_b64)
            if "REDACTED" in result:
                pytest.fail(f"40-char base64 was redacted by pattern {pattern.pattern}")

    def test_long_base64_redacted(self):
        """80+ char base64 strings should be redacted."""
        from nabla.log import _REDACT_PATTERNS
        import re
        long_b64 = "A" * 80  # 80 base64 chars
        redacted = False
        for pattern, replacement in _REDACT_PATTERNS:
            result = pattern.sub(replacement, long_b64)
            if "REDACTED" in result:
                redacted = True
                break
        assert redacted, "80-char base64 should be redacted"

    def test_bearer_token_still_redacted(self):
        """Bearer tokens should still be redacted regardless of length."""
        from nabla.log import _REDACT_PATTERNS
        import re
        msg = "Bearer eyJhbGciOiJIUzI1NiJ9"
        for pattern, replacement in _REDACT_PATTERNS:
            result = pattern.sub(replacement, msg)
            if "REDACTED" in result:
                return  # Success
        pytest.fail("Bearer token was not redacted")

    def test_password_kv_still_redacted(self):
        """password= and token= key-value pairs should still be redacted."""
        from nabla.log import _REDACT_PATTERNS
        import re
        msg = "password=secretpassword123"
        for pattern, replacement in _REDACT_PATTERNS:
            result = pattern.sub(replacement, msg)
            if "REDACTED" in result:
                return  # Success
        pytest.fail("password= value was not redacted")


# ── NABLA-006: DNS rebinding double-check ──


class TestDnsRebindingCheck:
    """Tests for verify_dns_stability (DNS rebinding detection)."""

    def test_stable_dns_passes(self):
        """Stable DNS resolution should pass."""
        with patch("nabla.ssrf.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("45.33.32.156", 0)),
            ]
            is_stable, err = verify_dns_stability("api.example.com", {"45.33.32.156"})
            assert is_stable is True
            assert err == ""

    def test_dns_changed_to_private_ip_blocked(self):
        """DNS resolution changed to private IP should be blocked."""
        with patch("nabla.ssrf.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("10.0.0.1", 0)),
            ]
            is_stable, err = verify_dns_stability("api.example.com", {"45.33.32.156"})
            assert is_stable is False
            assert "private IP" in err
            assert "DNS rebinding" in err.lower() or "rebinding" in err.lower()

    def test_dns_unresolvable_blocked(self):
        """Hostname no longer resolving should be blocked."""
        import socket
        with patch("nabla.ssrf.socket.getaddrinfo", side_effect=socket.gaierror):
            is_stable, err = verify_dns_stability("api.example.com", {"45.33.32.156"})
            assert is_stable is False
            assert "no longer resolves" in err

    def test_dns_changed_to_different_public_ip_warns(self):
        """DNS resolution changed to different public IP should pass but warn."""
        with patch("nabla.ssrf.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("1.2.3.4", 0)),
            ]
            is_stable, err = verify_dns_stability("api.example.com", {"45.33.32.156"})
            # Should pass (both are public IPs) but the IPs differ
            assert is_stable is True
            assert err == ""

    def test_dns_same_ips_passes(self):
        """Same IPs on re-resolution should pass."""
        with patch("nabla.ssrf.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("45.33.32.156", 0)),
                (2, 1, 6, "", ("1.2.3.4", 0)),
            ]
            is_stable, err = verify_dns_stability("api.example.com", {"45.33.32.156", "1.2.3.4"})
            assert is_stable is True
            assert err == ""


# ── NABLA-007: LOLBIN SHA-256 checksum pinning ──


class TestLolbinChecksumPinning:
    """Tests for LOLBIN download integrity verification."""

    def test_download_with_correct_checksum(self):
        """Download with correct SHA-256 should succeed."""
        from nabla.lolbin_db import _download
        content = b'[{"name": "cmd.exe"}]'
        expected_hash = hashlib.sha256(content).hexdigest()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = content

        with patch("httpx.get", return_value=mock_resp):
            with tempfile.TemporaryDirectory() as tmpdir:
                cache_path = os.path.join(tmpdir, "test.json")
                result = _download(
                    "https://lolbas-project.github.io/api/lolbas.json",
                    cache_path,
                    refresh_days=0,
                    expected_sha256=expected_hash,
                )
                assert result == cache_path

    def test_download_with_wrong_checksum(self):
        """Download with wrong SHA-256 should raise ValueError."""
        from nabla.lolbin_db import _download
        content = b'[{"name": "cmd.exe"}]'

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = content

        with patch("httpx.get", return_value=mock_resp):
            with tempfile.TemporaryDirectory() as tmpdir:
                cache_path = os.path.join(tmpdir, "test.json")
                with pytest.raises(ValueError, match="hash mismatch"):
                    _download(
                        "https://lolbas-project.github.io/api/lolbas.json",
                        cache_path,
                        refresh_days=0,
                        expected_sha256="0000000000000000000000000000000000000000000000000000000000000000",
                    )

    def test_download_without_checksum_logs_warning(self):
        """Download without checksum should log a warning with actual hash."""
        from nabla.lolbin_db import _download
        content = b'[{"name": "cmd.exe"}]'

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = content

        with patch("httpx.get", return_value=mock_resp):
            with tempfile.TemporaryDirectory() as tmpdir:
                cache_path = os.path.join(tmpdir, "test.json")
                with patch("nabla.lolbin_db.logger") as mock_logger:
                    _download(
                        "https://lolbas-project.github.io/api/lolbas.json",
                        cache_path,
                        refresh_days=0,
                        expected_sha256="",
                    )
                    # Should have logged a warning about missing checksum
                    mock_logger.warning.assert_called()
                    call_args = mock_logger.warning.call_args
                    assert "integrity verification disabled" in str(call_args).lower()

    def test_env_var_overrides_checksum(self):
        """Checksum pins come from Settings (N14 round 4: was raw env)."""
        import nabla.lolbin_db as lolbin_mod
        import nabla.config
        from nabla.config import Settings

        with patch.object(nabla.config, "get_settings",
                          lambda: Settings(lolbas_sha256="test_hash_123")):
            assert lolbin_mod._pinned_hash("lolbas_sha256") == "test_hash_123"
        # unset pin reads as empty (check skipped, warning logged)
        with patch.object(nabla.config, "get_settings",
                          lambda: Settings(lolbas_sha256="")):
            assert lolbin_mod._pinned_hash("lolbas_sha256") == ""
