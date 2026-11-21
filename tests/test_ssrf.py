"""Tests for SSRF URL validation module.

Tests cover:
- validate_connector_url: scheme, localhost, private IPs, DNS resolution
- validate_redirect_url: redirect-based SSRF prevention
- _is_private_ip: private/reserved IP range detection
"""

import ipaddress
from unittest.mock import patch

import pytest

from nabla.ssrf import (
    _is_private_ip,
    validate_connector_url,
    validate_redirect_url,
)


# ── _is_private_ip ──


class TestIsPrivateIp:
    """Tests for _is_private_ip."""

    def test_rfc1918_10_network(self):
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("10.255.255.255") is True

    def test_rfc1918_172_16_network(self):
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("172.31.255.255") is True

    def test_rfc1918_192_168_network(self):
        assert _is_private_ip("192.168.0.1") is True
        assert _is_private_ip("192.168.255.255") is True

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("127.0.0.53") is True

    def test_link_local(self):
        assert _is_private_ip("169.254.1.1") is True

    def test_ipv6_loopback(self):
        assert _is_private_ip("::1") is True

    def test_ipv6_unique_local(self):
        assert _is_private_ip("fc00::1") is True
        assert _is_private_ip("fd00::1") is True

    def test_ipv6_link_local(self):
        assert _is_private_ip("fe80::1") is True

    def test_public_ips(self):
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.2.3.4") is False
        assert _is_private_ip("45.33.32.156") is False

    def test_invalid_ip(self):
        """Invalid IP strings should return False (not raise)."""
        assert _is_private_ip("not-an-ip") is False
        assert _is_private_ip("") is False


# ── validate_connector_url ──


class TestValidateConnectorUrl:
    """Tests for validate_connector_url."""

    def test_valid_https_url(self):
        """Valid public HTTPS URL should pass (mock DNS to return public IP)."""
        with patch("nabla.ssrf.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = (
                (2, 1, 6, "", ("45.33.32.156", 0)),
            )
            is_valid, err = validate_connector_url("https://api.sumologic.com/api")
            assert is_valid is True
            assert err == ""

    def test_valid_http_url(self):
        """Valid public HTTP URL should pass (mock DNS to return public IP)."""
        with patch("nabla.ssrf.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = (
                (2, 1, 6, "", ("45.33.32.156", 0)),
            )
            is_valid, err = validate_connector_url("http://splunk.example.com:8089")
            assert is_valid is True
            assert err == ""

    def test_invalid_scheme_ftp(self):
        """FTP scheme should be rejected."""
        is_valid, err = validate_connector_url("ftp://evil.com")
        assert is_valid is False
        assert "Invalid scheme" in err

    def test_invalid_scheme_file(self):
        """File scheme should be rejected."""
        is_valid, err = validate_connector_url("file:///etc/passwd")
        assert is_valid is False
        assert "Invalid scheme" in err

    def test_no_scheme(self):
        """URL without scheme should be rejected."""
        is_valid, err = validate_connector_url("just-a-hostname")
        # Either no hostname or invalid scheme
        assert is_valid is False

    def test_localhost_hostname(self):
        """localhost hostname should be rejected."""
        is_valid, err = validate_connector_url("https://localhost:8089")
        assert is_valid is False
        assert "localhost" in err

    def test_localhost_localdomain(self):
        """localhost.localdomain should be rejected."""
        is_valid, err = validate_connector_url("https://localhost.localdomain")
        assert is_valid is False
        assert "localhost" in err

    def test_private_ip_10(self):
        """10.x.x.x IP should be rejected."""
        is_valid, err = validate_connector_url("https://10.0.0.1")
        assert is_valid is False
        assert "private" in err.lower() or "reserved" in err.lower()

    def test_private_ip_172_16(self):
        """172.16.x.x IP should be rejected."""
        is_valid, err = validate_connector_url("https://172.16.0.1")
        assert is_valid is False
        assert "private" in err.lower() or "reserved" in err.lower()

    def test_private_ip_192_168(self):
        """192.168.x.x IP should be rejected."""
        is_valid, err = validate_connector_url("https://192.168.1.1")
        assert is_valid is False
        assert "private" in err.lower() or "reserved" in err.lower()

    def test_loopback_ip(self):
        """127.x.x.x IP should be rejected."""
        is_valid, err = validate_connector_url("https://127.0.0.1")
        assert is_valid is False
        assert "private" in err.lower() or "reserved" in err.lower()

    def test_unresolvable_hostname(self):
        """Unresolvable hostname should be rejected."""
        is_valid, err = validate_connector_url("https://this-hostname-does-not-exist-xyz123.invalid")
        assert is_valid is False
        assert "does not resolve" in err

    def test_no_hostname(self):
        """URL with no hostname should be rejected."""
        is_valid, err = validate_connector_url("https://")
        assert is_valid is False

    def test_dns_rebinding_to_private(self):
        """Hostname resolving to a private IP should be rejected.

        We mock DNS to return a private IP for a public-looking hostname.
        """
        with patch("nabla.ssrf.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = (
                (2, 1, 6, "", ("10.0.0.1", 0)),
            )
            is_valid, err = validate_connector_url("https://looks-public.example.com")
            assert is_valid is False
            assert "private" in err.lower()

    def test_dns_rebinding_to_public(self):
        """Hostname resolving to a public IP should pass."""
        with patch("nabla.ssrf.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = (
                (2, 1, 6, "", ("45.33.32.156", 0)),
            )
            is_valid, err = validate_connector_url("https://looks-public.example.com")
            assert is_valid is True
            assert err == ""


# ── validate_redirect_url ──


class TestValidateRedirectUrl:
    """Tests for validate_redirect_url."""

    def test_valid_redirect(self):
        """Redirect to a valid public URL should pass (mock DNS)."""
        with patch("nabla.ssrf.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = (
                (2, 1, 6, "", ("45.33.32.156", 0)),
            )
            is_valid, err = validate_redirect_url(
                "https://api2.sumologic.com/api",
                "api.sumologic.com",
            )
            assert is_valid is True
            assert err == ""

    def test_redirect_to_localhost(self):
        """Redirect to localhost should be blocked."""
        is_valid, err = validate_redirect_url(
            "https://localhost:8089",
            "api.sumologic.com",
        )
        assert is_valid is False
        assert "localhost" in err

    def test_redirect_to_private_ip(self):
        """Redirect to a private IP should be blocked."""
        is_valid, err = validate_redirect_url(
            "https://10.0.0.1",
            "api.sumologic.com",
        )
        assert is_valid is False
        assert "private" in err.lower()

    def test_redirect_to_invalid_scheme(self):
        """Redirect to a non-http(s) scheme should be blocked."""
        is_valid, err = validate_redirect_url(
            "gopher://evil.com",
            "api.sumologic.com",
        )
        assert is_valid is False
        assert "invalid scheme" in err.lower()

    def test_redirect_no_hostname(self):
        """Redirect URL with no hostname should be blocked."""
        is_valid, err = validate_redirect_url(
            "https://",
            "api.sumologic.com",
        )
        assert is_valid is False

    def test_redirect_to_unresolvable(self):
        """Redirect to an unresolvable hostname should be blocked."""
        is_valid, err = validate_redirect_url(
            "https://this-hostname-does-not-exist-xyz123.invalid",
            "api.sumologic.com",
        )
        assert is_valid is False
        assert "does not resolve" in err

    def test_redirect_dns_rebinding(self):
        """Redirect hostname resolving to private IP should be blocked."""
        with patch("nabla.ssrf.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = (
                (2, 1, 6, "", ("192.168.1.1", 0)),
            )
            is_valid, err = validate_redirect_url(
                "https://looks-public.example.com",
                "api.sumologic.com",
            )
            assert is_valid is False
            assert "private" in err.lower()

    def test_original_hostname_in_error(self):
        """Error message should include the original hostname for context."""
        is_valid, err = validate_redirect_url(
            "https://localhost",
            "api.sumologic.com",
        )
        assert "api.sumologic.com" in err

    def test_relative_redirect_carries_original_scheme(self):
        """Round-7 low: the relative-URL rebuild uses the ORIGINAL
        request's scheme, not a hardcoded https — an http-only origin
        must validate its own redirect (behavioral half)."""
        from unittest.mock import patch
        from nabla.ssrf import validate_redirect_url
        fake = [(None, None, None, "", ("93.184.216.34", 0))]
        with patch("socket.getaddrinfo", return_value=fake):
            ok, err = validate_redirect_url("/login?next=x", "api.example.com",
                                            original_scheme="http")
        assert ok, err

    def test_no_hardcoded_scheme_rebuild(self):
        """Source-level half: no `f"https://{...}` rebuild remains in
        ssrf.py, and the caller threads response.url.scheme through."""
        from pathlib import Path
        import nabla.ssrf as ssrf_mod
        src = Path(ssrf_mod.__file__).read_text()
        assert 'f"https://{original_hostname}' not in src, (
            "the relative-redirect rebuild hardcodes https again")
        assert "original_scheme=original_scheme" in src, (
            "the caller stopped threading the original scheme")
