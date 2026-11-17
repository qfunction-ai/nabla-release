"""Tests for shared utility functions in nabla.utils."""

import os
import tempfile

from nabla.utils import is_off_hours, is_routable_ip
from nabla.persistence import ensure_data_path


# ---------------------------------------------------------------------------
# is_routable_ip
# ---------------------------------------------------------------------------

class TestIsRoutableIP:
    """Tests for is_routable_ip."""

    def test_public_ips(self):
        """Public IPs are routable."""
        assert is_routable_ip("8.8.8.8") is True
        assert is_routable_ip("1.2.3.4") is True
        assert is_routable_ip("45.33.32.156") is True

    def test_private_rfc1918(self):
        """RFC 1918 private addresses are not routable."""
        assert is_routable_ip("10.0.0.1") is False
        assert is_routable_ip("172.16.0.1") is False
        assert is_routable_ip("172.31.94.24") is False
        assert is_routable_ip("192.168.1.1") is False

    def test_loopback(self):
        """Loopback addresses are not routable."""
        assert is_routable_ip("127.0.0.1") is False
        assert is_routable_ip("::1") is False

    def test_link_local(self):
        """Link-local addresses are not routable."""
        assert is_routable_ip("169.254.1.1") is False
        assert is_routable_ip("fe80::1") is False

    def test_unique_local_ipv6(self):
        """IPv6 unique-local addresses are not routable."""
        assert is_routable_ip("fc00::1") is False
        assert is_routable_ip("fd00::1") is False

    def test_routable_ipv6(self):
        """Globally routable IPv6 addresses are routable."""
        assert is_routable_ip("2607:f8b0:4004:800::200e") is True

    def test_reserved(self):
        """Reserved/documentation addresses are not routable."""
        assert is_routable_ip("203.0.113.1") is False  # TEST-NET-3
        assert is_routable_ip("2001:db8::1") is False  # IPv6 documentation

    def test_empty_and_invalid(self):
        """Empty and invalid inputs return False."""
        assert is_routable_ip("") is False
        assert is_routable_ip("not-an-ip") is False
        assert is_routable_ip("999.999.999.999") is False

    def test_multicast(self):
        """Multicast addresses are not routable."""
        assert is_routable_ip("224.0.0.1") is False
        assert is_routable_ip("ff02::1") is False


# ---------------------------------------------------------------------------
# is_off_hours
# ---------------------------------------------------------------------------

class TestIsOffHours:
    """Tests for is_off_hours."""

    def test_night(self):
        """23:00 is off-hours."""
        assert is_off_hours("2025-01-15T23:00:00Z") is True

    def test_early_morning(self):
        """03:00 is off-hours."""
        assert is_off_hours("2025-01-15T03:00:00Z") is True

    def test_business_hours(self):
        """14:00 is not off-hours."""
        assert is_off_hours("2025-01-15T14:00:00Z") is False

    def test_boundary_6am(self):
        """06:00 is not off-hours (boundary)."""
        assert is_off_hours("2025-01-15T06:00:00Z") is False

    def test_boundary_10pm(self):
        """22:00 is off-hours (boundary)."""
        assert is_off_hours("2025-01-15T22:00:00Z") is True

    def test_boundary_5am(self):
        """05:59 is off-hours."""
        assert is_off_hours("2025-01-15T05:59:00Z") is True

    def test_boundary_9pm(self):
        """21:59 is not off-hours."""
        assert is_off_hours("2025-01-15T21:59:00Z") is False

    def test_invalid_timestamp(self):
        """Invalid timestamps return False."""
        assert is_off_hours("") is False
        assert is_off_hours("invalid") is False

    def test_midnight(self):
        """00:00 (midnight) is off-hours."""
        assert is_off_hours("2025-01-15T00:00:00Z") is True


# ---------------------------------------------------------------------------
# ensure_data_path
# ---------------------------------------------------------------------------

class TestEnsureDataPath:
    """Tests for ensure_data_path."""

    def test_creates_parent_dir(self):
        """Creates parent directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "subdir", "data.json")
            result = ensure_data_path(path)
            assert result == path
            assert os.path.isdir(os.path.join(tmpdir, "subdir"))

    def test_existing_parent_dir(self):
        """Returns path when parent directory already exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "data.json")
            result = ensure_data_path(path)
            assert result == path

    def test_read_only_parent(self):
        """Returns None when parent directory cannot be created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Make the parent read-only
            os.chmod(tmpdir, 0o444)
            path = os.path.join(tmpdir, "subdir", "data.json")
            result = ensure_data_path(path)
            assert result is None
            os.chmod(tmpdir, 0o755)  # restore for cleanup

    def test_relative_path(self):
        """Handles relative paths (empty dirname falls back to '.')."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            path = "data.json"
            result = ensure_data_path(path)
            assert result == path
