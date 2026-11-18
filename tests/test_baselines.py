"""Unit tests for nabla.baselines — entity profile storage and updates."""

import json
import os
import tempfile

import pytest

from nabla.baselines import (
    EWMAProfile,
    EntityProfileStore,
    HostProfile,
    IPProfile,
    UserProfile,
    group_entries_by_entity,
    _capped_set,
)
from nabla.utils import is_off_hours, is_routable_ip


# ---------------------------------------------------------------------------
# EWMAProfile tests
# ---------------------------------------------------------------------------

class TestEWMAProfile:
    """Tests for EWMAProfile update, z-score, and serialization."""

    def test_update_converges(self):
        """EWMA converges toward repeated observations."""
        ewma = EWMAProfile(alpha=0.3)
        for _ in range(20):
            ewma.update(100.0)
        assert abs(ewma.value - 100.0) < 1.0

    def test_update_adapts(self):
        """EWMA adapts when observations change."""
        ewma = EWMAProfile(alpha=0.3)
        for _ in range(20):
            ewma.update(100.0)
        for _ in range(10):
            ewma.update(200.0)
        assert 150.0 < ewma.value < 200.0

    def test_z_score_zero_variance(self):
        """Z-score returns 0 when variance is zero."""
        ewma = EWMAProfile(value=50.0, variance=0.0)
        assert ewma.z_score(100.0) == 0.0

    def test_z_score_calculation(self):
        """Z-score computes correctly for known values."""
        ewma = EWMAProfile(value=100.0, variance=25.0)  # std = max(5, 10) = 10 (R4 floor)
        z = ewma.z_score(110.0)
        assert abs(z - 1.0) < 0.01  # Poisson-floored

    def test_std_property(self):
        """std returns sqrt of variance."""
        ewma = EWMAProfile(variance=9.0)
        assert abs(ewma.std - 3.0) < 0.01

    def test_std_zero_variance_poisson_floor(self):
        """R4: zero variance floors at sqrt(value) — Poisson noise, not 0.01."""
        ewma = EWMAProfile(value=36.0, variance=0.0)
        assert abs(ewma.std - 6.0) < 0.01  # sqrt(36)
        cold = EWMAProfile(value=0.0, variance=0.0)
        assert abs(cold.std - 0.01) < 0.001  # below-count-regime: plain floor

    def test_serialization_roundtrip(self):
        """EWMAProfile survives dict serialization roundtrip."""
        ewma = EWMAProfile(value=42.0, variance=9.0, alpha=0.5)
        d = ewma.to_dict()
        restored = EWMAProfile.from_dict(d)
        assert restored.value == 42.0
        assert restored.variance == 9.0
        assert restored.alpha == 0.5

    def test_from_dict_defaults(self):
        """from_dict uses defaults for missing keys."""
        restored = EWMAProfile.from_dict({})
        assert restored.value == 0.0
        assert restored.variance == 0.0
        assert restored.alpha == 0.3


# ---------------------------------------------------------------------------
# UserProfile tests
# ---------------------------------------------------------------------------

class TestUserProfile:
    """Tests for UserProfile serialization."""

    def test_serialization_roundtrip(self):
        """UserProfile survives dict serialization roundtrip."""
        profile = UserProfile(
            entity_id="jsmith",
            first_seen="2025-01-01T00:00:00+00:00",
            last_seen="2025-01-10T00:00:00+00:00",
            observation_count=5,
            account_created_at="2025-01-01T00:00:00+00:00",
            typical_ips={"10.0.1.50", "10.0.1.100"},
            typical_hours={8, 9, 10, 14, 15},
            typical_actions={"login": 0.6, "logout": 0.4},
        )
        d = profile.to_dict()
        restored = UserProfile.from_dict(d)
        assert restored.entity_id == "jsmith"
        assert restored.observation_count == 5
        assert restored.account_created_at == "2025-01-01T00:00:00+00:00"
        # A11: recency sets compare by membership
        assert set(restored.typical_ips) == {"10.0.1.50", "10.0.1.100"}
        assert set(restored.typical_hours) == {8, 9, 10, 14, 15}
        assert restored.typical_actions == {"login": 0.6, "logout": 0.4}

    def test_recency_sets_serialized_with_members(self):
        """A11: typical_ips/hours serialize as {members, last_seen} dicts."""
        profile = UserProfile()
        profile.typical_ips.add("c")
        profile.typical_ips.add("a")
        profile.typical_ips.add("b")
        d = profile.to_dict()
        assert d["typical_ips"]["members"] == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# HostProfile tests
# ---------------------------------------------------------------------------

class TestHostProfile:
    """Tests for HostProfile serialization."""

    def test_serialization_roundtrip(self):
        """HostProfile survives dict serialization roundtrip."""
        profile = HostProfile(
            entity_id="DC01",
            observation_count=10,
            typical_processes={"svchost", "lsass", "dns"},
            typical_users={"admin", "system"},
            typical_destinations={"10.0.5.20"},
            typical_ports={53, 88, 389},
            typical_registry_keys={"HKLM\\Software\\Run"},
        )
        d = profile.to_dict()
        restored = HostProfile.from_dict(d)
        assert restored.entity_id == "DC01"
        assert restored.typical_processes == {"svchost", "lsass", "dns"}
        assert restored.typical_users == {"admin", "system"}
        assert restored.typical_ports == {53, 88, 389}

    def test_ewma_profiles_in_roundtrip(self):
        """EWMAProfile fields survive HostProfile roundtrip."""
        profile = HostProfile(
            entity_id="DC01",
            typical_process_count=EWMAProfile(value=80.0, variance=10.0),
        )
        d = profile.to_dict()
        restored = HostProfile.from_dict(d)
        assert restored.typical_process_count.value == 80.0
        assert restored.typical_process_count.variance == 10.0


# ---------------------------------------------------------------------------
# IPProfile tests
# ---------------------------------------------------------------------------

class TestIPProfile:
    """Tests for IPProfile serialization."""

    def test_serialization_roundtrip(self):
        """IPProfile survives dict serialization roundtrip."""
        profile = IPProfile(
            entity_id="10.0.1.50",
            typical_users={"jsmith"},
            typical_domains={"api.corp.com"},
        )
        d = profile.to_dict()
        restored = IPProfile.from_dict(d)
        assert restored.entity_id == "10.0.1.50"
        assert restored.typical_users == {"jsmith"}
        assert restored.typical_domains == {"api.corp.com"}


# ---------------------------------------------------------------------------
# EntityProfileStore tests
# ---------------------------------------------------------------------------

class TestEntityProfileStore:
    """Tests for EntityProfileStore load, save, and update methods."""

    def test_fresh_store_no_file(self, tmp_path):
        """Store starts empty when no file exists."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        assert len(store.users) == 0
        assert len(store.hosts) == 0
        assert len(store.ips) == 0

    def test_save_and_reload(self, tmp_path):
        """Store persists and reloads profiles correctly."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        store.get_or_create_user("jsmith").observation_count = 5
        store.get_or_create_host("DC01").observation_count = 3
        store.get_or_create_ip("10.0.1.50").observation_count = 2
        store.save()

        # Reload
        store2 = EntityProfileStore(path)
        assert store2.users["jsmith"].observation_count == 5
        assert store2.hosts["DC01"].observation_count == 3
        assert store2.ips["10.0.1.50"].observation_count == 2

    def test_get_or_create_user(self, tmp_path):
        """get_or_create_user creates profile on first access."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        profile = store.get_or_create_user("jsmith")
        assert profile.entity_id == "jsmith"
        assert profile.observation_count == 0
        assert profile.first_seen != ""

        # Second call returns same object
        profile2 = store.get_or_create_user("jsmith")
        assert profile2 is profile

    def test_get_or_create_host(self, tmp_path):
        """get_or_create_host creates profile on first access."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        profile = store.get_or_create_host("DC01")
        assert profile.entity_id == "DC01"

    def test_get_or_create_ip(self, tmp_path):
        """get_or_create_ip creates profile on first access."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        profile = store.get_or_create_ip("10.0.1.50")
        assert profile.entity_id == "10.0.1.50"

    def test_get_returns_none_for_missing(self, tmp_path):
        """get_user/get_host/get_ip return None for missing entities."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        assert store.get_user("nobody") is None
        assert store.get_host("nohost") is None
        assert store.get_ip("0.0.0.0") is None

    def test_warm_up_complete_false_initially(self, tmp_path):
        """warm_up_complete returns False for new entities."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        store.get_or_create_user("jsmith")
        assert not store.warm_up_complete("user", "jsmith", min_observations=3)

    def test_warm_up_complete_true_after_observations(self, tmp_path):
        """warm_up_complete returns True after enough observations."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        profile = store.get_or_create_user("jsmith")
        profile.observation_count = 3
        assert store.warm_up_complete("user", "jsmith", min_observations=3)

    def test_warm_up_complete_for_missing_entity(self, tmp_path):
        """warm_up_complete returns False for entities not in store."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        assert not store.warm_up_complete("user", "ghost", min_observations=1)

    def test_warm_up_complete_by_entity_type(self, tmp_path):
        """warm_up_complete works for all entity types."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        store.get_or_create_host("DC01").observation_count = 5
        store.get_or_create_ip("10.0.1.1").observation_count = 2
        assert store.warm_up_complete("host", "DC01", min_observations=3)
        assert not store.warm_up_complete("ip", "10.0.1.1", min_observations=3)

    def test_update_user_basic(self, tmp_path):
        """update_user updates EWMA and sets correctly."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries = [
            {"user": "jsmith", "source_ip": "8.8.8.8", "action": "login_success",
             "timestamp": "2025-01-15T09:00:00Z"},
            {"user": "jsmith", "source_ip": "8.8.8.8", "action": "login_failure",
             "timestamp": "2025-01-15T23:00:00Z"},
            {"user": "jsmith", "source_ip": "1.2.3.4", "action": "logout",
             "timestamp": "2025-01-15T10:00:00Z"},
        ]
        store.update_user("jsmith", entries)
        profile = store.get_user("jsmith")
        assert profile.observation_count == 1
        # R4: hour-bucketed rate — 3 events across 3 distinct hours = 1.0/hr
        assert profile.typical_event_count.value == pytest.approx(1.0, abs=0.05)
        assert "8.8.8.8" in profile.typical_ips
        assert "1.2.3.4" in profile.typical_ips
        # Private IPs should NOT be stored
        assert "10.0.1.50" not in profile.typical_ips
        assert 9 in profile.typical_hours
        assert 23 in profile.typical_hours
        assert profile.auth_failure_ratio.value > 0  # 1/3 = 33%

    def test_update_user_ewma_converges_across_runs(self, tmp_path):
        """EWMA converges to stable value after multiple runs."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        # 10 runs with 100 events each
        for _ in range(10):
            entries = [{"user": "jsmith", "action": "login", "timestamp": "2025-01-15T09:00:00Z"}] * 100
            store.update_user("jsmith", entries)
        profile = store.get_user("jsmith")
        assert profile.observation_count == 10
        # A8: single-instant batch -> 1h window convention -> rate = 100/hr;
        # A9: bias-corrected EWMA converges to the observation exactly
        assert abs(profile.typical_event_count.value - 100.0) < 1.0

    def test_update_user_accumulates_across_runs(self, tmp_path):
        """update_user accumulates observations across multiple calls."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries_run1 = [
            {"user": "jsmith", "source_ip": "8.8.8.8", "action": "login_success",
             "timestamp": "2025-01-15T09:00:00Z"},
        ]
        entries_run2 = [
            {"user": "jsmith", "source_ip": "1.2.3.4", "action": "login_success",
             "timestamp": "2025-01-15T10:00:00Z"},
        ]
        store.update_user("jsmith", entries_run1)
        store.update_user("jsmith", entries_run2)
        profile = store.get_user("jsmith")
        assert profile.observation_count == 2
        assert "8.8.8.8" in profile.typical_ips
        assert "1.2.3.4" in profile.typical_ips

    def test_update_host_processes(self, tmp_path):
        """update_host tracks processes, parents, and users."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries = [
            {"type": "endpoint", "host": "DC01", "user": "admin",
             "process": "C:\\Windows\\svchost.exe",
             "parent_process": "C:\\Windows\\services.exe",
             "action": "execute", "timestamp": "2025-01-15T09:00:00Z"},
            {"type": "endpoint", "host": "DC01", "user": "system",
             "process": "C:\\Windows\\lsass.exe",
             "parent_process": "C:\\Windows\\wininit.exe",
             "action": "execute", "timestamp": "2025-01-15T09:01:00Z"},
        ]
        store.update_host("DC01", entries)
        profile = store.get_host("DC01")
        assert profile.observation_count == 1
        assert "svchost" in profile.typical_processes
        assert "lsass" in profile.typical_processes
        assert "services" in profile.typical_parent_processes
        assert "wininit" in profile.typical_parent_processes
        assert "admin" in profile.typical_users
        assert "system" in profile.typical_users
        # R4: hour-bucketed — 2 processes within hour 9 = one bucket -> 2.0/hr
        assert profile.typical_process_count.value == pytest.approx(2.0, abs=0.05)

    def test_update_host_network(self, tmp_path):
        """update_host tracks network destinations and ports."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries = [
            {"type": "endpoint", "host": "DC01", "action": "network_connect",
             "dest_ip": "10.0.5.20", "dest_port": "443",
             "timestamp": "2025-01-15T09:00:00Z"},
            {"type": "endpoint", "host": "DC01", "action": "network_connect",
             "dest_ip": "10.0.5.21", "dest_port": "53",
             "timestamp": "2025-01-15T09:01:00Z"},
        ]
        store.update_host("DC01", entries)
        profile = store.get_host("DC01")
        assert "10.0.5.20" in profile.typical_destinations
        assert 443 in profile.typical_ports
        assert 53 in profile.typical_ports
        # A9: bias-corrected first observation = exactly 2
        assert profile.typical_network_count.value == pytest.approx(2.0, abs=0.05)

    def test_update_host_registry(self, tmp_path):
        """update_host tracks registry modifications."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries = [
            {"type": "endpoint", "host": "DC01", "action": "registry_set",
             "target_registry": "HKLM\\Software\\Run\\MyApp",
             "process": "svchost.exe", "timestamp": "2025-01-15T09:00:00Z"},
        ]
        store.update_host("DC01", entries)
        profile = store.get_host("DC01")
        assert any("Run" in k for k in profile.typical_registry_keys)

    def test_update_host_auth(self, tmp_path):
        """update_host tracks auth events and failure ratio."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries = [
            {"host": "DC01", "action": "login_success", "timestamp": "2025-01-15T09:00:00Z"},
            {"host": "DC01", "action": "login_failure", "timestamp": "2025-01-15T09:01:00Z"},
        ]
        store.update_host("DC01", entries)
        profile = store.get_host("DC01")
        # A9: bias-corrected first observation = exactly 2 (was 0.6 under zero-start)
        assert profile.typical_auth_count.value == pytest.approx(2.0, abs=0.05)
        assert profile.typical_auth_failure_ratio.value > 0

    def test_update_ip_basic(self, tmp_path):
        """update_ip tracks users, hosts, and domains."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries = [
            {"source_ip": "10.0.1.50", "user": "jsmith", "host": "DC01",
             "type": "dns", "query": "api.corp.com", "timestamp": "2025-01-15T09:00:00Z"},
        ]
        store.update_ip("10.0.1.50", entries)
        profile = store.get_ip("10.0.1.50")
        assert profile.observation_count == 1
        assert "jsmith" in profile.typical_users
        assert "DC01" in profile.typical_hosts
        assert "api.corp.com" in profile.typical_domains

    def test_size_cap_ips(self, tmp_path):
        """IP set is capped at 50 entries."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries = []
        for i in range(60):
            entries.append({
                "user": "jsmith",
                "source_ip": f"1.2.{i // 256}.{i % 256}",  # Public IPs
                "action": "login",
                "timestamp": "2025-01-15T09:00:00Z",
            })
        store.update_user("jsmith", entries)
        profile = store.get_user("jsmith")
        assert len(profile.typical_ips) <= 50

    def test_size_cap_processes(self, tmp_path):
        """Process set is capped at 200 entries."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries = []
        for i in range(250):
            entries.append({
                "type": "endpoint",
                "host": "DC01",
                "process": f"proc_{i}.exe",
                "action": "execute",
                "timestamp": "2025-01-15T09:00:00Z",
            })
        store.update_host("DC01", entries)
        profile = store.get_host("DC01")
        assert len(profile.typical_processes) <= 200

    def test_corrupted_file_starts_fresh(self, tmp_path):
        """Store starts fresh if the file is corrupted JSON."""
        path = str(tmp_path / "profiles.json")
        with open(path, "w") as f:
            f.write("{invalid json")
        store = EntityProfileStore(path)
        assert len(store.users) == 0

    def test_save_creates_directory(self, tmp_path):
        """save creates parent directories if they don't exist."""
        path = str(tmp_path / "subdir" / "profiles.json")
        store = EntityProfileStore(path)
        store.get_or_create_user("jsmith")
        store.save()
        assert os.path.exists(path)

    def test_update_user_detects_account_created_action(self, tmp_path):
        """update_user sets account_created_at from action='account_created'."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries = [
            {"user": "newuser", "action": "account_created", "timestamp": "2026-04-28T10:00:00Z"},
            {"user": "newuser", "action": "login", "timestamp": "2026-04-28T11:00:00Z"},
        ]
        store.update_user("newuser", entries)
        profile = store.get_user("newuser")
        assert profile.account_created_at == "2026-04-28T10:00:00Z"

    def test_update_user_detects_event_code_4720(self, tmp_path):
        """update_user sets account_created_at from event_code='4720'."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries = [
            {"user": "newuser2", "event_code": "4720", "timestamp": "2026-04-28T12:00:00Z"},
        ]
        store.update_user("newuser2", entries)
        profile = store.get_user("newuser2")
        assert profile.account_created_at == "2026-04-28T12:00:00Z"

    def test_update_user_does_not_overwrite_existing_created_at(self, tmp_path):
        """First creation event wins — subsequent ones don't overwrite."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries1 = [
            {"user": "newuser3", "action": "account_created", "timestamp": "2026-04-20T10:00:00Z"},
        ]
        store.update_user("newuser3", entries1)
        entries2 = [
            {"user": "newuser3", "action": "account_created", "timestamp": "2026-04-28T10:00:00Z"},
        ]
        store.update_user("newuser3", entries2)
        profile = store.get_user("newuser3")
        assert profile.account_created_at == "2026-04-20T10:00:00Z"

    def test_account_created_at_persists_across_save_load(self, tmp_path):
        """account_created_at survives save/load cycle."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        entries = [
            {"user": "persistuser", "action": "account_created", "timestamp": "2026-04-28T10:00:00Z"},
        ]
        store.update_user("persistuser", entries)
        store.save()
        store2 = EntityProfileStore(path)
        profile = store2.get_user("persistuser")
        assert profile.account_created_at == "2026-04-28T10:00:00Z"


# ---------------------------------------------------------------------------
# group_entries_by_entity tests
# ---------------------------------------------------------------------------

class TestGroupEntriesByEntity:
    """Tests for the group_entries_by_entity helper."""

    def test_groups_by_user(self):
        """Entries are grouped by user."""
        entries = [
            {"user": "jsmith", "action": "login"},
            {"user": "jsmith", "action": "logout"},
            {"user": "admin", "action": "login"},
        ]
        groups = group_entries_by_entity(entries)
        assert len(groups[("user", "jsmith")]) == 2
        assert len(groups[("user", "admin")]) == 1

    def test_groups_by_host(self):
        """Entries are grouped by host."""
        entries = [
            {"host": "DC01", "type": "endpoint"},
            {"Computer": "WS01", "type": "endpoint"},
        ]
        groups = group_entries_by_entity(entries)
        assert ("host", "DC01") in groups
        assert ("host", "WS01") in groups

    def test_groups_by_ip(self):
        """Entries are grouped by source IP."""
        entries = [
            {"source_ip": "10.0.1.50", "action": "connect"},
            {"src_ip": "10.0.1.51", "action": "connect"},
        ]
        groups = group_entries_by_entity(entries)
        assert ("ip", "10.0.1.50") in groups
        assert ("ip", "10.0.1.51") in groups

    def test_entry_appears_in_multiple_groups(self):
        """An entry with user, host, and IP appears in all three groups."""
        entries = [
            {"user": "jsmith", "host": "DC01", "source_ip": "10.0.1.50"},
        ]
        groups = group_entries_by_entity(entries)
        assert ("user", "jsmith") in groups
        assert ("host", "DC01") in groups
        assert ("ip", "10.0.1.50") in groups

    def test_empty_entries(self):
        """Empty list returns empty dict."""
        groups = group_entries_by_entity([])
        assert len(groups) == 0

    def test_entries_without_entity_fields(self):
        """Entries with no user/host/ip are not grouped."""
        entries = [{"action": "heartbeat", "timestamp": "2025-01-15T09:00:00Z"}]
        groups = group_entries_by_entity(entries)
        assert len(groups) == 0


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestHelpers:
    """Tests for internal helper functions."""

    def test_capped_set_no_truncation(self):
        """_capped_set doesn't truncate sets within limit."""
        s = {"a", "b", "c"}
        result = _capped_set(s, 5)
        assert len(result) == 3

    def test_capped_set_truncates(self):
        """_capped_set truncates sets exceeding limit."""
        s = {str(i) for i in range(10)}
        result = _capped_set(s, 5)
        assert len(result) == 5

    def testis_off_hours_night(self):
        """is_off_hours returns True for 23:00."""
        assert is_off_hours("2025-01-15T23:00:00Z") is True

    def testis_off_hours_early_morning(self):
        """is_off_hours returns True for 03:00."""
        assert is_off_hours("2025-01-15T03:00:00Z") is True

    def test_is_not_off_hours_daytime(self):
        """is_off_hours returns False for 14:00."""
        assert is_off_hours("2025-01-15T14:00:00Z") is False

    def testis_off_hours_boundary_6am(self):
        """is_off_hours returns False for 06:00 (boundary)."""
        assert is_off_hours("2025-01-15T06:00:00Z") is False

    def testis_off_hours_boundary_10pm(self):
        """is_off_hours returns True for 22:00 (boundary)."""
        assert is_off_hours("2025-01-15T22:00:00Z") is True

    def testis_off_hours_invalid_timestamp(self):
        """is_off_hours returns False for invalid timestamps."""
        assert is_off_hours("") is False
        assert is_off_hours("invalid") is False


# --- is_routable_ip (baselines copy) ---

class TestBaselinesIsRoutableIP:
    """Tests for the baselines copy of is_routable_ip."""

    def test_private_ips_not_routable(self):
        """Private IPs are not routable."""
        assert is_routable_ip("10.0.0.1") is False
        assert is_routable_ip("172.31.94.24") is False
        assert is_routable_ip("192.168.1.1") is False

    def test_loopback_not_routable(self):
        """Loopback is not routable."""
        assert is_routable_ip("127.0.0.1") is False
        assert is_routable_ip("::1") is False

    def test_public_ips_routable(self):
        """Public IPs are routable."""
        assert is_routable_ip("8.8.8.8") is True
        assert is_routable_ip("1.2.3.4") is True


# --- typical_ips filtering ---

class TestTypicalIPsFiltering:
    """Tests that typical_ips only stores routable IPs."""

    def test_update_user_stores_only_routable_ips(self):
        """update_user should only add public IPs to typical_ips."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            store = EntityProfileStore(path)
            entries = [
                {"source_ip": "8.8.8.8", "action": "login", "user": "alice", "timestamp": "2026-01-15T10:00:00Z"},
                {"source_ip": "172.31.94.24", "action": "login", "user": "alice", "timestamp": "2026-01-15T10:01:00Z"},
                {"source_ip": "10.0.1.5", "action": "login", "user": "alice", "timestamp": "2026-01-15T10:02:00Z"},
                {"source_ip": "1.2.3.4", "action": "login", "user": "alice", "timestamp": "2026-01-15T10:03:00Z"},
            ]
            store.update_user("alice", entries)
            profile = store.get_user("alice")
            assert profile is not None
            assert "8.8.8.8" in profile.typical_ips
            assert "1.2.3.4" in profile.typical_ips
            # Private IPs should NOT be in typical_ips
            assert "172.31.94.24" not in profile.typical_ips
            assert "10.0.1.5" not in profile.typical_ips
        finally:
            os.unlink(path)
