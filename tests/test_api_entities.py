"""Tests for nabla.api.entities — /api/entities endpoints."""

import json
import os
import pathlib

import pytest


def _write_profiles(temp_data_dir, profiles):
    """Write entity profiles to the temp data dir."""
    path = os.path.join(temp_data_dir, "entity_profiles.json")
    with open(path, "w") as f:
        json.dump(profiles, f)


class TestListEntities:
    """Test GET /api/entities."""

    def test_list_empty(self, app_client):
        """Empty profiles returns empty list."""
        resp = app_client.get("/api/entities")
        assert resp.status_code == 200
        data = resp.json()
        assert data["entities"] == []
        assert data["total"] == 0

    def test_list_returns_all_types(self, app_client, temp_data_dir):
        """List includes users, hosts, and IPs."""
        _write_profiles(temp_data_dir, {
            "users": {"alice": {"observation_count": 5, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None}},
            "hosts": {"server1": {"observation_count": 3, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}}},
            "ips": {"1.2.3.4": {"observation_count": 10, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}}},
        })
        resp = app_client.get("/api/entities")
        data = resp.json()
        assert data["total"] == 3
        types = {e["type"] for e in data["entities"]}
        assert types == {"user", "host", "ip"}

    def test_list_filter_by_type(self, app_client, temp_data_dir):
        """Filter by type=user returns only users."""
        _write_profiles(temp_data_dir, {
            "users": {"alice": {"observation_count": 5, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None}},
            "hosts": {"server1": {"observation_count": 3, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}}},
            "ips": {},
        })
        resp = app_client.get("/api/entities?type=user")
        data = resp.json()
        assert data["total"] == 1
        assert data["entities"][0]["type"] == "user"

    def test_list_search(self, app_client, temp_data_dir):
        """Search filters by entity ID substring."""
        _write_profiles(temp_data_dir, {
            "users": {
                "alice": {"observation_count": 5, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None},
                "bob": {"observation_count": 2, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None},
            },
            "hosts": {},
            "ips": {},
        })
        resp = app_client.get("/api/entities?search=ali")
        data = resp.json()
        assert data["total"] == 1
        assert data["entities"][0]["id"] == "alice"

    def test_list_search_case_insensitive(self, app_client, temp_data_dir):
        """Search is case-insensitive."""
        _write_profiles(temp_data_dir, {
            "users": {"Alice": {"observation_count": 5, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None}},
            "hosts": {},
            "ips": {},
        })
        resp = app_client.get("/api/entities?search=alice")
        data = resp.json()
        assert data["total"] == 1

    def test_list_filter_warm(self, app_client, temp_data_dir):
        """Filter by warm=true returns only entities with >= 3 observations."""
        _write_profiles(temp_data_dir, {
            "users": {
                "alice": {"observation_count": 5, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None},
                "bob": {"observation_count": 1, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None},
            },
            "hosts": {},
            "ips": {},
        })
        resp = app_client.get("/api/entities?warm=true")
        data = resp.json()
        assert data["total"] == 1
        assert data["entities"][0]["id"] == "alice"

    def test_list_pagination(self, app_client, temp_data_dir):
        """Pagination with limit and offset."""
        users = {f"user{i}": {"observation_count": i + 1, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None} for i in range(10)}
        _write_profiles(temp_data_dir, {"users": users, "hosts": {}, "ips": {}})

        resp = app_client.get("/api/entities?limit=3&offset=0")
        data = resp.json()
        assert len(data["entities"]) == 3
        assert data["total"] == 10

        resp2 = app_client.get("/api/entities?limit=3&offset=3")
        data2 = resp2.json()
        assert len(data2["entities"]) == 3
        # Different page
        ids1 = {e["id"] for e in data["entities"]}
        ids2 = {e["id"] for e in data2["entities"]}
        assert ids1.isdisjoint(ids2)

    def test_list_entity_has_required_fields(self, app_client, temp_data_dir):
        """Each entity in the list has required fields."""
        _write_profiles(temp_data_dir, {
            "users": {"alice": {"observation_count": 5, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None}},
            "hosts": {},
            "ips": {},
        })
        resp = app_client.get("/api/entities")
        data = resp.json()
        entity = data["entities"][0]
        for field in ("id", "type", "observation_count", "first_seen", "last_seen", "warm"):
            assert field in entity, f"Missing field: {field}"


class TestGetEntity:
    """Test GET /api/entities/{entity_id}."""

    def test_get_entity_found(self, app_client, temp_data_dir):
        """Get an existing entity by ID."""
        _write_profiles(temp_data_dir, {
            "users": {"alice": {"observation_count": 5, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": ["1.2.3.4"], "ewma": {"auth_failure_ratio": 0.1}, "account_created_at": None}},
            "hosts": {},
            "ips": {},
        })
        resp = app_client.get("/api/entities/alice")
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "user"
        assert data["observation_count"] == 5

    def test_get_entity_not_found(self, app_client):
        """Get a non-existent entity returns 404."""
        resp = app_client.get("/api/entities/nonexistent")
        assert resp.status_code == 404

    def test_get_entity_host(self, app_client, temp_data_dir):
        """Get a host entity."""
        _write_profiles(temp_data_dir, {
            "users": {},
            "hosts": {"server1": {"observation_count": 3, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}}},
            "ips": {},
        })
        resp = app_client.get("/api/entities/server1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "host"

    def test_get_entity_ip(self, app_client, temp_data_dir):
        """Get an IP entity."""
        _write_profiles(temp_data_dir, {
            "users": {},
            "hosts": {},
            "ips": {"1.2.3.4": {"observation_count": 10, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}}},
        })
        resp = app_client.get("/api/entities/1.2.3.4")
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "ip"

    def test_get_entity_includes_warm(self, app_client, temp_data_dir):
        """Entity detail includes warm flag."""
        _write_profiles(temp_data_dir, {
            "users": {"alice": {"observation_count": 5, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None}},
            "hosts": {},
            "ips": {},
        })
        resp = app_client.get("/api/entities/alice")
        data = resp.json()
        assert data["warm"] is True

    def test_get_entity_environment_facts(self, app_client, temp_data_dir):
        """Entity detail includes environment facts if declared."""
        _write_profiles(temp_data_dir, {
            "users": {"alice": {"observation_count": 5, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None}},
            "hosts": {},
            "ips": {},
        })
        # Write environment context with entity facts
        env_path = os.path.join(temp_data_dir, "environment_context.json")
        with open(env_path, "w") as f:
            json.dump({"entities": {"alice": ["Service account for CI/CD"]}}, f)

        resp = app_client.get("/api/entities/alice")
        data = resp.json()
        assert "environment_facts" in data
        assert data["environment_facts"] == ["Service account for CI/CD"]


class TestPhase2MachineAndQuarantine:
    """Phase 2 (mockup 04): the entities list carries the machine-
    account flag (F5/N9 — the SAME predicate baselining uses) and the
    quarantine state with its data-clock TTL (N3/N5)."""

    def _profiles(self, tmp):
        _write_profiles(tmp, {
            "users": {
                "alice": {"observation_count": 5, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None},
                "svc-jenkins": {"observation_count": 50, "first_seen": "2025-01-01", "last_seen": "2025-01-02", "typical_ips": [], "ewma": {}, "account_created_at": None},
            },
            "hosts": {}, "ips": {},
        })

    def test_machine_account_flagged(self, app_client, temp_data_dir):
        self._profiles(temp_data_dir)
        data = app_client.get("/api/entities").json()
        flags = {e["id"]: e["is_machine"] for e in data["entities"]}
        assert flags["svc-jenkins"] is True
        assert flags["alice"] is False

    def test_quarantine_none_when_absent(self, app_client, temp_data_dir):
        self._profiles(temp_data_dir)
        data = app_client.get("/api/entities").json()
        assert all(e["quarantine"] is None for e in data["entities"])

    def test_quarantine_state_in_list(self, app_client, temp_data_dir):
        """TP hold anchored 1 day before the data clock (wall fallback)
        -> held with 13 data-clock days left."""
        import json as _json
        from datetime import datetime, timedelta, timezone
        self._profiles(temp_data_dir)
        since = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        pathlib.Path(os.path.join(temp_data_dir, "baseline_quarantine.json")).write_text(_json.dumps({
            "alice": {"held": True, "since": since, "batches_held": 2, "tp_hold_days": 14},
        }))
        data = app_client.get("/api/entities").json()
        q = {e["id"]: e["quarantine"] for e in data["entities"]}["alice"]
        assert q is not None and q["held"] is True
        assert q["tp_hold"] is True
        assert q["days_left"] == 13
        assert q["batches_held"] == 2

    def test_expired_hold_reads_not_held(self, app_client, temp_data_dir):
        """A hold older than its TTL is NOT held — the summary must say
        so (the UI shows ACTIVE, and the pipeline re-arms on new fire)."""
        import json as _json
        from datetime import datetime, timedelta, timezone
        self._profiles(temp_data_dir)
        since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        pathlib.Path(os.path.join(temp_data_dir, "baseline_quarantine.json")).write_text(_json.dumps({
            "alice": {"held": True, "since": since, "batches_held": 1},
        }))
        data = app_client.get("/api/entities").json()
        q = {e["id"]: e["quarantine"] for e in data["entities"]}["alice"]
        assert q["held"] is False
        assert q["days_left"] is None

    def test_held_events_counted_from_pending_store(self, app_client, temp_data_dir):
        import json as _json
        from datetime import datetime, timedelta, timezone
        self._profiles(temp_data_dir)
        since = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        pathlib.Path(os.path.join(temp_data_dir, "baseline_quarantine.json")).write_text(_json.dumps({
            "alice": {"held": True, "since": since, "batches_held": 1},
        }))
        pathlib.Path(os.path.join(temp_data_dir, "baseline_pending.json")).write_text(_json.dumps({
            "alice": [{"batch_uid": "b1", "source_kind": "file", "entries": [{"event_id": f"e{i}"} for i in range(20)]}],
        }))
        data = app_client.get("/api/entities").json()
        q = {e["id"]: e["quarantine"] for e in data["entities"]}["alice"]
        assert q["held_events"] == 20

    def test_detail_carries_machine_and_quarantine(self, app_client, temp_data_dir):
        self._profiles(temp_data_dir)
        d1 = app_client.get("/api/entities/svc-jenkins").json()
        assert d1["is_machine"] is True
        assert d1["quarantine"] is None
        d2 = app_client.get("/api/entities/alice").json()
        assert d2["is_machine"] is False
