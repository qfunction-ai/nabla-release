"""Tests for nabla.api.config — /api/config endpoints."""

import json
import os
from unittest.mock import patch, MagicMock

import pytest


class TestWatchlists:
    """Test GET/PUT /api/config/watchlists."""

    def test_get_watchlists_empty(self, app_client):
        """Empty watchlists returns empty dict."""
        resp = app_client.get("/api/config/watchlists")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_get_watchlists_with_data(self, app_client, temp_data_dir):
        """Returns watchlist groups (built-in + user-defined)."""
        # Write a watchlist with a user-defined group
        path = os.path.join(temp_data_dir, "watchlists.json")
        with open(path, "w") as f:
            json.dump({"admin_accounts": ["alice", "bob"]}, f)

        resp = app_client.get("/api/config/watchlists")
        data = resp.json()
        # get_all_entities returns built-in groups (users, hosts, ips)
        # plus any user-defined groups that match the built-in structure
        assert isinstance(data, dict)
        assert "users" in data or "admin_accounts" in data

    def test_put_watchlists(self, app_client, temp_data_dir):
        """Replace watchlist configuration."""
        resp = app_client.put(
            "/api/config/watchlists",
            json={"groups": {"service_accounts": ["svc1", "svc2"]}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "service_accounts" in data

        # Verify persisted
        path = os.path.join(temp_data_dir, "watchlists.json")
        with open(path) as f:
            stored = json.load(f)
        assert "service_accounts" in stored

    def test_put_watchlists_dangerous_chars(self, app_client):
        """Watchlist with dangerous characters in entity values is rejected."""
        resp = app_client.put(
            "/api/config/watchlists",
            json={"groups": {"bad": ["user;rm -rf"]}},
        )
        assert resp.status_code == 422


class TestEnvironment:
    """Test GET/PUT /api/config/environment."""

    def test_get_environment_empty(self, app_client):
        """Empty environment returns defaults."""
        resp = app_client.get("/api/config/environment")
        assert resp.status_code == 200
        data = resp.json()
        assert "environment" in data
        assert "entities" in data
        assert "network_ranges" in data

    def test_get_environment_with_data(self, app_client, temp_data_dir):
        """Returns stored environment context."""
        path = os.path.join(temp_data_dir, "environment_context.json")
        with open(path, "w") as f:
            json.dump({
                "environment": ["AWS VPC us-east-1"],
                "entities": {"alice": ["Service account"]},
                "network_ranges": ["10.0.0.0/8"],
                "new_accounts": [],
                "service_accounts": ["alice"],
                "admin_accounts": ["bob"],
                "benign_patterns": ["Scheduled cron jobs"],
            }, f)

        resp = app_client.get("/api/config/environment")
        data = resp.json()
        assert data["environment"] == ["AWS VPC us-east-1"]
        assert data["service_accounts"] == ["alice"]

    def test_put_environment(self, app_client, temp_data_dir):
        """Update environment context."""
        resp = app_client.put(
            "/api/config/environment",
            json={
                "environment": ["Test env"],
                "entities": {},
                "network_ranges": ["192.168.0.0/16"],
                "new_accounts": [],
                "service_accounts": [],
                "admin_accounts": ["admin"],
                "benign_patterns": [],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["environment"] == ["Test env"]

        # Verify persisted
        path = os.path.join(temp_data_dir, "environment_context.json")
        with open(path) as f:
            stored = json.load(f)
        assert stored["environment"] == ["Test env"]

    def test_put_environment_dangerous_entity_name(self, app_client):
        """Entity name with dangerous characters is rejected."""
        resp = app_client.put(
            "/api/config/environment",
            json={
                "environment": [],
                "entities": {"user;rm": ["fact"]},
                "network_ranges": [],
                "new_accounts": [],
                "service_accounts": [],
                "admin_accounts": [],
                "benign_patterns": [],
            },
        )
        assert resp.status_code == 422


class TestSchedule:
    """Test GET/PUT /api/config/schedule."""

    def test_get_schedule(self, app_client):
        """Schedule endpoint returns current config."""
        with patch("nabla.scheduler.scheduler_status", return_value={"running": False}):
            resp = app_client.get("/api/config/schedule")
        assert resp.status_code == 200
        data = resp.json()
        assert "running" in data
        assert "interval" in data
        assert "log_types" in data
        assert "log_count" in data

    def test_put_schedule_stop(self, app_client):
        """Stop the scheduler."""
        with patch("nabla.scheduler.stop_scheduler"):
            resp = app_client.put(
                "/api/config/schedule",
                json={"enabled": False, "interval": 5},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["running"] is False

    def test_put_schedule_start(self, app_client):
        """Start the scheduler."""
        with patch("nabla.scheduler.start_scheduler"), \
             patch("nabla.pipeline._resolve_log_types", return_value=["auth"]):
            resp = app_client.put(
                "/api/config/schedule",
                json={"enabled": True, "interval": 10, "log_types": "auth", "log_count": 50},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["running"] is True


class TestConnectors:
    """Test GET /api/config/connectors."""

    def test_get_connectors(self, app_client):
        """Connectors endpoint returns status for splunk and sumologic."""
        resp = app_client.get("/api/config/connectors")
        assert resp.status_code == 200
        data = resp.json()
        assert "splunk" in data
        assert "sumologic" in data
        assert "configured" in data["splunk"]
        assert "configured" in data["sumologic"]

    def test_connectors_not_configured(self, app_client):
        """When no connector hosts are set, both show unconfigured."""
        resp = app_client.get("/api/config/connectors")
        data = resp.json()
        assert data["splunk"]["configured"] is False
        assert data["sumologic"]["configured"] is False
