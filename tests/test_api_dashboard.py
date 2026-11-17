"""Tests for nabla.api.dashboard — /api/dashboard endpoint."""

import json
import os
from unittest.mock import patch, MagicMock

import pytest


class TestDashboard:
    """Test the /api/dashboard endpoint."""

    def test_dashboard_returns_200(self, app_client):
        """Dashboard endpoint returns 200 with valid structure."""
        resp = app_client.get("/api/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        # Required top-level keys
        assert "phase" in data
        assert "health" in data
        assert "entity_counts" in data
        assert "incident_stats" in data
        assert "recent_runs" in data
        assert "recent_incidents" in data
        assert "warm_up" in data

    def test_dashboard_phase_values(self, app_client):
        """Phase is one of the valid values."""
        resp = app_client.get("/api/dashboard")
        data = resp.json()
        assert data["phase"] in ("baseline", "detection")

    def test_dashboard_health_structure(self, app_client):
        """Health section has letta and ollama with healthy bool."""
        resp = app_client.get("/api/dashboard")
        data = resp.json()
        health = data["health"]
        assert "letta" in health
        assert "ollama" in health
        assert "healthy" in health["letta"]
        assert "healthy" in health["ollama"]

    def test_dashboard_entity_counts(self, app_client):
        """Entity counts has users, hosts, ips."""
        resp = app_client.get("/api/dashboard")
        data = resp.json()
        counts = data["entity_counts"]
        assert "users" in counts
        assert "hosts" in counts
        assert "ips" in counts
        assert all(isinstance(counts[k], int) for k in ("users", "hosts", "ips"))

    def test_dashboard_warm_up_structure(self, app_client):
        """Warm-up section has per-type breakdown."""
        resp = app_client.get("/api/dashboard")
        data = resp.json()
        wu = data["warm_up"]
        for entity_type in ("users", "hosts", "ips"):
            assert entity_type in wu
            assert "total" in wu[entity_type]
            assert "warm" in wu[entity_type]
            assert "pct" in wu[entity_type]

    def test_dashboard_letta_healthy(self, app_client, mock_letta_client):
        """When Letta client.health() returns ok, dashboard shows healthy."""
        mock_letta_client.health.return_value = MagicMock(status="ok", version="0.16.7")
        resp = app_client.get("/api/dashboard")
        data = resp.json()
        assert data["health"]["letta"]["healthy"] is True

    def test_dashboard_letta_unhealthy(self, app_client, mock_letta_client):
        """When Letta client.health() raises, dashboard shows unhealthy."""
        mock_letta_client.health.side_effect = Exception("Connection refused")
        resp = app_client.get("/api/dashboard")
        data = resp.json()
        assert data["health"]["letta"]["healthy"] is False
        assert data["health"]["letta"]["detail"] == "unreachable"

    def test_dashboard_recent_runs_is_list(self, app_client):
        """Recent runs is a list."""
        resp = app_client.get("/api/dashboard")
        data = resp.json()
        assert isinstance(data["recent_runs"], list)

    def test_dashboard_recent_incidents_is_list(self, app_client):
        """Recent incidents is a list."""
        resp = app_client.get("/api/dashboard")
        data = resp.json()
        assert isinstance(data["recent_incidents"], list)

    def test_dashboard_with_empty_profiles(self, app_client):
        """Dashboard works with empty entity profiles."""
        resp = app_client.get("/api/dashboard")
        data = resp.json()
        # All counts should be 0 with empty profiles
        assert data["entity_counts"]["users"] == 0
        assert data["entity_counts"]["hosts"] == 0
        assert data["entity_counts"]["ips"] == 0

    def test_dashboard_with_populated_profiles(self, app_client, temp_data_dir):
        """Dashboard shows correct counts when profiles exist."""
        profiles = {
            "users": {
                "alice": {"observation_count": 5, "first_seen": "2025-01-01", "last_seen": "2025-01-02"},
                "bob": {"observation_count": 2, "first_seen": "2025-01-01", "last_seen": "2025-01-02"},
            },
            "hosts": {
                "server1": {"observation_count": 10, "first_seen": "2025-01-01", "last_seen": "2025-01-02"},
            },
            "ips": {
                "1.2.3.4": {"observation_count": 3, "first_seen": "2025-01-01", "last_seen": "2025-01-02"},
                "5.6.7.8": {"observation_count": 1, "first_seen": "2025-01-01", "last_seen": "2025-01-02"},
                "9.10.11.12": {"observation_count": 7, "first_seen": "2025-01-01", "last_seen": "2025-01-02"},
            },
        }
        path = os.path.join(temp_data_dir, "entity_profiles.json")
        with open(path, "w") as f:
            json.dump(profiles, f)

        resp = app_client.get("/api/dashboard")
        data = resp.json()
        assert data["entity_counts"]["users"] == 2
        assert data["entity_counts"]["hosts"] == 1
        assert data["entity_counts"]["ips"] == 3
