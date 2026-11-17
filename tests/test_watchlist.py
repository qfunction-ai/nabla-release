"""Tests for watchlist CRUD operations."""

import json
import os
import tempfile

from nabla.watchlist import (
    add_entity,
    get_all_entities,
    list_groups,
    load_watchlist,
    remove_entity,
    save_watchlist,
)


def _tmp_watchlist():
    """Create a temp watchlist file path."""
    d = tempfile.mkdtemp()
    return os.path.join(d, "watchlists.json")


def test_load_creates_default():
    path = _tmp_watchlist()
    data = load_watchlist(path)
    assert "high_value_users" in data
    assert "critical_systems" in data
    assert "watched_ips" in data
    assert data["high_value_users"] == []
    assert os.path.exists(path)


def test_add_entity_builtin_group():
    path = _tmp_watchlist()
    add_entity(path, "high_value_users", "admin")
    data = load_watchlist(path)
    assert "admin" in data["high_value_users"]


def test_add_entity_duplicate():
    path = _tmp_watchlist()
    add_entity(path, "high_value_users", "admin")
    add_entity(path, "high_value_users", "admin")  # no-op
    data = load_watchlist(path)
    assert data["high_value_users"].count("admin") == 1


def test_add_entity_custom_group():
    path = _tmp_watchlist()
    add_entity(path, "onboarded", "newuser1")
    data = load_watchlist(path)
    assert "onboarded" in data["custom_groups"]
    assert "newuser1" in data["custom_groups"]["onboarded"]


def test_remove_entity():
    path = _tmp_watchlist()
    add_entity(path, "high_value_users", "admin")
    add_entity(path, "high_value_users", "jsmith")
    remove_entity(path, "high_value_users", "admin")
    data = load_watchlist(path)
    assert "admin" not in data["high_value_users"]
    assert "jsmith" in data["high_value_users"]


def test_remove_entity_not_present():
    path = _tmp_watchlist()
    add_entity(path, "high_value_users", "admin")
    remove_entity(path, "high_value_users", "nobody")  # no-op
    data = load_watchlist(path)
    assert data["high_value_users"] == ["admin"]


def test_remove_empty_custom_group():
    path = _tmp_watchlist()
    add_entity(path, "onboarded", "newuser1")
    remove_entity(path, "onboarded", "newuser1")
    data = load_watchlist(path)
    assert "onboarded" not in data.get("custom_groups", {})


def test_list_groups():
    path = _tmp_watchlist()
    add_entity(path, "high_value_users", "admin")
    add_entity(path, "watched_ips", "10.0.1.50")
    groups = list_groups(path)
    assert "admin" in groups["high_value_users"]
    assert "10.0.1.50" in groups["watched_ips"]
    assert groups["critical_systems"] == []


def test_get_all_entities():
    path = _tmp_watchlist()
    add_entity(path, "high_value_users", "admin")
    add_entity(path, "critical_systems", "SERVER-DC01")
    add_entity(path, "watched_ips", "10.0.1.50")
    add_entity(path, "onboarded", "newuser1")  # custom group → users
    entities = get_all_entities(path)
    assert "admin" in entities["users"]
    assert "newuser1" in entities["users"]
    assert "SERVER-DC01" in entities["hosts"]
    assert "10.0.1.50" in entities["ips"]


def test_get_all_entities_ip_custom_group():
    path = _tmp_watchlist()
    add_entity(path, "vpn_ips", "10.0.1.100")  # contains "ip" → ips
    entities = get_all_entities(path)
    assert "10.0.1.100" in entities["ips"]


def test_get_all_entities_host_custom_group():
    path = _tmp_watchlist()
    add_entity(path, "web_servers", "WEB-01")  # contains "server" → hosts
    entities = get_all_entities(path)
    assert "WEB-01" in entities["hosts"]


def test_deduplication():
    path = _tmp_watchlist()
    add_entity(path, "high_value_users", "admin")
    add_entity(path, "onboarded", "admin")  # same user in custom group
    entities = get_all_entities(path)
    assert entities["users"].count("admin") == 1  # deduplicated
