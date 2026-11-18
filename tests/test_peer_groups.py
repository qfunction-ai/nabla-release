"""Tests for nabla.peer_groups — peer group analysis."""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from nabla.peer_groups import (
    PeerGroup,
    PeerGroupStore,
    _auto_label,
    _euclidean_distance,
    _extract_user_features,
    _kmeans,
    _normalize_features,
)


# ---------------------------------------------------------------------------
# PeerGroup
# ---------------------------------------------------------------------------

class TestPeerGroup:
    def test_roundtrip(self):
        pg = PeerGroup(
            group_id="user_0",
            entity_type="user",
            members=["alice", "bob"],
            centroid={"event_count": 0.5},
            label="high event_count",
        )
        d = pg.to_dict()
        restored = PeerGroup.from_dict(d)
        assert restored.group_id == "user_0"
        assert restored.members == ["alice", "bob"]
        assert restored.label == "high event_count"


# ---------------------------------------------------------------------------
# PeerGroupStore
# ---------------------------------------------------------------------------

class TestPeerGroupStore:
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "peer_groups.json")
            store = PeerGroupStore(path)
            pg = PeerGroup(group_id="user_0", entity_type="user", members=["alice", "bob"])
            store.groups["user_0"] = pg
            store._rebuild_index()
            store.save()

            store2 = PeerGroupStore(path)
            assert store2.get_group("user_0") is not None
            assert "alice" in store2.get_group("user_0").members

    def test_get_group_for_entity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "peer_groups.json")
            store = PeerGroupStore(path)
            pg = PeerGroup(group_id="user_0", entity_type="user", members=["alice", "bob"])
            store.groups["user_0"] = pg
            store._rebuild_index()
            assert store.get_group_for_entity("alice") is not None
            assert store.get_group_for_entity("charol") is None

    def test_list_groups_by_type(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "peer_groups.json")
            store = PeerGroupStore(path)
            store.groups["user_0"] = PeerGroup(group_id="user_0", entity_type="user")
            store.groups["host_0"] = PeerGroup(group_id="host_0", entity_type="host")
            assert len(store.list_groups("user")) == 1
            assert len(store.list_groups("host")) == 1
            assert len(store.list_groups()) == 2

    def test_handles_corrupt_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "peer_groups.json")
            with open(path, "w") as f:
                f.write("not json")
            store = PeerGroupStore(path)
            assert len(store.groups) == 0


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

class TestExtractUserFeatures:
    def test_extracts_features(self):
        from nabla.baselines import UserProfile
        profile = UserProfile(entity_id="alice", observation_count=5)
        profile.typical_event_count.update(100)
        profile.typical_ips.add("1.2.3.4")
        for h in (9, 10, 11, 14, 15):
            profile.typical_hours.add(h)
        profile.auth_failure_ratio.update(0.1)
        profile.off_hours_ratio.update(0.05)
        profile.typical_actions = {"login": 0.5, "file_access": 0.3}

        features = _extract_user_features(profile)
        assert "event_count" in features
        assert "unique_ips" in features
        assert features["unique_ips"] == 1.0  # 1 IP
        assert features["active_hours"] == 5.0  # 5 hours
        assert features["action_types"] == 2.0  # 2 action types


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

class TestNormalizeFeatures:
    def test_normalizes_to_0_1(self):
        features = {
            "alice": {"event_count": 10, "off_hours": 0.1},
            "bob": {"event_count": 50, "off_hours": 0.9},
        }
        normalized = _normalize_features(features)
        assert normalized["alice"]["event_count"] == 0.0
        assert normalized["bob"]["event_count"] == 1.0
        assert normalized["alice"]["off_hours"] == 0.0
        assert normalized["bob"]["off_hours"] == 1.0

    def test_empty_input(self):
        assert _normalize_features({}) == {}

    def test_single_entity(self):
        features = {"alice": {"event_count": 10}}
        normalized = _normalize_features(features)
        # All same → 0.5 (no range)
        assert normalized["alice"]["event_count"] == 0.5


# ---------------------------------------------------------------------------
# K-means
# ---------------------------------------------------------------------------

class TestKMeans:
    def test_two_clear_clusters(self):
        # Two clearly separated groups
        features = {
            "a": {"x": 0.0, "y": 0.0},
            "b": {"x": 0.1, "y": 0.1},
            "c": {"x": 0.9, "y": 0.9},
            "d": {"x": 0.95, "y": 0.85},
        }
        clusters, centroids, inertia = _kmeans(list(features.keys()), features, k=2)
        assert len(clusters) == 2
        # a and b should be together, c and d together
        for cluster in clusters:
            if "a" in cluster:
                assert "b" in cluster
                assert "c" not in cluster
            else:
                assert "c" in cluster
                assert "d" in cluster

    def test_fewer_entities_than_k(self):
        features = {"a": {"x": 0.0}, "b": {"x": 1.0}}
        clusters, centroids, inertia = _kmeans(list(features.keys()), features, k=5)
        assert len(clusters) == 2  # Each entity gets its own cluster

    def test_empty_features(self):
        features = {"a": {}, "b": {}}
        clusters, centroids, inertia = _kmeans(list(features.keys()), features, k=2)
        assert len(clusters) == 2


# ---------------------------------------------------------------------------
# Euclidean distance
# ---------------------------------------------------------------------------

class TestEuclideanDistance:
    def test_identical(self):
        assert _euclidean_distance({"x": 1.0}, {"x": 1.0}) == 0.0

    def test_different(self):
        d = _euclidean_distance({"x": 0.0, "y": 0.0}, {"x": 3.0, "y": 4.0})
        assert abs(d - 5.0) < 0.01

    def test_missing_keys(self):
        d = _euclidean_distance({"x": 1.0}, {"x": 1.0, "y": 1.0})
        assert d > 0


# ---------------------------------------------------------------------------
# Auto-label
# ---------------------------------------------------------------------------

class TestAutoLabel:
    def test_high_label(self):
        centroid = {"event_count": 0.9, "off_hours": 0.1}
        all_centroids = [centroid, {"event_count": 0.1, "off_hours": 0.2}]
        label = _auto_label(centroid, all_centroids)
        assert "high" in label
        assert "event count" in label

    def test_low_label(self):
        centroid = {"event_count": 0.1, "off_hours": 0.1}
        all_centroids = [centroid, {"event_count": 0.8, "off_hours": 0.8}]
        label = _auto_label(centroid, all_centroids)
        assert "low" in label

    def test_empty_centroids(self):
        assert _auto_label({}, []) == "default"
