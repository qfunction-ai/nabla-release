"""Peer group analysis — cluster entities by behavioral similarity.

Groups entities into peer groups using K-means clustering on behavioral
features extracted from entity profiles. Peer groups enable three things:

1. Contextual baseline comparison: "unusual for this user's peers" vs
   "unusual for everyone"
2. Risk score dampening: anomalies common among peers get dampened
3. Risk score boosting: anomalies unique to an entity get boosted

Grouping algorithm:
- Extract feature vectors from entity profiles (EWMA values, set sizes,
  activity patterns)
- Normalize to [0, 1]
- K-means with k = sqrt(n_entities), capped at 20
- Run 3 iterations, pick best inertia
- Auto-label by most-discriminating feature
- Re-cluster every N pipeline runs (configurable, default 10)
"""

from __future__ import annotations

import json
import math
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from nabla.log import get_logger
from nabla.persistence import atomic_write_json

if TYPE_CHECKING:
    from nabla.baselines import EntityProfileStore, UserProfile, HostProfile, IPProfile

logger = get_logger("peer_groups")


# ---------------------------------------------------------------------------
# Peer group data structures
# ---------------------------------------------------------------------------

@dataclass
class PeerGroup:
    """A group of behaviorally similar entities.

    Attributes:
        group_id: Unique identifier (e.g., "user_0", "host_2").
        entity_type: "user", "host", or "ip".
        members: List of entity IDs in this group.
        centroid: Behavioral centroid (mean feature values).
        label: Auto-generated human-readable label.
        created_at: ISO timestamp of group creation.
        updated_at: ISO timestamp of last update.
        peer_anomaly_summary: Recent anomaly method counts per member.
    """

    group_id: str = ""
    entity_type: str = "user"
    members: list[str] = field(default_factory=list)
    centroid: dict[str, float] = field(default_factory=dict)
    label: str = ""
    created_at: str = ""
    updated_at: str = ""
    peer_anomaly_summary: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict."""
        return {
            "group_id": self.group_id,
            "entity_type": self.entity_type,
            "members": self.members,
            "centroid": self.centroid,
            "label": self.label,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "peer_anomaly_summary": self.peer_anomaly_summary,
        }

    @classmethod
    def from_dict(cls, data: dict) -> PeerGroup:
        """Deserialize from a dict."""
        return cls(
            group_id=data.get("group_id", ""),
            entity_type=data.get("entity_type", "user"),
            members=data.get("members", []),
            centroid=data.get("centroid", {}),
            label=data.get("label", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            peer_anomaly_summary=data.get("peer_anomaly_summary", {}),
        )


# ---------------------------------------------------------------------------
# Peer group store
# ---------------------------------------------------------------------------

class PeerGroupStore:
    """Manages peer groups with file-based persistence.

    Args:
        path: Path to the JSON peer groups file.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.groups: dict[str, PeerGroup] = {}
        self._entity_to_group: dict[str, str] = {}  # entity_id → group_id
        self._load()

    def _load(self) -> None:
        """Load peer groups from the JSON file."""
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            for gid, gdata in data.get("groups", {}).items():
                self.groups[gid] = PeerGroup.from_dict(gdata)
            self._rebuild_index()
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load peer groups from %s: %s", self.path, e)

    def save(self) -> None:
        """Save all peer groups to the JSON file atomically."""
        data = {
            "groups": {k: v.to_dict() for k, v in self.groups.items()},
        }
        try:
            atomic_write_json(self.path, data)
        except OSError as e:
            logger.warning("Failed to save peer groups to %s: %s", self.path, e)

    def _rebuild_index(self) -> None:
        """Rebuild the entity → group index."""
        self._entity_to_group = {}
        for group in self.groups.values():
            for member in group.members:
                self._entity_to_group[member] = group.group_id

    def get_group_for_entity(self, entity_id: str) -> PeerGroup | None:
        """Get the peer group for a specific entity."""
        gid = self._entity_to_group.get(entity_id)
        if gid:
            return self.groups.get(gid)
        return None

    def get_group(self, group_id: str) -> PeerGroup | None:
        """Get a peer group by ID."""
        return self.groups.get(group_id)

    def list_groups(self, entity_type: str | None = None) -> list[PeerGroup]:
        """List all groups, optionally filtered by entity type."""
        groups = list(self.groups.values())
        if entity_type:
            groups = [g for g in groups if g.entity_type == entity_type]
        return groups


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _extract_user_features(profile: UserProfile) -> dict[str, float]:
    """Extract behavioral features from a user profile for clustering.

    Returns:
        Dict of feature name → normalized value.
    """
    return {
        "event_count": profile.typical_event_count.value,
        "unique_ips": float(len(profile.typical_ips)),
        "active_hours": float(len(profile.typical_hours)),
        "auth_failure_ratio": profile.auth_failure_ratio.value,
        "off_hours_ratio": profile.off_hours_ratio.value,
        "action_types": float(len(profile.typical_actions)),
    }


def _extract_host_features(profile: HostProfile) -> dict[str, float]:
    """Extract behavioral features from a host profile for clustering."""
    return {
        "process_count": profile.typical_process_count.value,
        "unique_processes": float(len(profile.typical_processes)),
        "user_count": profile.typical_user_count.value,
        "unique_users": float(len(profile.typical_users)),
        "network_count": profile.typical_network_count.value,
        "unique_destinations": float(len(profile.typical_destinations)),
        "auth_failure_ratio": profile.typical_auth_failure_ratio.value,
    }


def _extract_ip_features(profile: IPProfile) -> dict[str, float]:
    """Extract behavioral features from an IP profile for clustering."""
    return {
        "event_count": profile.typical_event_count.value,
        "unique_users": float(len(profile.typical_users)),
        "unique_hosts": float(len(profile.typical_hosts)),
        "unique_ports": float(len(profile.typical_ports)),
        "unique_domains": float(len(profile.typical_domains)),
    }


def _normalize_features(feature_dicts: dict[str, dict[str, float]]) -> dict[str, dict[str, float]]:
    """Normalize features to [0, 1] across all entities.

    Args:
        feature_dicts: Dict of entity_id → {feature_name → raw_value}.

    Returns:
        Dict of entity_id → {feature_name → normalized_value}.
    """
    if not feature_dicts:
        return {}

    # Find min/max per feature
    all_features: set[str] = set()
    for feats in feature_dicts.values():
        all_features.update(feats.keys())

    ranges: dict[str, tuple[float, float]] = {}
    for feat in all_features:
        values = [fd.get(feat, 0.0) for fd in feature_dicts.values()]
        lo, hi = min(values), max(values)
        ranges[feat] = (lo, hi)

    normalized = {}
    for eid, feats in feature_dicts.items():
        norm = {}
        for feat, val in feats.items():
            lo, hi = ranges.get(feat, (0.0, 1.0))
            if hi > lo:
                norm[feat] = (val - lo) / (hi - lo)
            else:
                norm[feat] = 0.5  # All same value → middle
        normalized[eid] = norm

    return normalized


# ---------------------------------------------------------------------------
# K-means clustering (pure Python, no dependencies)
# ---------------------------------------------------------------------------

def _euclidean_distance(a: dict[str, float], b: dict[str, float]) -> float:
    """Compute Euclidean distance between two feature vectors."""
    keys = set(a.keys()) | set(b.keys())
    return math.sqrt(sum((a.get(k, 0.0) - b.get(k, 0.0)) ** 2 for k in keys))


def _kmeans(
    entity_ids: list[str],
    features: dict[str, dict[str, float]],
    k: int,
    max_iterations: int = 50,
) -> tuple[list[list[str]], list[dict[str, float]], float]:
    """Run K-means clustering on feature vectors.

    Args:
        entity_ids: List of entity IDs to cluster.
        features: Dict of entity_id → normalized feature vector.
        k: Number of clusters.
        max_iterations: Maximum iterations per run.

    Returns:
        Tuple of (clusters, centroids, inertia).
        clusters: List of lists of entity IDs.
        centroids: List of centroid feature vectors.
        inertia: Total within-cluster sum of squared distances.
    """
    if len(entity_ids) <= k:
        # Fewer entities than clusters — each entity is its own cluster
        clusters = [[eid] for eid in entity_ids]
        centroids = [features.get(eid, {}) for eid in entity_ids]
        inertia = 0.0
        return clusters, centroids, inertia

    # Initialize centroids randomly (pick k entities)
    import random
    random.seed(42)  # Deterministic for reproducibility
    initial = random.sample(entity_ids, k)
    centroids = [features[eid].copy() for eid in initial]

    for _ in range(max_iterations):
        # Assign each entity to nearest centroid
        clusters: list[list[str]] = [[] for _ in range(k)]
        for eid in entity_ids:
            feats = features.get(eid, {})
            distances = [_euclidean_distance(feats, c) for c in centroids]
            nearest = min(range(k), key=lambda i: distances[i])
            clusters[nearest].append(eid)

        # Recompute centroids
        new_centroids = []
        for i, cluster in enumerate(clusters):
            if not cluster:
                new_centroids.append(centroids[i])
                continue
            # Mean of all feature vectors in cluster
            centroid: dict[str, float] = defaultdict(float)
            for eid in cluster:
                for feat, val in features.get(eid, {}).items():
                    centroid[feat] += val
            n = len(cluster)
            new_centroids.append({f: v / n for f, v in centroid.items()})

        # Check convergence
        converged = True
        for old, new in zip(centroids, new_centroids):
            if _euclidean_distance(old, new) > 0.001:
                converged = False
                break
        centroids = new_centroids
        if converged:
            break

    # Compute inertia
    inertia = 0.0
    for i, cluster in enumerate(clusters):
        for eid in cluster:
            inertia += _euclidean_distance(features.get(eid, {}), centroids[i]) ** 2

    return clusters, centroids, inertia


def _auto_label(centroid: dict[str, float], all_centroids: list[dict[str, float]]) -> str:
    """Generate a human-readable label for a cluster based on its centroid.

    The label reflects the most discriminating feature: the one where this
    centroid is furthest from the global mean.

    Args:
        centroid: This cluster's centroid.
        all_centroids: All cluster centroids (for computing global mean).

    Returns:
        Label string like "high_off_hours" or "low_event_count".
    """
    if not all_centroids:
        return "default"

    # Compute global mean per feature
    all_features: set[str] = set()
    for c in all_centroids:
        all_features.update(c.keys())

    global_mean = {}
    for feat in all_features:
        global_mean[feat] = sum(c.get(feat, 0.0) for c in all_centroids) / len(all_centroids)

    # Find most discriminating feature
    best_feat = ""
    best_deviation = 0.0
    for feat in all_features:
        deviation = abs(centroid.get(feat, 0.0) - global_mean.get(feat, 0.0))
        if deviation > best_deviation:
            best_deviation = deviation
            best_feat = feat

    if not best_feat:
        return "default"

    # Format: "high_X" or "low_X"
    value = centroid.get(best_feat, 0.0)
    mean = global_mean.get(best_feat, 0.0)
    prefix = "high" if value > mean else "low"
    # Convert feature name to readable form
    readable = best_feat.replace("_", " ")
    return f"{prefix} {readable}"


# ---------------------------------------------------------------------------
# Main clustering function
# ---------------------------------------------------------------------------

def compute_peer_groups(
    profile_store: EntityProfileStore,
    recompute_interval: int = 10,
) -> PeerGroupStore:
    """Compute peer groups from entity profiles.

    Clusters entities by type (user, host, ip) using K-means on behavioral
    features. If peer groups already exist and the recompute interval hasn't
    been reached, returns the existing groups.

    Args:
        profile_store: Entity profile store with EWMA data.
        recompute_interval: Minimum runs between re-clustering.

    Returns:
        PeerGroupStore with updated groups.
    """
    from nabla.config import get_settings
    settings = get_settings()

    store = PeerGroupStore(settings.entity_risk_scores_file.replace("risk_scores", "peer_groups"))

    # Check if we need to recompute
    if store.groups:
        # Check if any group has been updated recently enough
        newest = max((g.updated_at for g in store.groups.values()), default="")
        if newest:
            hours = _hours_since(newest)
            # Only recompute if it's been more than recompute_interval runs
            # (approximate: 1 run ≈ 5 minutes, so interval * 5 min / 60 = hours)
            min_hours = (recompute_interval * 5) / 60
            if hours < min_hours:
                return store

    now = datetime.now(timezone.utc).isoformat()

    # Cluster each entity type separately
    for entity_type, extract_fn, profiles in [
        ("user", _extract_user_features, profile_store.users),
        ("host", _extract_host_features, profile_store.hosts),
        ("ip", _extract_ip_features, profile_store.ips),
    ]:
        # Only cluster entities with sufficient observations
        min_obs = 3
        eligible = {
            eid: extract_fn(profile)
            for eid, profile in profiles.items()
            if profile.observation_count >= min_obs
        }

        if len(eligible) < 2:
            continue

        # Normalize features
        normalized = _normalize_features(eligible)

        # Determine k
        n = len(eligible)
        k = min(int(math.sqrt(n)), 20)
        k = max(k, 2)

        # Run K-means 3 times, pick best inertia
        entity_ids = list(eligible.keys())
        best_clusters = None
        best_centroids = None
        best_inertia = float("inf")

        for _ in range(3):
            clusters, centroids, inertia = _kmeans(entity_ids, normalized, k)
            if inertia < best_inertia:
                best_clusters = clusters
                best_centroids = centroids
                best_inertia = inertia

        if best_clusters is None:
            continue

        # Create PeerGroup objects
        for i, (cluster, centroid) in enumerate(zip(best_clusters, best_centroids)):
            group_id = f"{entity_type}_{i}"
            label = _auto_label(centroid, best_centroids)
            group = PeerGroup(
                group_id=group_id,
                entity_type=entity_type,
                members=cluster,
                centroid=centroid,
                label=label,
                created_at=now,
                updated_at=now,
            )
            store.groups[group_id] = group

    store._rebuild_index()
    store.save()

    total_groups = len(store.groups)
    total_members = sum(len(g.members) for g in store.groups.values())
    logger.info(
        "Peer groups computed: %d groups covering %d entities",
        total_groups, total_members,
    )
    return store


def _hours_since(timestamp: str) -> float:
    """Return hours elapsed since an ISO timestamp."""
    try:
        dt = datetime.fromisoformat(timestamp)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        elapsed = (datetime.now(timezone.utc) - dt).total_seconds() / 3600
        return max(0, elapsed)
    except (ValueError, TypeError):
        return 999.0
