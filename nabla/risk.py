"""Entity risk scoring — aggregate per-entity risk with time decay and category partitioning.

Grounded in vendor practices:
- Anchor weights (Exabeam): expert-assigned base scores per detection method
- Bayesian adjustment: weights scaled by Thompson Sampling bandit confirmation rate
- Exponential decay (NetGain): 24-hour half-life for anomaly contributions
- Per-category partitioning (ManageEngine/Log360): insider_threat, account_compromise,
  data_exfiltration, lateral_movement
- Attack chain multiplier (NetGain): temporal chains get 1.5x, multi-technique chains get 2x
- Watchlist boost (Sentinel's blast-radius): high-value entities get 1.3x
- Risk acceleration (NetGain's "Rising Risk"): track rate of score change

Core formula:
    entity_risk = Σ(anomaly_weight × confidence × decay × peer_adjustment
                     × chain_multiplier × watchlist_boost)
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from nabla.log import get_logger
from nabla.persistence import atomic_write_json

logger = get_logger("risk")

# ---------------------------------------------------------------------------
# Severity anchor weights (Exabeam model)
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[str, float] = {
    "low": 2.0,
    "medium": 5.0,
    "high": 10.0,
    "critical": 15.0,
}

# ---------------------------------------------------------------------------
# Detection method → threat category mapping
# ---------------------------------------------------------------------------

# Each detection method maps to one or more threat categories.
# When an anomaly's method maps to multiple categories, the weight is split.
METHOD_CATEGORIES: dict[str, list[str]] = {
    "brute_force_attempt": ["account_compromise"],
    "z_score_spike": ["insider_threat"],
    "off_hours_activity": ["insider_threat"],
    "impossible_travel": ["account_compromise"],
    "activity_spike": ["insider_threat"],
    "lolbin_abuse": ["lateral_movement"],
    "suspicious_parent_child": ["lateral_movement"],
    "privilege_escalation": ["lateral_movement"],
    "unusual_process": ["lateral_movement"],
    "known_attack_script": ["lateral_movement", "account_compromise"],
    "renamed_attack_tool": ["lateral_movement"],
    "enumeration_behavior": ["lateral_movement"],
    "rapid_action_sequence": ["lateral_movement"],
    "suspicious_path": ["lateral_movement"],
    "integrity_anomaly": ["lateral_movement"],
    "registry_abuse": ["lateral_movement"],
    "network_anomaly": ["data_exfiltration"],
    "data_exfiltration": ["data_exfiltration"],
    "gcn_lof": ["insider_threat"],
    "temporal_chain": [],  # category determined by chain's dominant phase
    "pre_flagged": ["insider_threat"],
    "attack_script": ["lateral_movement", "account_compromise"],
    "renamed_tool": ["lateral_movement"],
    "provenance_community": ["insider_threat"],
    "dns_tunneling": ["data_exfiltration"],
    "exfil_volume": ["data_exfiltration"],
    "exfil_destination": ["data_exfiltration"],
    "exfil_staging": ["data_exfiltration"],
}

# Temporal chain phase → category
PHASE_CATEGORIES: dict[str, str] = {
    "recon": "lateral_movement",
    "initial_access": "account_compromise",
    "execution": "lateral_movement",
    "persistence": "lateral_movement",
    "privilege_escalation": "lateral_movement",
    "defense_evasion": "lateral_movement",
    "credential_access": "account_compromise",
    "lateral_movement": "lateral_movement",
    "exfiltration": "data_exfiltration",
    "command_and_control": "lateral_movement",
}

# All valid threat categories
THREAT_CATEGORIES = ("insider_threat", "account_compromise", "data_exfiltration", "lateral_movement")

# Watchlist groups that trigger blast-radius boost
_HIGH_VALUE_GROUPS = {"high_value_users", "critical_systems"}

# Chain multiplier thresholds
_CHAIN_MULTIPLIER_SIMPLE = 1.5   # Any temporal chain
_CHAIN_MULTIPLIER_MULTI = 2.0    # Chain with ≥3 distinct ATT&CK phases

# Watchlist boost factor
_WATCHLIST_BOOST = 1.3

# Risk score cap
_MAX_SCORE = 100.0


# ---------------------------------------------------------------------------
# Entity risk score
# ---------------------------------------------------------------------------

@dataclass
class EntityRiskScore:
    """Per-entity aggregate risk score with category partitioning and trend tracking.

    Attributes:
        entity_id: Entity identifier (username, hostname, or IP).
        entity_type: One of "user", "host", "ip".
        overall: Current overall risk score (0–100).
        categories: Per-category risk scores.
        peak: Highest overall score ever recorded.
        trend: Rate of score change (points/hour). Positive = rising risk.
        last_updated: ISO timestamp of last update.
        score_history: Recent (timestamp, overall) pairs for trend calculation.
        contributing_anomalies: Last N anomalies that contributed to the score.
    """

    entity_id: str = ""
    entity_type: str = "user"
    overall: float = 0.0
    categories: dict[str, float] = field(default_factory=lambda: dict.fromkeys(THREAT_CATEGORIES, 0.0))
    peak: float = 0.0
    trend: float = 0.0
    last_updated: str = ""
    score_history: list[tuple[str, float]] = field(default_factory=list)
    contributing_anomalies: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict."""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "overall": round(self.overall, 2),
            "categories": {k: round(v, 2) for k, v in self.categories.items()},
            "peak": round(self.peak, 2),
            "trend": round(self.trend, 3),
            "last_updated": self.last_updated,
            "score_history": self.score_history[-24:],  # Keep last 24 entries
            "contributing_anomalies": self.contributing_anomalies[-20:],
        }

    @classmethod
    def from_dict(cls, data: dict) -> EntityRiskScore:
        """Deserialize from a dict."""
        cats = dict.fromkeys(THREAT_CATEGORIES, 0.0)
        cats.update(data.get("categories", {}))
        return cls(
            entity_id=data.get("entity_id", ""),
            entity_type=data.get("entity_type", "user"),
            overall=data.get("overall", 0.0),
            categories=cats,
            peak=data.get("peak", 0.0),
            trend=data.get("trend", 0.0),
            last_updated=data.get("last_updated", ""),
            score_history=[tuple(pair) for pair in data.get("score_history", [])],
            contributing_anomalies=data.get("contributing_anomalies", []),
        )


# ---------------------------------------------------------------------------
# Risk score store
# ---------------------------------------------------------------------------

class EntityRiskStore:
    """Manages entity risk scores with file-based persistence.

    Args:
        path: Path to the JSON risk scores file.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.scores: dict[str, EntityRiskScore] = {}
        self._load()

    def _load(self) -> None:
        """Load risk scores from the JSON file."""
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            for entity_id, score_data in data.get("entities", {}).items():
                self.scores[entity_id] = EntityRiskScore.from_dict(score_data)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load risk scores from %s: %s", self.path, e)

    def save(self) -> None:
        """Save all risk scores to the JSON file atomically."""
        data = {
            "entities": {k: v.to_dict() for k, v in self.scores.items()},
        }
        try:
            atomic_write_json(self.path, data)
        except OSError as e:
            logger.warning("Failed to save risk scores to %s: %s", self.path, e)

    def get(self, entity_id: str) -> EntityRiskScore | None:
        """Get a risk score by entity ID."""
        return self.scores.get(entity_id)

    def get_or_create(self, entity_id: str, entity_type: str = "user") -> EntityRiskScore:
        """Get or create a risk score for an entity."""
        if entity_id not in self.scores:
            self.scores[entity_id] = EntityRiskScore(
                entity_id=entity_id,
                entity_type=entity_type,
            )
        return self.scores[entity_id]

    def top_risky(self, limit: int = 10) -> list[EntityRiskScore]:
        """Return the top-riskiest entities, sorted by overall score descending."""
        sorted_scores = sorted(
            self.scores.values(),
            key=lambda s: s.overall,
            reverse=True,
        )
        return sorted_scores[:limit]


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------

def _hours_since(timestamp: str) -> float:
    """Return hours elapsed since an ISO timestamp."""
    from nabla.utils import parse_iso_timestamp
    dt = parse_iso_timestamp(timestamp)
    if dt is None:
        return 999.0  # Unparseable timestamps are treated as very old
    elapsed = (datetime.now(timezone.utc) - dt).total_seconds() / 3600
    return max(0, elapsed)


def _decay_factor(timestamp: str, half_life_hours: float) -> float:
    """Compute exponential decay factor for an anomaly.

    Args:
        timestamp: ISO timestamp of the anomaly.
        half_life_hours: Decay half-life in hours.

    Returns:
        Decay factor between 0 and 1.
    """
    hours = _hours_since(timestamp)
    return 0.5 ** (hours / half_life_hours)


def _get_bandit_weights(bandit_store=None) -> dict[str, float]:
    """Get Bayesian-adjusted detection method weights from the Thompson Sampling bandit.

    If the bandit store is unavailable, return uniform weights (1.0 for all methods).

    Returns:
        Dict mapping detection method → adjustment factor (0.5–1.5).
    """
    if bandit_store is None:
        return {}

    try:
        from nabla.rl.bandit import DetectionMethodBandit
        weights = {}
        for method_name, arm in bandit_store.arms.items():
            # Confirmation rate: α / (α + β)
            # Higher confirmation = more reliable method = boost
            # Lower confirmation = noisier method = dampen
            alpha = arm.get("alpha", 1.0)
            beta = arm.get("beta", 1.0)
            confirmation_rate = alpha / (alpha + beta) if (alpha + beta) > 0 else 0.5
            # Map [0, 1] → [0.5, 1.5]: 0.5 confirmation → 1.0, 1.0 → 1.5, 0.0 → 0.5
            weights[method_name] = 0.5 + confirmation_rate
        return weights
    except Exception:
        return {}


def _chain_multiplier(anomaly: dict, temporal_chains: list[dict]) -> float:
    """Compute chain multiplier for an anomaly that's part of a temporal chain.

    Args:
        anomaly: Anomaly dict. Must have temporal_chain_id if part of a chain.
        temporal_chains: List of temporal chain dicts from the correlation engine.

    Returns:
        Multiplier (1.0, 1.5, or 2.0).
    """
    chain_id = anomaly.get("temporal_chain_id")
    if not chain_id:
        return 1.0

    for chain in temporal_chains:
        if chain.get("chain_id") == chain_id:
            phases = chain.get("phases", [])
            if len(phases) >= 3:
                return _CHAIN_MULTIPLIER_MULTI
            return _CHAIN_MULTIPLIER_SIMPLE

    return 1.0


def _watchlist_boost(entity_id: str, _entity_type: str, watchlist=None) -> float:
    """Compute watchlist blast-radius boost.

    Args:
        entity_id: Entity identifier.
        entity_type: Entity type.
        watchlist: Watchlist object (optional).

    Returns:
        Boost factor (1.0 or 1.3).
    """
    if watchlist is None:
        return 1.0

    try:
        # The pipeline's Watchlist is a flat users/hosts/ips aggregate (group
        # names like high_value_users don't survive into it). Watchlisted =
        # high-value by definition — boost applies to any watchlist member.
        # (Fixed 2026-09-09: the previous get_group() call was broken since
        # inception — silently swallowed until the silent-swallow sweep made
        # it loud, 58 warnings in the first real-data ingest.)
        if entity_id in watchlist.users or entity_id in watchlist.hosts or entity_id in watchlist.ips:
            return _WATCHLIST_BOOST
    except Exception as e:
        logger.warning("watchlist boost failed (non-fatal): %s", e, exc_info=True)

    return 1.0


def _peer_adjustment(entity_id: str, detection_method: str, peer_groups=None) -> float:
    """Compute peer-group-based adjustment.

    If the anomaly's detection method is common among the entity's peers,
    dampen it (×0.7). If unique to this entity, boost it (×1.3).

    Args:
        entity_id: Entity identifier.
        detection_method: Detection method name.
        peer_groups: PeerGroupStore (optional).

    Returns:
        Adjustment factor (0.7, 1.0, or 1.3).
    """
    if peer_groups is None:
        return 1.0

    try:
        group = peer_groups.get_group_for_entity(entity_id)
        if group is None:
            return 1.0

        # Check how many peers in the group have the same detection method
        # recently. If >50% of peers have it, dampen. If 0% of peers have it, boost.
        peer_method_count = 0
        peer_total = len(group.members)
        if peer_total <= 1:
            return 1.0

        for member_id in group.members:
            if member_id == entity_id:
                continue
            # Check if the peer has recent anomalies with this method
            member_anomalies = group.peer_anomaly_summary.get(member_id, {})
            if member_anomalies.get(detection_method, 0) > 0:
                peer_method_count += 1

        peer_fraction = peer_method_count / max(1, peer_total - 1)
        if peer_fraction > 0.5:
            return 0.7  # Common among peers → dampen
        if peer_fraction == 0:
            return 1.3  # Unique to this entity → boost
        return 1.0
    except Exception:
        return 1.0


def _resolve_categories(anomaly: dict) -> list[str]:
    """Determine which threat categories an anomaly contributes to.

    Args:
        anomaly: Anomaly dict with 'detection_method' and optionally 'phases'.

    Returns:
        List of threat category names.
    """
    method = anomaly.get("detection_method", anomaly.get("type", ""))

    # Temporal chains: category from dominant phase
    if method == "temporal_chain":
        phases = anomaly.get("phases", [])
        if phases:
            # Use the last phase in the chain (most advanced)
            return [PHASE_CATEGORIES.get(phases[-1], "insider_threat")]
        return ["insider_threat"]

    categories = METHOD_CATEGORIES.get(method, ["insider_threat"])
    return categories if categories else ["insider_threat"]


def compute_risk_scores(
    anomalies: list[dict],
    entity_type_map: dict[str, str],
    temporal_chains: list[dict] | None = None,
    watchlist=None,
    peer_groups=None,
    bandit_store=None,
    half_life_hours: float = 24.0,
    max_anomalies: int = 20,
) -> EntityRiskStore:
    """Compute risk scores for all entities mentioned in anomalies.

    This is the main entry point called from the pipeline. It:
    1. Groups anomalies by entity
    2. Applies the full scoring formula per anomaly
    3. Aggregates per-entity and per-category
    4. Computes trend (risk acceleration)
    5. Returns an EntityRiskStore with all scores

    Args:
        anomalies: List of anomaly dicts from detect_anomalies().
        entity_type_map: Dict mapping entity_id → entity_type ("user"/"host"/"ip").
        temporal_chains: List of temporal chain dicts (for chain multiplier).
        watchlist: Watchlist object (for blast-radius boost).
        peer_groups: PeerGroupStore (for peer adjustment).
        bandit_store: Bandit store (for Bayesian weight adjustment).
        half_life_hours: Decay half-life in hours.
        max_anomalies: Maximum contributing anomalies to retain per entity.

    Returns:
        EntityRiskStore with updated risk scores.
    """
    from nabla.config import get_settings
    settings = get_settings()

    store = EntityRiskStore(settings.entity_risk_scores_file)
    if temporal_chains is None:
        temporal_chains = []

    # Get Bayesian-adjusted method weights
    bandit_weights = _get_bandit_weights(bandit_store)

    # Build chain ID → anomaly mapping for chain multiplier lookup
    chain_ids_in_anomalies: set[str] = set()
    for a in anomalies:
        cid = a.get("temporal_chain_id")
        if cid:
            chain_ids_in_anomalies.add(cid)

    # Group anomalies by entity
    entity_anomalies: dict[str, list[dict]] = defaultdict(list)
    for anomaly in anomalies:
        entity = anomaly.get("entity", anomaly.get("user", "unknown"))
        if entity:
            entity_anomalies[entity].append(anomaly)

    now = datetime.now(timezone.utc).isoformat()

    for entity_id, entity_anoms in entity_anomalies.items():
        etype = entity_type_map.get(entity_id, "user")
        score = store.get_or_create(entity_id, etype)

        # Track previous overall for trend calculation
        prev_overall = score.overall

        # Reset category scores (we recompute from all contributing anomalies)
        new_categories: dict[str, float] = dict.fromkeys(THREAT_CATEGORIES, 0.0)
        all_contributing: list[dict] = []

        for anomaly in entity_anoms:
            # --- Base weight from severity ---
            severity = anomaly.get("severity", "medium")
            base_weight = SEVERITY_WEIGHTS.get(severity, 5.0)

            # --- Bayesian adjustment from bandit ---
            method = anomaly.get("detection_method", anomaly.get("type", ""))
            bandit_factor = bandit_weights.get(method, 1.0)

            # --- Confidence from anomaly ---
            confidence = anomaly.get("confidence", 0.5)

            # --- Time decay ---
            anomaly_time = anomaly.get("timestamp", anomaly.get("detected_at", ""))
            decay = _decay_factor(anomaly_time, half_life_hours) if anomaly_time else 1.0

            # --- Chain multiplier ---
            chain_mult = _chain_multiplier(anomaly, temporal_chains)

            # --- Watchlist boost ---
            wl_boost = _watchlist_boost(entity_id, etype, watchlist)

            # --- Peer adjustment ---
            peer_adj = _peer_adjustment(entity_id, method, peer_groups)

            # --- Compute contribution ---
            contribution = (
                base_weight
                * bandit_factor
                * confidence
                * decay
                * chain_mult
                * wl_boost
                * peer_adj
            )

            # --- Distribute to categories ---
            categories = _resolve_categories(anomaly)
            per_category = contribution / len(categories)
            for cat in categories:
                if cat in new_categories:
                    new_categories[cat] += per_category

            # Track contributing anomaly (condensed)
            all_contributing.append({
                "method": method,
                "severity": severity,
                "timestamp": anomaly_time,
                "contribution": round(contribution, 3),
                "categories": categories,
            })

        # Compute overall as max of category scores, capped at 100
        for cat, val in new_categories.items():
            new_categories[cat] = min(val, _MAX_SCORE)
        overall = min(max(new_categories.values()), _MAX_SCORE)

        # Compute trend: (current - previous) / hours_since_last_update
        if score.last_updated:
            hours = _hours_since(score.last_updated)
            if hours > 0:
                trend = (overall - prev_overall) / hours
            else:
                trend = 0.0
        else:
            trend = 0.0

        # Update score
        score.overall = overall
        score.categories = new_categories
        score.peak = max(score.peak, overall)
        score.trend = trend
        score.last_updated = now
        score.contributing_anomalies = all_contributing[-max_anomalies:]
        score.score_history.append((now, overall))
        # Keep last 24 history entries
        if len(score.score_history) > 24:
            score.score_history = score.score_history[-24:]

    # Decay inactive entities: entities that had scores but no new anomalies
    # this run should have their scores decay over time
    for entity_id, score in store.scores.items():
        if entity_id not in entity_anomalies and score.overall > 0:
            # Apply decay since last update
            if score.last_updated:
                hours = _hours_since(score.last_updated)
                decay = 0.5 ** (hours / half_life_hours)
                score.overall = min(score.overall * decay, _MAX_SCORE)
                for cat in score.categories:
                    score.categories[cat] = min(score.categories[cat] * decay, _MAX_SCORE)
                score.last_updated = now
                score.trend = -score.overall * (1 - decay) / max(hours, 0.1)

    store.save()
    logger.info(
        "Risk scores updated: %d entities scored, %d above cutoff",
        len(entity_anomalies),
        sum(1 for s in store.scores.values() if s.overall >= 50),
    )
    return store


def get_trend_label(trend: float) -> str:
    """Convert a trend value to a human-readable label.

    Args:
        trend: Rate of score change (points/hour).

    Returns:
        One of "rising", "stable", "declining".
    """
    if trend > 0.5:
        return "rising"
    if trend < -0.5:
        return "declining"
    return "stable"
