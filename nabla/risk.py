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
    "multiple_source_ips": ["account_compromise"],
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
    # N2.2 (round 4): the entity's OWN reference clock — the newest stamp
    # it was scored against. Each entity's decay reference is the max of
    # this and its own batch anomalies' stamps; a batch for ANOTHER entity
    # cannot age it. Dormant entities keep their score until their own
    # stream advances (documented, intended: the score reflects the last
    # known activity).
    data_clock: str = ""
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
            "data_clock": self.data_clock,
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
            data_clock=data.get("data_clock", ""),
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


def _data_clock() -> datetime:
    """The risk-computation reference clock (A7 remediation).

    Decay, last_updated stamping, and trend math all run against the NEWEST
    INGESTED EVENT timestamp (data time), not the wall clock — replaying
    historical data keeps relative timing intact instead of zeroing scores
    (live ingestion tracks the wall clock closely, so behavior there is
    unchanged). Falls back to the wall clock when no data has been ingested
    (or the persisted value is unparseable), and says so here in code.
    """
    try:
        from nabla.config import get_settings
        state_path = get_settings().system_state_file
        if os.path.exists(state_path):
            import json as _json
            state = _json.load(open(state_path))
            newest = state.get("data_newest_ts")
            if newest:
                from nabla.utils import parse_iso_timestamp
                dt = parse_iso_timestamp(str(newest))
                if dt is not None:
                    return dt
    except Exception as e:
        logger.warning("data clock fallback to wall clock: %s", e)
    return datetime.now(timezone.utc)


def _hours_since_ref(timestamp: str, ref: datetime) -> float:
    """Hours from an ISO timestamp to a reference instant (data clock).

    Unparseable timestamps are 'time unknown': treated as occurring AT the
    reference (zero age) with a warning — not silently maximum-age, which
    zeroed their contribution (external review A7).
    """
    from nabla.utils import parse_iso_timestamp
    dt = parse_iso_timestamp(timestamp)
    if dt is None:
        logger.warning("unparseable anomaly timestamp %r — treating as reference-time", timestamp)
        return 0.0
    return max(0.0, (ref - dt).total_seconds() / 3600)


def _decay_factor(timestamp: str, half_life_hours: float, ref: datetime | None = None) -> float:
    """Compute exponential decay factor for an anomaly.

    Args:
        timestamp: ISO timestamp of the anomaly.
        half_life_hours: Decay half-life in hours.
        ref: Reference instant (data clock). None = wall clock (legacy).

    Returns:
        Decay factor between 0 and 1.
    """
    hours = _hours_since_ref(timestamp, ref) if ref is not None else _hours_since(timestamp)
    return 0.5 ** (hours / half_life_hours)


def _get_bandit_weights(bandit_store=None) -> dict[str, float]:
    """Get Bayesian-adjusted detection method weights from the Thompson Sampling bandit.

    If the bandit store is unavailable, return uniform weights (1.0 for all methods).

    Returns:
        Dict mapping detection method → adjustment factor (0.5–1.5).
    """
    if bandit_store is None:
        return {}

    # A5 remediation: the previous body iterated bandit_store.arms — an
    # attribute DetectionMethodBandit never had (alpha/beta dicts instead).
    # The AttributeError was swallowed by the blanket except, making the
    # advertised Bayesian adjustment silently inert (external review A5).
    # Use the class's own API; no blanket handler — failures surface now.
    # Map [0,1] → [0.5,1.5]: 0.5 confirmation → 1.0, 1.0 → 1.5, 0.0 → 0.5.
    return {method: 0.5 + rate for method, rate in bandit_store.get_means().items()}


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
    # N2.3: count of anomalies skipped for missing timestamps — surfaced to
    # the caller (pipeline degradations) so the loss is visible, not silent.
    degraded_missing_ts = 0
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

    # A7: the entire risk computation runs on the DATA clock (newest ingested
    # event), not the wall clock — decay, stamps, and trend all share one
    # reference so replayed data keeps relative timing (review REQUIRED 1:
    # all four consumers, or mixed-clock artifacts reintroduce the bug).
    # R12 (round 3, review REQUIRED 1): per-batch reference — max(data clock,
    # newest anomaly timestamp IN THIS BATCH). A persisted cross-source
    # high-water would recreate the A7 disease for the course order
    # (synthetic quickstart runs advance it to wall-now; the attack replay's
    # months-old stamps then decay to zero). Per-batch handles both orders:
    # synthetic batches reference their own now (~0 age), replay batches
    # reference their window end (~0 age).
    ref_clock = _data_clock()
    from nabla.utils import parse_iso_timestamp as _pit
    for a in anomalies:
        dt = _pit(str(a.get("timestamp", "") or ""))
        if dt is not None and dt > ref_clock:
            ref_clock = dt
    now = ref_clock.isoformat()

    for entity_id, entity_anoms in entity_anomalies.items():
        etype = entity_type_map.get(entity_id, "user")
        # N-harness (round 4, found live): machine principals are excluded
        # from BEHAVIORAL baselining (F5) but nothing excluded them from risk
        # accumulation — svc-jenkins/root/-/adm rack up z/spike anomalies on
        # every batch (their volume IS their job) and outrank the attack
        # user. A machine account has no behavior to deviate from, so it
        # accumulates no behavioral risk. Same predicate as detection's
        # exclusion — one definition of "machine", not two.
        if etype == "user":
            from nabla.utils import is_baselineable_user
            if not is_baselineable_user(entity_id):
                continue
        score = store.get_or_create(entity_id, etype)

        # N2.2 (round 4): the PER-ENTITY reference clock. R12's batch-max
        # rule is one clock for everyone: a batch on recent data ages every
        # entity from an older dataset (reviewer scenario (c): replay for
        # alice, then a run for bob, zeroes alice). This entity's reference
        # is the max of ITS OWN persisted data_clock and ITS OWN anomalies'
        # stamps this batch. COLD START floors at the global data clock
        # (R12's synthetic-then-replay guard: a fresh entity scored on old
        # stamps must still age honestly to the dataset's newest, not read
        # "age 0" against its own batch). Dormant entities keep their score
        # until their own stream advances.
        ent_ref = _pit(str(score.data_clock or "")) if score.data_clock else None
        for a in entity_anoms:
            dt = _pit(str(a.get("timestamp", "") or ""))
            if dt is not None and (ent_ref is None or dt > ent_ref):
                ent_ref = dt
        if ent_ref is None or ent_ref < ref_clock:
            ent_ref = max(ent_ref, ref_clock) if ent_ref else ref_clock
        ent_now = ent_ref.isoformat()
        score.data_clock = ent_now

        # Track previous overall for trend calculation
        prev_overall = score.overall

        # Reset category scores (we recompute from all contributing anomalies)
        new_categories: dict[str, float] = dict.fromkeys(THREAT_CATEGORIES, 0.0)
        all_contributing: list[dict] = []

        # A6: RETAINED anomalies from previous runs — the score accumulates
        # across runs instead of resetting (external review A6: a steady
        # trickle of low-grade anomalies must build risk; that is the core
        # UEBA promise). Dedup by (method, timestamp); decay recomputed each
        # run against the data clock; negligible contributions pruned.
        # Phase 3: dedup key upgrades to anomaly_id (stable, Phase 2) —
        # identical re-fired anomalies collapse to one contribution; entries
        # without an ID (pre-Phase-3 stores) fall back to (method, timestamp).
        retained: dict[object, dict] = {
            (a.get("anomaly_id") or (a.get("method"), a.get("timestamp"))): a
            for a in score.contributing_anomalies
        }

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
            # N2.3 (round 4, final-review REQUIRED 2): absent means absent.
            # The old guard (`... if anomaly_time else 1.0`) made empty-ts
            # anomalies decay-IMMORTAL — full weight forever, never pruned
            # (prune compares the never-shrinking decayed value), and
            # resurrected at full weight by recompute-from-retained. An
            # anomaly with no timestamp carries no defensible time
            # information: it contributes nothing this run and is not
            # retained. The run's degradation count records the loss.
            if not anomaly_time:
                degraded_missing_ts += 1
                continue
            decay = _decay_factor(anomaly_time, half_life_hours, ref=ent_ref)  # N2.2: per-entity

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
            # R2 (fixed for real in R12's testing): base = the UNDECAYED
            # weight — the contribution formula includes this-run's decay,
            # so dividing it back out (decay > 0 whenever a timestamp
            # exists) yields the durable base. Storing the decayed value
            # made every future run re-decay from a shrunken start.
            undecayed = contribution / decay if decay > 0 else contribution
            condensed = {
                "anomaly_id": anomaly.get("anomaly_id", ""),
                "method": method,
                "severity": severity,
                "timestamp": anomaly_time,
                "base_contribution": round(undecayed, 3),
                "contribution": round(contribution, 3),
                "categories": categories,
            }
            all_contributing.append(condensed)
            retained[condensed.get("anomaly_id") or (method, anomaly_time)] = condensed

        # Recompute categories from ALL retained anomalies (old + new),
        # decaying each against the data clock
        new_categories = dict.fromkeys(THREAT_CATEGORIES, 0.0)
        survivors: list[dict] = []
        # R1 (round 3): iterate VALUES, never unpack keys — keys are
        # anomaly_id strings (or legacy tuples) and unpacking a string
        # into (method, ts) raised ValueError on every real run.
        # R2 (round 3): decay ONCE per run from the stored UNDECAYED
        # base — the old path stored the already-decayed contribution
        # and decayed it again each run (compounding; ~2h memory).
        for a in retained.values():
            ts = a.get("timestamp", "")
            # N2.3: legacy zombies — empty-ts entries already in a store
            # (written by the immortal-guard era, or by N2.1's
            # absent-means-absent exfil stamps before anyone disposed of
            # them) are dropped here, not resurrected.
            if not ts:
                continue
            base = a.get("base_contribution", a.get("contribution", 0.0))
            decay = _decay_factor(ts, half_life_hours, ref=ent_ref)  # N2.2: per-entity
            contribution = base * decay
            # Prune negligible (decayed below 1% of its original weight)
            if contribution < 0.05:
                continue
            survivors.append({**a, "base_contribution": round(base, 3),
                              "contribution": round(contribution, 3)})
            for cat in a.get("categories", []):
                n_cats = max(len(a.get("categories", [])), 1)
                if cat in new_categories:
                    new_categories[cat] += contribution / n_cats

        # Compute overall as max of category scores, capped at 100
        for cat, val in new_categories.items():
            new_categories[cat] = min(val, _MAX_SCORE)
        overall = min(max(new_categories.values()), _MAX_SCORE)

        # Compute trend: (current - previous) / hours_since_last_update
        if score.last_updated:
            hours = _hours_since_ref(score.last_updated, ent_ref)  # N2.2: per-entity
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
        score.last_updated = ent_now  # N2.2: the entity's own clock
        score.contributing_anomalies = survivors[-max_anomalies:]
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
                # N2.2: the INACTIVE entity decays against ITS OWN persisted
                # clock and does NOT advance it — no activity means no
                # advancement (a dormant score reflects last known activity;
                # bob's newer batch cannot age alice). The clock advances
                # only when the entity's own stream does.
                own = _pit(str(score.data_clock or "")) if score.data_clock else None
                own_ref = own if own is not None else ref_clock
                hours = _hours_since_ref(score.last_updated, own_ref)  # N2.2: per-entity
                decay = 0.5 ** (hours / half_life_hours)
                score.overall = min(score.overall * decay, _MAX_SCORE)
                for cat in score.categories:
                    score.categories[cat] = min(score.categories[cat] * decay, _MAX_SCORE)
                # R2: refresh the retained survivors' displayed contributions
                # from base against the current reference (inactive entities
                # keep accurate per-anomaly decay, not just the overall score)
                # N2.3: empty-ts entries are zombies — dropped, not refreshed
                # (the `else 1.0` guard kept them at full weight forever).
                survivors_active: list[dict] = []
                for a in score.contributing_anomalies:
                    ts_a = a.get("timestamp", "")
                    if not ts_a:
                        continue
                    base_a = a.get("base_contribution", a.get("contribution", 0.0))
                    d_a = _decay_factor(ts_a, half_life_hours, ref=own_ref)  # N2.2: per-entity
                    a["contribution"] = round(base_a * d_a, 3)
                    survivors_active.append(a)
                score.contributing_anomalies = survivors_active
                score.trend = -score.overall * (1 - decay) / max(hours, 0.1)

    store.save()
    if degraded_missing_ts:
        logger.warning(
            "Risk scoring skipped %d anomalies with missing timestamps "
            "(counted as a degradation — absent means absent, never 'now')",
            degraded_missing_ts,
        )
        store.missing_timestamp_anomalies = degraded_missing_ts
    else:
        store.missing_timestamp_anomalies = 0
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
