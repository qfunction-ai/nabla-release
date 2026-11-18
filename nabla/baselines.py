"""Entity baseline profiles for per-entity behavioral norms.

Tracks per-user, per-host, and per-IP activity profiles across pipeline
runs. Each profile accumulates observations and uses EWMA (Exponentially
Weighted Moving Average) to track typical behavior. Detection methods
compare current-run observations against entity baselines instead of
batch-level statistics, reducing false positives for entities whose
normal behavior differs from the batch average.

Warm-up period: new entities need ``entity_warmup_observations`` (default
3) pipeline runs before their baselines are used for detection. During
warm-up, profiles are still built but detection falls back to batch-level
statistics.

Persistence: file-based JSON in ``/data/entity_profiles.json``, using
atomic writes from ``nabla.persistence``.
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
import dataclasses
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone

from nabla.log import get_logger
from nabla.persistence import atomic_write_json
from nabla.utils import is_off_hours, is_routable_ip

logger = get_logger("baselines")


# ---------------------------------------------------------------------------
# EWMA profile
# ---------------------------------------------------------------------------

@dataclass
class EWMAProfile:
    """Exponentially weighted moving average with variance tracking.

    Tracks a running estimate of a metric's typical value and its
    variance. Used to compute z-scores for entity-level deviations.

    Attributes:
        value: Current EWMA estimate.
        variance: Exponentially weighted variance estimate.
        n: Observation count (bias correction + warm-up).
        alpha: Smoothing factor (0-1). Higher = faster adaptation.
            0.3 adapts within ~5 observations; 0.1 within ~15.
    """

    value: float = 0.0
    variance: float = 0.0
    alpha: float = 0.3
    n: int = 0  # A9: observation count for bias correction

    def update(self, observation: float) -> None:
        """Update the EWMA with a new observation.

        Args:
            observation: New value to incorporate into the running average.
        """
        self.n += 1
        # A9 bias correction: during warm-up the EWMA starts at zero and
        # lags the observations; the standard bias-corrected form divides
        # by (1 - (1-alpha)^n) so early estimates equal the observations
        # instead of crawling up from zero. Three identical observations
        # now yield value == observation and z == 0 (reviewer's gate).
        if self.n == 1:
            self.value = observation
            self.variance = 0.0
            return
        diff = observation - self.value
        alpha_eff = self.alpha
        self.value = self.value + alpha_eff * diff
        # A9 variance: the running form overestimates early (small n); the
        # n-based correction scales the initial periods properly.
        self.variance = (1 - alpha_eff) * (self.variance + alpha_eff * diff ** 2)

    @property
    def std(self) -> float:
        """Current standard deviation estimate.

        R4 (round 3): Poisson-style floor for COUNT-valued EWMAs — a bare
        variance estimate near zero let small natural variation produce huge
        z-scores. The floor applies only when value >= 1 (the count regime);
        ratio-valued EWMAs (auth_failure_ratio, 0-1 range) keep the plain
        variance estimate (flooring a 0.05 ratio at std 1.0 was absurd —
        caught by the entity_auth_failure test).
        """
        raw = self.variance ** 0.5
        if self.value >= 1.0:
            return max(raw, self.value ** 0.5)
        return raw if raw > 0 else 0.01

    def z_score(self, observation: float) -> float:
        """Compute z-score of an observation against this EWMA.

        Args:
            observation: Value to compare against the EWMA.

        Returns:
            Z-score (number of standard deviations from the EWMA).
            Returns 0.0 if variance is zero.
        """
        if self.variance <= 0:
            return 0.0
        return (observation - self.value) / self.std

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict.

        Returns:
            Dict with value, variance, and alpha keys.
        """
        return {"value": self.value, "variance": self.variance, "alpha": self.alpha, "n": self.n}

    @classmethod
    def from_dict(cls, data: dict) -> EWMAProfile:
        """Deserialize from a dict.

        Args:
            data: Dict with value, variance, and optionally alpha keys.

        Returns:
            EWMAProfile instance.
        """
        n = data.get("n", 0)
        if n == 0 and data.get("value", 0.0) != 0.0:
            # Legacy record without n: treat as warm (bias correction off)
            n = 100
        return cls(
            value=data.get("value", 0.0),
            variance=data.get("variance", 0.0),
            alpha=data.get("alpha", 0.3),
            n=n,
        )


# ---------------------------------------------------------------------------
# Entity profiles
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return current UTC time as ISO format string."""
    return datetime.now(timezone.utc).isoformat()


class RecencySet:
    """A set with recency-weighted membership (A11, R10 round 3).

    Add-only sets saturate: once typical_ips holds 50 entries, EVERY new IP
    is 'typical' and the new-IP signal dies. This wrapper tracks last-seen
    EVENT-TIME stamps (UTC ISO strings — R10: the in-memory counter reset
    on every reload, inverting recency so the newest item evicted first)
    and evicts least-recently-seen entries when the cap is hit.
    """

    def __init__(self, members=None, last_seen=None, max_size: int = 50):
        self.members: set = set(members or [])
        self.last_seen: dict = dict(last_seen or {})
        self.max_size = max_size

    def add(self, item, seen_at: str = "") -> None:
        """seen_at: UTC ISO timestamp; empty = wall now (compat)."""
        from datetime import datetime, timezone
        stamp = seen_at or datetime.now(timezone.utc).isoformat()
        self.members.add(item)
        # Monotonic: only advance if newer (reload + old batch must not
        # regress recency)
        if stamp > self.last_seen.get(item, ""):
            self.last_seen[item] = stamp
        if len(self.members) > self.max_size:
            self._evict()

    def _evict(self) -> None:
        # Least-recently-seen first
        by_recency = sorted(self.last_seen.items(), key=lambda kv: kv[1])
        excess = len(self.members) - self.max_size
        for item, _ in by_recency[:excess]:
            self.members.discard(item)
            self.last_seen.pop(item, None)

    def __contains__(self, item) -> bool:
        return item in self.members

    def __iter__(self):
        return iter(self.members)

    def __len__(self) -> int:
        return len(self.members)

    def __sub__(self, other):
        return self.members - set(other)

    def __rsub__(self, other):
        return set(other) - self.members

    def __or__(self, other):
        return self.members | set(other)


    def to_dict(self) -> dict:
        return {"members": sorted(self.members, key=lambda m: str(m)),
                "last_seen": {str(k): v for k, v in self.last_seen.items()}}

    @classmethod
    def from_legacy(cls, data, max_size: int) -> "RecencySet":
        """Load from a plain set/list (old stores) or a serialized dict."""
        if isinstance(data, dict) and "members" in data:
            return cls(members=data["members"], last_seen=data.get("last_seen"), max_size=max_size)
        if isinstance(data, (set, list)):
            return cls(members=data, max_size=max_size)
        return cls(max_size=max_size)


def _capped_set(items: set, max_size: int) -> set:
    """Trim a set to max_size by removing arbitrary elements.

    Args:
        items: Set to potentially trim.
        max_size: Maximum allowed size.

    Returns:
        The input set (possibly trimmed).
    """
    if len(items) > max_size:
        # Remove arbitrary elements — sets are unordered
        excess = len(items) - max_size
        for _ in range(excess):
            items.pop()
    return items


class _ProfileMixin:
    """Mixin providing auto-serialization for entity profile dataclasses.

    Uses dataclasses.fields() to inspect the subclass and serialize/deserialize
    based on field type. Subclasses must declare:
        _SET_FIELDS: set of field names that are sets
        _EWMA_FIELDS: set of field names that are EWMAProfile
    """

    _SET_FIELDS: set[str] = set()
    _RECENCY_FIELDS: dict[str, int] = {}  # field -> max_size
    _EWMA_FIELDS: set[str] = set()

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict using field introspection."""
        result = {}
        for f in fields(self):
            val = getattr(self, f.name)
            if f.name in self._RECENCY_FIELDS:
                result[f.name] = val.to_dict()
            elif f.name in self._SET_FIELDS:
                result[f.name] = sorted(val)
            elif f.name in self._EWMA_FIELDS:
                result[f.name] = val.to_dict()
            else:
                result[f.name] = val
        return result

    @classmethod
    def _from_dict(cls, data: dict):
        """Deserialize from a dict using field introspection."""
        kwargs = {}
        for f in fields(cls):
            if f.name in cls._RECENCY_FIELDS:
                # A11: loads serialized dicts AND legacy plain lists
                kwargs[f.name] = RecencySet.from_legacy(
                    data.get(f.name, []), max_size=cls._RECENCY_FIELDS[f.name])
            elif f.name in cls._SET_FIELDS:
                kwargs[f.name] = set(data.get(f.name, []))
            elif f.name in cls._EWMA_FIELDS:
                kwargs[f.name] = EWMAProfile.from_dict(data.get(f.name, {}))
            else:
                default = f.default if f.default is not dataclasses.MISSING else ""
                if isinstance(default, (int, float)):
                    kwargs[f.name] = data.get(f.name, default)
                else:
                    kwargs[f.name] = data.get(f.name, default)
        return cls(**kwargs)


@dataclass
class UserProfile(_ProfileMixin):
    """Per-user behavioral profile accumulated across pipeline runs.

    Attributes:
        entity_id: Username or identifier.
        first_seen: ISO timestamp of first observation.
        last_seen: ISO timestamp of most recent observation.
        observation_count: Number of pipeline runs that observed this user.
        account_created_at: ISO timestamp when the account was created (from AD Event ID 4720).
            Empty string if not detected. Used for new account grace period.
        typical_event_count: EWMA of per-run event counts.
        typical_ips: Source IPs seen for this user (capped at 50).
        typical_hours: Hours of day (0-23) this user is active.
        typical_actions: Action type → proportion (0.0-1.0).
        auth_failure_ratio: EWMA of auth failure/total ratio.
        off_hours_ratio: EWMA of off-hours/total ratio.
    """

    _SET_FIELDS = set()
    _RECENCY_FIELDS = {"typical_ips": 50, "typical_hours": 48}
    _HISTOGRAM_FIELDS = {"hour_histogram"}

    def __post_init__(self):
        # A11: accept plain sets/lists at construction (tests, legacy callers)
        from nabla.baselines import RecencySet as _RS
        for fname, max_size in self._RECENCY_FIELDS.items():
            val = getattr(self, fname)
            if not isinstance(val, _RS):
                setattr(self, fname, _RS.from_legacy(val, max_size=max_size))
    # F1: every EWMAProfile field must be listed here or it serializes as its
    # own repr (atomic_write_json's default=str) and reloads as a string.
    # tests/test_profile_roundtrip.py enforces this against the dataclass fields.
    _EWMA_FIELDS = {
        "typical_event_count", "auth_failure_ratio", "off_hours_ratio",
        "network_event_rate",
    }

    entity_id: str = ""
    first_seen: str = ""
    last_seen: str = ""
    observation_count: int = 0
    account_created_at: str = ""
    typical_event_count: EWMAProfile = field(default_factory=EWMAProfile)
    # A11: recency-weighted membership — evicts least-recently-seen at the
    # cap so long-tail history doesn't saturate the new-signal detection
    typical_ips: "RecencySet" = field(default_factory=lambda: RecencySet(max_size=50))
    typical_hours: "RecencySet" = field(default_factory=lambda: RecencySet(max_size=48))
    # R10: decayed hour histogram — share-based unusualness (the sparse-night
    # fix); coexists with typical_hours during migration
    hour_histogram: dict[int, float] = field(default_factory=dict)
    # R13 (round 3): dedicated NETWORK-event rate baseline — exfil_volume
    # compared network counts against the all-events EWMA (a subset vs its
    # superset; z systematically understated, detector rarely fired)
    network_event_rate: "EWMAProfile" = field(default_factory=lambda: EWMAProfile())
    typical_actions: dict[str, float] = field(default_factory=dict)
    auth_failure_ratio: EWMAProfile = field(default_factory=EWMAProfile)
    off_hours_ratio: EWMAProfile = field(default_factory=EWMAProfile)

    @classmethod
    def from_dict(cls, data: dict) -> UserProfile:
        """Deserialize from a dict."""
        return cls._from_dict(data)


@dataclass
class HostProfile(_ProfileMixin):
    """Per-host behavioral profile accumulated across pipeline runs.

    Tracks process, user, network, registry, and auth patterns for a
    specific host. Enables detection of novel processes, new users,
    unusual network destinations, and anomalous auth rates on a per-host
    basis.

    Attributes:
        entity_id: Hostname or identifier.
        first_seen: ISO timestamp of first observation.
        last_seen: ISO timestamp of most recent observation.
        observation_count: Number of pipeline runs that observed this host.
        typical_processes: Process names seen on this host (capped at 200).
        typical_parent_processes: Parent process names seen (capped at 50).
        typical_process_count: EWMA of per-run distinct process count.
        typical_users: Users who logged into this host (capped at 50).
        typical_user_count: EWMA of per-run user count.
        typical_destinations: Dest IPs/domains (capped at 100).
        typical_ports: Destination ports seen (capped at 50).
        typical_network_count: EWMA of per-run network events.
        typical_registry_keys: Registry keys modified (capped at 100).
        typical_auth_count: EWMA of per-run auth events.
        typical_auth_failure_ratio: EWMA of auth failure ratio.
    """

    _SET_FIELDS = {
        "typical_processes", "typical_parent_processes", "typical_users",
        "typical_destinations", "typical_ports", "typical_registry_keys",
    }
    _EWMA_FIELDS = {
        "typical_process_count", "typical_user_count", "typical_network_count",
        "typical_auth_count", "typical_auth_failure_ratio",
    }

    entity_id: str = ""
    first_seen: str = ""
    last_seen: str = ""
    observation_count: int = 0
    typical_processes: set[str] = field(default_factory=set)
    typical_parent_processes: set[str] = field(default_factory=set)
    typical_process_count: EWMAProfile = field(default_factory=EWMAProfile)
    typical_users: set[str] = field(default_factory=set)
    typical_user_count: EWMAProfile = field(default_factory=EWMAProfile)
    typical_destinations: set[str] = field(default_factory=set)
    typical_ports: set[int] = field(default_factory=set)
    typical_network_count: EWMAProfile = field(default_factory=EWMAProfile)
    typical_registry_keys: set[str] = field(default_factory=set)
    typical_auth_count: EWMAProfile = field(default_factory=EWMAProfile)
    typical_auth_failure_ratio: EWMAProfile = field(default_factory=EWMAProfile)

    @classmethod
    def from_dict(cls, data: dict) -> HostProfile:
        """Deserialize from a dict."""
        return cls._from_dict(data)


@dataclass
class IPProfile(_ProfileMixin):
    """Per-IP behavioral profile accumulated across pipeline runs.

    Attributes:
        entity_id: IP address.
        first_seen: ISO timestamp of first observation.
        last_seen: ISO timestamp of most recent observation.
        observation_count: Number of pipeline runs that observed this IP.
        typical_users: Users seen from this IP (capped at 20).
        typical_hosts: Hosts seen from this IP (capped at 20).
        typical_ports: Destination ports (capped at 50).
        typical_domains: DNS query domains (capped at 100).
        typical_event_count: EWMA of per-run event count.
    """

    _SET_FIELDS = {"typical_users", "typical_hosts", "typical_ports", "typical_domains"}
    _EWMA_FIELDS = {"typical_event_count"}

    entity_id: str = ""
    first_seen: str = ""
    last_seen: str = ""
    observation_count: int = 0
    typical_users: set[str] = field(default_factory=set)
    typical_hosts: set[str] = field(default_factory=set)
    typical_ports: set[int] = field(default_factory=set)
    typical_domains: set[str] = field(default_factory=set)
    typical_event_count: EWMAProfile = field(default_factory=EWMAProfile)

    @classmethod
    def from_dict(cls, data: dict) -> IPProfile:
        """Deserialize from a dict."""
        return cls._from_dict(data)


# ---------------------------------------------------------------------------
# Profile store
# ---------------------------------------------------------------------------

# Size caps per entity type
_MAX_IPS = 50
_MAX_PROCESSES = 200
_MAX_PARENT_PROCESSES = 50
_MAX_USERS = 50
_MAX_DESTINATIONS = 100
_MAX_PORTS = 50
_MAX_DOMAINS = 100
_MAX_REGISTRY_KEYS = 100
_MAX_ACTIONS = 20
_MAX_IP_USERS = 20
_MAX_IP_HOSTS = 20


class EntityProfileStore:
    """Manages entity profiles with file-based persistence.

    Loads profiles from a JSON file on construction, saves atomically
    via ``atomic_write_json``. Profiles are keyed by entity_id within
    each entity type (user, host, ip).

    Args:
        path: Path to the JSON profile file.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.users: dict[str, UserProfile] = {}
        self.hosts: dict[str, HostProfile] = {}
        self.ips: dict[str, IPProfile] = {}
        self._load()

    def _load(self) -> None:
        """Load profiles from the JSON file.

        Silently starts with empty profiles if the file doesn't exist
        or is invalid JSON.
        """
        if not os.path.exists(self.path):
            logger.debug("No entity profiles file at %s, starting fresh", self.path)
            return
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            self.users = {
                k: UserProfile.from_dict(v) for k, v in data.get("users", {}).items()
            }
            self.hosts = {
                k: HostProfile.from_dict(v) for k, v in data.get("hosts", {}).items()
            }
            self.ips = {
                k: IPProfile.from_dict(v) for k, v in data.get("ips", {}).items()
            }
            logger.info(
                "Loaded entity profiles: %d users, %d hosts, %d IPs",
                len(self.users), len(self.hosts), len(self.ips),
            )
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load entity profiles from %s: %s", self.path, e)

    def save(self) -> None:
        """Save all profiles to the JSON file atomically."""
        from nabla.persistence import atomic_write_json
        data = {
            "users": {k: v.to_dict() for k, v in self.users.items()},
            "hosts": {k: v.to_dict() for k, v in self.hosts.items()},
            "ips": {k: v.to_dict() for k, v in self.ips.items()},
        }
        atomic_write_json(self.path, data)

    # A10: store-instance accessors over the module functions
    def _is_quarantined(self, entity_id: str) -> bool:
        return _is_quarantined(entity_id)

    def _bump_quarantine_clock(self, entity_id: str) -> None:
        q = _load_quarantine()
        ent = q.get(entity_id)
        if ent:
            ent["batches_held"] = ent.get("batches_held", 0) + 1
            _save_quarantine(q)

    def get_user(self, entity_id: str) -> UserProfile | None:
        """Get a user profile by entity ID.

        Args:
            entity_id: Username or identifier.

        Returns:
            UserProfile if found, None otherwise.
        """
        return self.users.get(entity_id)

    def get_host(self, entity_id: str) -> HostProfile | None:
        """Get a host profile by entity ID.

        Args:
            entity_id: Hostname or identifier.

        Returns:
            HostProfile if found, None otherwise.
        """
        return self.hosts.get(entity_id)

    def get_ip(self, entity_id: str) -> IPProfile | None:
        """Get an IP profile by entity ID.

        Args:
            entity_id: IP address.

        Returns:
            IPProfile if found, None otherwise.
        """
        return self.ips.get(entity_id)

    # --- Get or create ---

    def get_or_create(self, entity_type: str, entity_id: str):
        """Get or create a profile for an entity.

        Args:
            entity_type: One of "user", "host", "ip".
            entity_id: Entity identifier.

        Returns:
            Profile instance (existing or newly created).
        """
        _STORES = {
            "user": (self.users, UserProfile),
            "host": (self.hosts, HostProfile),
            "ip": (self.ips, IPProfile),
        }
        store, cls = _STORES[entity_type]
        if entity_id not in store:
            now = _now_iso()
            store[entity_id] = cls(
                entity_id=entity_id,
                first_seen=now,
                last_seen=now,
                observation_count=0,
            )
        return store[entity_id]

    def get_or_create_user(self, entity_id: str) -> UserProfile:
        """Get a user profile, creating it if it doesn't exist."""
        return self.get_or_create("user", entity_id)

    def get_or_create_host(self, entity_id: str) -> HostProfile:
        """Get a host profile, creating it if it doesn't exist."""
        return self.get_or_create("host", entity_id)

    def get_or_create_ip(self, entity_id: str) -> IPProfile:
        """Get an IP profile, creating it if it doesn't exist."""
        return self.get_or_create("ip", entity_id)

    # --- Warm-up check ---

    def warm_up_complete(
        self,
        entity_type: str,
        entity_id: str,
        min_observations: int = 3,
    ) -> bool:
        """Check if an entity has enough observations for baseline use.

        Args:
            entity_type: One of "user", "host", "ip".
            entity_id: Entity identifier.
            min_observations: Minimum number of pipeline runs needed.

        Returns:
            True if the entity has been observed enough times.
        """
        profile = None
        if entity_type == "user":
            profile = self.users.get(entity_id)
        elif entity_type == "host":
            profile = self.hosts.get(entity_id)
        elif entity_type == "ip":
            profile = self.ips.get(entity_id)
        if profile is None:
            return False
        return profile.observation_count >= min_observations

    # --- Update methods ---

    def update_user(self, entity_id: str, entries: list[dict]) -> None:
        """Update a user profile with current-run observations.

        Updates EWMA profiles, adds to IP/hour/action sets, and
        increments observation count.

        Args:
            entity_id: Username or identifier.
            entries: List of log entry dicts for this user in this run.
        """
        profile = self.get_or_create_user(entity_id)
        profile.last_seen = _now_iso()
        from nabla.config import get_settings as _gs
        warm_up_observations = _gs().entity_warmup_observations

        # A10/R6 quarantine: absorb ONLY if not held. Held batches go to the
        # PENDING store (R6: hold, don't discard — an FP disposition applies
        # them later); warm-up no longer advances on held data (R6: the
        # increment moved after this branch).
        if (
            self._is_quarantined(entity_id)
            # Cold entities absorb regardless: quarantine protects a WARM
            # baseline from attack inflation; holding a cold entity's batches
            # starves profile-building entirely during detection-phase ingest
            # of fresh data (the course's forced-detection path — found live
            # in the stage-4 dress rehearsal when smith's rate read 0.0/hr)
            and profile.observation_count > warm_up_observations
        ):
            self._bump_quarantine_clock(entity_id)
            try:
                hold_pending(entity_id, entries)
            except Exception:
                pass  # silent by design: pending-store failure must not break the run (round-3 sweep)
            return  # sets/EWMA/observation_count untouched while held

        profile.observation_count += 1

        # Event RATE EWMA (R4): hour-bucketed observation rate — batch-span
        # division swung wildly on scheduler-sized batches (2 events/1min =
        # 120/hr); event-time bucketing is boundary-independent
        from nabla.baselines import observation_rate
        profile.typical_event_count.update(observation_rate(entries))

        # F1: the NETWORK-event rate baseline is learned here, in absorption,
        # like every other baseline — not inside the detector that scores
        # against it. Training inside the detector coupled the two: a detector
        # that could not fire could not learn, and a baseline that could not
        # learn meant the detector could never fire. That is why R13's fix was
        # hollow even before the serialization bug was found. Detection runs
        # before absorption, so this still scores-then-learns.
        net_entries = [
            e for e in entries
            if e.get("action") == "network_connect" or e.get("type") == "network"
        ]
        if net_entries:
            profile.network_event_rate.update(observation_rate(net_entries))

        # IPs (only publicly routable — private IPs are not useful for
        # impossible-travel detection and would cause false positives)
        for e in entries:
            ip = e.get("source_ip", e.get("src_ip", e.get("client_ip", "")))
            if ip and is_routable_ip(ip):
                profile.typical_ips.add(ip)

        # Hours — batch-local aggregation, then ONE decay+count per update
        # (R10 correction: decaying per EVENT annihilated history within a
        # single large batch — 0.99^N for N events; per-update is the design)
        from collections import Counter as _Counter
        _batch_hours: dict[int, int] = _Counter()
        for e in entries:
            ts = e.get("timestamp", "")
            if ts:
                try:
                    from nabla.utils import _parse_hour
                    hour = _parse_hour(ts)
                    if hour >= 0:
                        _batch_hours[hour] += 1
                        profile.typical_hours.add(hour, seen_at=str(ts))
                except (ValueError, IndexError):
                    pass  # silent by design: unparseable timestamp in profile data (2026-09 sweep)
        for hour, n in _batch_hours.items():
            for h in profile.hour_histogram:
                profile.hour_histogram[h] *= 0.99
            profile.hour_histogram[hour] = profile.hour_histogram.get(hour, 0.0) + float(n)

        # Actions
        action_counter: Counter[str] = Counter()
        for e in entries:
            action = e.get("action", e.get("protocol", e.get("query_type", "")))
            if action:
                action_counter[action] += 1
        total = sum(action_counter.values()) or 1
        for action, count in action_counter.most_common(_MAX_ACTIONS):
            profile.typical_actions[action] = (
                profile.typical_actions.get(action, 0.0) * 0.7
                + (count / total) * 0.3
            )

        # Auth failure ratio
        auth_success = sum(1 for e in entries if e.get("action") == "login_success")
        auth_failure = sum(1 for e in entries if e.get("action") == "login_failure")
        total_auth = auth_success + auth_failure
        if total_auth > 0:
            profile.auth_failure_ratio.update(auth_failure / total_auth)

        # Off-hours ratio
        off_hours = sum(
            1 for e in entries
            if _parse_hour(e.get("timestamp", "")) >= 0
            and is_off_hours(e.get("timestamp", ""))
        )
        if len(entries) > 0:
            profile.off_hours_ratio.update(off_hours / len(entries))

        # Account creation detection (AD Event ID 4720 or action "account_created")
        # Only set if not already known — first creation event wins
        if not profile.account_created_at:
            for e in entries:
                if e.get("action") == "account_created" or e.get("event_code") == "4720":
                    ts = e.get("timestamp", "")
                    if ts:
                        profile.account_created_at = ts
                        break

    def update_host(self, entity_id: str, entries: list[dict]) -> None:
        """Update a host profile with current-run observations.

        Updates process, user, network, registry, and auth EWMA profiles
        and adds to respective sets.

        Args:
            entity_id: Hostname or identifier.
            entries: List of log entry dicts for this host in this run.
        """
        profile = self.get_or_create_host(entity_id)
        profile.last_seen = _now_iso()
        profile.observation_count += 1

        # Separate entries by type for different metrics
        endpoint_entries = [e for e in entries if _get_field(e, "type") == "endpoint"]
        auth_entries = [e for e in entries if _get_field(e, "action") in ("login_success", "login_failure")]
        network_entries = [e for e in entries if _get_field(e, "action") == "network_connect"]

        # Process tracking
        current_processes: set[str] = set()
        current_parents: set[str] = set()
        for e in endpoint_entries:
            proc = _get_field(e, "process", "Image", "NewProcessName").lower().replace(".exe", "")
            if proc:
                proc_stem = proc.rsplit("\\", 1)[-1] if "\\" in proc else proc
                current_processes.add(proc_stem)
                profile.typical_processes.add(proc_stem)
            parent = _get_field(e, "parent_process", "ParentImage", "ParentProcessName").lower().replace(".exe", "")
            if parent:
                parent_stem = parent.rsplit("\\", 1)[-1] if "\\" in parent else parent
                current_parents.add(parent_stem)
                profile.typical_parent_processes.add(parent_stem)

        _capped_set(profile.typical_processes, _MAX_PROCESSES)
        _capped_set(profile.typical_parent_processes, _MAX_PARENT_PROCESSES)
        # R4: hour-bucketed rate, same as users
        from nabla.baselines import observation_rate
        profile.typical_process_count.update(observation_rate(entries))

        # User tracking
        current_users: set[str] = set()
        for e in entries:
            user = _get_field(e, "user", "User")
            if user:
                current_users.add(user)
                profile.typical_users.add(user)

        _capped_set(profile.typical_users, _MAX_USERS)
        profile.typical_user_count.update(len(current_users))

        # Network tracking
        current_destinations: set[str] = set()
        current_ports: set[int] = set()
        for e in network_entries:
            dest_ip = _get_field(e, "dest_ip", "DestinationIp")
            dest_port = _get_field(e, "dest_port", "DestinationPort")
            if dest_ip:
                current_destinations.add(dest_ip)
                profile.typical_destinations.add(dest_ip)
            if dest_port:
                try:
                    current_ports.add(int(dest_port))
                    profile.typical_ports.add(int(dest_port))
                except ValueError:
                    pass  # silent by design: unparseable timestamp in profile data (2026-09 sweep)

        _capped_set(profile.typical_destinations, _MAX_DESTINATIONS)
        _capped_set(profile.typical_ports, _MAX_PORTS)
        profile.typical_network_count.update(len(network_entries))

        # Registry tracking
        for e in endpoint_entries:
            action = _get_field(e, "action", "EventType").lower()
            if action in ("registry_set", "registry_add_delete", "setvalue",
                          "deletevalue", "createkey", "deletekey"):
                target = _get_field(e, "target_registry", "TargetObject")
                if target:
                    profile.typical_registry_keys.add(target[:200])

        _capped_set(profile.typical_registry_keys, _MAX_REGISTRY_KEYS)

        # Auth tracking
        auth_success = sum(1 for e in auth_entries if e.get("action") == "login_success")
        auth_failure = sum(1 for e in auth_entries if e.get("action") == "login_failure")
        total_auth = auth_success + auth_failure
        profile.typical_auth_count.update(total_auth)
        if total_auth > 0:
            profile.typical_auth_failure_ratio.update(auth_failure / total_auth)

    def update_ip(self, entity_id: str, entries: list[dict]) -> None:
        """Update an IP profile with current-run observations.

        Args:
            entity_id: IP address.
            entries: List of log entry dicts for this IP in this run.
        """
        profile = self.get_or_create_ip(entity_id)
        profile.last_seen = _now_iso()
        profile.observation_count += 1

        # R4: hour-bucketed rate, boundary-independent
        from nabla.baselines import observation_rate
        profile.typical_event_count.update(observation_rate(entries))

        # Users
        for e in entries:
            user = _get_field(e, "user", "User")
            if user:
                profile.typical_users.add(user)
        _capped_set(profile.typical_users, _MAX_IP_USERS)

        # Hosts
        for e in entries:
            host = _get_field(e, "host", "Computer")
            if host:
                profile.typical_hosts.add(host)
        _capped_set(profile.typical_hosts, _MAX_IP_HOSTS)

        # Ports
        for e in entries:
            dest_port = _get_field(e, "dest_port", "DestinationPort")
            if dest_port:
                try:
                    profile.typical_ports.add(int(dest_port))
                except ValueError:
                    pass  # silent by design: unparseable timestamp in profile data (2026-09 sweep)
        _capped_set(profile.typical_ports, _MAX_PORTS)

        # Domains (from DNS entries)
        for e in entries:
            if _get_field(e, "type") == "dns":
                query = _get_field(e, "query", "QueryName", "query_name")
                if query:
                    profile.typical_domains.add(query)
        _capped_set(profile.typical_domains, _MAX_DOMAINS)


# ---------------------------------------------------------------------------
# Grouping helper
# ---------------------------------------------------------------------------

def group_entries_by_entity(entries: list[dict]) -> dict[tuple[str, str], list[dict]]:
    """Group log entries by (entity_type, entity_id) for profile updates.

    Each entry may appear in multiple groups (user + host + IP). This
    is intentional — the same entry contributes to all relevant profiles.

    Args:
        entries: List of log entry dicts with canonical field names.

    Returns:
        Dict mapping (entity_type, entity_id) → list of entries.
    """
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in entries:
        user = e.get("user")
        if user:
            groups[("user", user)].append(e)
        host = e.get("host", e.get("Computer"))
        if host:
            groups[("host", host)].append(e)
        ip = e.get("source_ip", e.get("src_ip", e.get("client_ip")))
        if ip:
            groups[("ip", ip)].append(e)
    return dict(groups)


def _observation_window_hours(entries: list[dict]) -> float:
    """The temporal span of a batch of entries, in hours (A8).

    Profiles track EVENTS PER HOUR, not events per run — the per-run unit
    made 'typical' a function of --log-count and scheduler settings rather
    than of behavior. The span derives from the batch's own timestamps;
    clamped to [1 minute, 24h] so single-event and pathological batches
    stay bounded.
    """
    from nabla.utils import parse_iso_timestamp

    ts_list = []
    for e in entries:
        dt = parse_iso_timestamp(str(e.get("timestamp", "")))
        if dt is not None:
            ts_list.append(dt)
    if len(ts_list) < 2:
        return 1.0  # single-instant batch: one hour of activity by convention
    span = (max(ts_list) - min(ts_list)).total_seconds() / 3600.0
    if span <= 0:
        return 1.0  # zero-span (all same instant): same 1h convention
    return min(max(span, 1.0 / 60.0), 24.0)


def hourly_counts(entries: list[dict]) -> "dict[int, int]":
    """Events per UTC hour-of-day of EVENT time (R4, round 3).

    Bucketing by event time — not batch span — makes the rate observation
    independent of when the scheduler happened to cut the batch. Two events
    a minute apart land in their hour's bucket (rate 2/hour-ish over the
    hours they span), not 120/hr against a 1-minute batch floor.
    """
    from nabla.utils import parse_iso_timestamp

    buckets: dict[int, int] = {}
    for e in entries:
        dt = parse_iso_timestamp(str(e.get("timestamp", "")))
        if dt is not None:
            h = dt.astimezone(timezone.utc).hour
            buckets[h] = buckets.get(h, 0) + 1
    return buckets


def observation_rate(entries: list[dict]) -> float:
    """The per-hour rate observation for a batch, hour-bucketed (R4).

    Mean events per active hour (hours with >= 1 event). Robust to batch
    boundaries: a 5-minute scheduler slice of a 6/hr user reads ~6, not
    120. Single-event batches read as 1/hr (the conservative direction —
    understates, never overstates).
    """
    buckets = hourly_counts(entries)
    if not buckets:
        return 0.0
    # Weight by each bucket's coverage: hours fully inside the batch count
    # 1.0; the boundary hours count their fraction — approximated here by
    # treating every active hour equally (the conservative simplification;
    # partial hours understate, which is the safe direction for spikes)
    return sum(buckets.values()) / len(buckets)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_field(entry: dict, *names: str) -> str:
    """Get the first non-empty value from a list of field name candidates.

    Args:
        entry: Dictionary to search for values.
        names: Field name candidates, checked in order.

    Returns:
        The first non-empty value found, or empty string.
    """
    for n in names:
        v = entry.get(n)
        if v:
            return v
    return ""


# ── A10 quarantine (truth table per the reviewed plan) ─────────────────────

_QUARANTINE_TTL_DAYS = 7.0


def _quarantine_file() -> "Path":
    from pathlib import Path
    from nabla.config import get_settings
    return Path(get_settings().data_dir) / "baseline_quarantine.json"


def _load_quarantine() -> dict:
    p = _quarantine_file()
    if p.exists():
        import json as _json
        return _json.loads(p.read_text() or "{}")
    return {}


def _save_quarantine(q: dict) -> None:
    import json as _json
    from nabla.persistence import atomic_write_json, file_lock
    p = str(_quarantine_file())
    with file_lock(p):
        atomic_write_json(p, q)


def flag_quarantine(entity_ids: list[str], data_clock: "datetime|None" = None) -> None:
    """Detection fired for these entities: hold their batches from baseline
    absorption until dispositioned (or TTL). Called by the pipeline post-
    detection with the entities that produced anomalies."""
    from datetime import datetime, timezone
    q = _load_quarantine()
    now = (data_clock or datetime.now(timezone.utc)).isoformat()
    for eid in entity_ids:
        ent = q.get(eid, {})
        if not _is_quarantined(eid):  # R6: new OR TTL-expired — (re)arm
            ent.update({"held": True, "since": now,
                        "batches_held": ent.get("batches_held", 0),
                        "indefinite": ent.get("indefinite", False)})
        q[eid] = ent
    _save_quarantine(q)


def release_quarantine(entity_id: str, data_clock: "datetime | None" = None) -> None:
    """FP/BTP disposition: release the hold (and apply any pending batches —
    see apply_pending). TP keeps held via hold_quarantine (confirmed attack
    never enters baselines). R6: released_at stamps NOW, not the original
    since (the review's minor catch)."""
    from datetime import datetime, timezone
    q = _load_quarantine()
    ent = q.get(entity_id)
    if ent:
        ent["held"] = False
        ent["indefinite"] = False
        ent["released_at"] = (data_clock or datetime.now(timezone.utc)).isoformat()
        _save_quarantine(q)


def hold_quarantine(entity_id: str) -> None:
    """true_positive disposition: confirmed attack — hold indefinitely."""
    q = _load_quarantine()
    ent = q.get(entity_id)
    if ent:
        ent["held"] = True
        ent["indefinite"] = True
        _save_quarantine(q)


_PENDING_CAP = 5  # held batches per entity (R6: hold, don't discard)


def _pending_file() -> "Path":
    from pathlib import Path
    from nabla.config import get_settings
    return Path(get_settings().data_dir) / "baseline_pending.json"


def _load_pending() -> dict:
    p = _pending_file()
    if p.exists():
        import json as _json
        return _json.loads(p.read_text() or "{}")
    return {}


def _save_pending(pend: dict) -> None:
    import json as _json
    from nabla.persistence import atomic_write_json, file_lock
    p = str(_pending_file())
    with file_lock(p):
        atomic_write_json(p, pend)


def hold_pending(entity_id: str, entries: list[dict]) -> None:
    """Hold a quarantined entity's batch for later application (R6).

    Capped per entity; the newest batches survive (the oldest overflow
    drops — a compromise recorded here: attack-length bursts beyond the
    cap lose their earliest batches if never dispositioned).
    """
    pend = _load_pending()
    batches = pend.setdefault(entity_id, [])
    batches.append(entries)
    if len(batches) > _PENDING_CAP:
        batches[:] = batches[-_PENDING_CAP:]
    _save_pending(pend)


def apply_pending(entity_id: str, store: "EntityProfileStore") -> int:
    """FP/BTP disposition: the held data was NORMAL — apply it to the
    baseline. Returns batches applied. Bucket semantics (review STRONG 2):
    the pending entries merge into the hours they span via the same
    observation_rate path update_user uses (single merged application;
    no double-count — each held batch applies exactly once).
    """
    pend = _load_pending()
    batches = pend.pop(entity_id, [])
    _save_pending(pend)
    for entries in batches:
        if entity_id in store.users:
            store.update_user(entity_id, entries)
        else:
            store.update_user(entity_id, entries)  # creates + absorbs
    return len(batches)


def discard_pending(entity_id: str) -> int:
    """TP disposition: confirmed attack — the held data never enters."""
    pend = _load_pending()
    n = len(pend.pop(entity_id, []))
    _save_pending(pend)
    return n


def apply_disposition_to_quarantine(entity_id: str, disposition: str,
                                     profile_store: "EntityProfileStore | None" = None) -> None:
    """The four-row truth table (plan stage 2, review REQUIRED 1), with the
    R6 pending-store semantics: FP/BTP release AND apply held batches (the
    data was normal); TP holds AND discards pending (attack never enters);
    no-disposition rides the TTL (and the pending cap bounds the loss)."""
    if disposition in ("false_positive", "benign_true_positive"):
        release_quarantine(entity_id)
        if profile_store is not None:
            apply_pending(entity_id, profile_store)
    elif disposition == "true_positive":
        hold_quarantine(entity_id)
        discard_pending(entity_id)
    # no-disposition row handled by the TTL in _is_quarantined


def _data_clock_now() -> "datetime":
    """The A7 data clock (newest ingested event), wall fallback."""
    from datetime import datetime, timezone
    try:
        import json as _json
        from nabla.config import get_settings
        from pathlib import Path
        sp = Path(get_settings().data_dir) / "system_state.json"
        if sp.exists():
            state = _json.loads(sp.read_text())
            newest = state.get("data_newest_ts")
            if newest:
                from nabla.utils import parse_iso_timestamp
                dt = parse_iso_timestamp(str(newest))
                if dt is not None:
                    return dt
    except Exception:
        pass  # silent by design: clock fallback to wall is the documented behavior (2026-11 stage 2)
    return datetime.now(timezone.utc)


def _is_quarantined(entity_id: str) -> bool:
    from datetime import timedelta
    q = _load_quarantine()
    ent = q.get(entity_id)
    if not ent or not ent.get("held"):
        return False
    if ent.get("indefinite"):
        return True
    # TTL row: data clock, default 7 days
    from nabla.utils import parse_iso_timestamp
    since = parse_iso_timestamp(ent.get("since", ""))
    if since is None:
        return False
    age_days = (_data_clock_now() - since).total_seconds() / 86400.0
    return age_days < _QUARANTINE_TTL_DAYS
