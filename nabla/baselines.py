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

from pathlib import Path

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
            Z-score (number of standard deviations from the EWMA),
            against the floored std. Returns 0.0 only if std is zero
            (unreachable for count EWMAs — the R4 floor guarantees
            std >= sqrt(value) when value >= 1).

        N10 (round 4): the old guard short-circuited on variance <= 0
        BEFORE consulting std — a perfectly regular user (variance
        exactly 0) scored z=0 on ANY burst, bypassing the R4 Poisson
        floor that exists for precisely that regime. The floor makes
        the guard redundant; the guard made the floor dead code.
        """
        std = self.std
        if std <= 0:
            return 0.0
        return (observation - self.value) / std

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
    # N1: histogram fields (int-hour-keyed dicts). Empty default so classes
    # without one don't crash the shared to_dict/_from_dict lookups;
    # UserProfile overrides with {"hour_histogram"}.
    _HISTOGRAM_FIELDS: set[str] = set()

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
            elif f.name in self._HISTOGRAM_FIELDS:
                # N1 (round 4): JSON stringifies int dict keys; emit them as
                # strings explicitly so the loader's int() repair is the only
                # conversion (no silent str-keyed dicts reaching runtime).
                result[f.name] = {str(k): v for k, v in val.items()}
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
            elif f.name in cls._HISTOGRAM_FIELDS:
                # N1 (round 4): convert string keys (JSON artifact) back to
                # int hours, merging duplicates defensively — a store written
                # by the pre-fix serializer could hold both "10" and 10 if a
                # repair ran mid-life; sum is the lossless merge for counts.
                hist: dict[int, float] = {}
                for k, v in (data.get(f.name) or {}).items():
                    hist[int(k)] = hist.get(int(k), 0.0) + float(v)
                kwargs[f.name] = hist
            else:
                if f.default is not dataclasses.MISSING:
                    default = f.default
                elif f.default_factory is not dataclasses.MISSING:  # type: ignore[attr-defined]
                    # N-2 (round 7): default_factory fields (dict/list state)
                    # deserialize to a FRESH factory value when absent —
                    # the old "" fallback made open_hours deserialize as a
                    # string and crash the engine on first touch.
                    default = f.default_factory()  # type: ignore[misc]
                else:
                    default = ""
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
    # N1: the R10 histogram — UserProfile is the only class with one; the
    # serializer converts int hour keys to strings explicitly and the loader
    # repairs them, because JSON cannot carry int keys and R10 shipped
    # without either half (every hour read unusual after any reload).
    _HISTOGRAM_FIELDS = {"hour_histogram"}

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
    # N-2/R-1 (round 7): the stateful Rule 6 engine state — per-stream
    # (event + network) open-hours maps keyed "source|hour" -> {count,
    # ids, reopen_wm} and observed-hours registries keyed the same ->
    # {count, wm}. Replaces the single open_hour/open_count accumulator
    # (one open hour at a time; late fragments each observed as their
    # own complete hour — the R6-7 undercount) and the shared
    # closed_hours list (no counts, no source separation, no watermark
    # stamps — R-14/R-15).
    open_hours: dict[str, dict] = field(default_factory=dict)
    observed_hours: dict[str, dict] = field(default_factory=dict)
    net_open_hours: dict[str, dict] = field(default_factory=dict)
    net_observed_hours: dict[str, dict] = field(default_factory=dict)
    typical_actions: dict[str, float] = field(default_factory=dict)
    auth_failure_ratio: EWMAProfile = field(default_factory=EWMAProfile)
    off_hours_ratio: EWMAProfile = field(default_factory=EWMAProfile)
    # S7 (round 5): the last absolute hour a rate alert fired for this
    # user — one alert per entity per hour, even when 5-min batches
    # re-score the cumulative hour.
    last_rate_alert_hour: str = ""
    # R-4 (round 7): held-batch IDs already absorbed by a drain — the
    # crash-replay guard. Assigned per batch at HOLD time (a whole-set
    # fingerprint breaks the moment a new approval arrives between crash
    # and restart). Saved with the store; the post-save commit
    # (commit_drain_after_save) removes exactly these batches.
    drained_batch_ids: list[str] = field(default_factory=list)

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
        from nabla.persistence import file_lock
        with file_lock(str(_quarantine_file())):
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

    def update_user(self, entity_id: str, entries: list[dict],
                    *, bypass_quarantine: bool = False,
                    source_kind: str | None = None,
                    watermark: str | None = None) -> None:
        """Update a user profile with current-run observations.

        Updates EWMA profiles, adds to IP/hour/action sets, and
        increments observation count.

        Args:
            entity_id: Username or identifier.
            entries: List of log entry dicts for this user in this run.
            bypass_quarantine: S6 (round 5) — analyst-approved drains pass
                True: a false-positive disposition already ruled on this
                data, so a same-run re-flag must not re-hold it. Only the
                drain path sets this; live batches still respect holds.
            source_kind: N-2 (round 7) — the batch's pipeline source
                ("splunk" | "sumologic" | "synthetic" | "file"). Keys the
                Rule 6 engine's per-(source, hour) state (R-15) and picks
                the mode: SIEM sources are LIVE (watermark semantics);
                file/synthetic are BACKFILL (hour-aligned windows close
                at batch end, V-2). None defaults to "file".
            watermark: the source's watermark (ISO) — the run passes its
                in-memory advanced value; None reads the persisted one.
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
            not bypass_quarantine
            and self._is_quarantined(entity_id)
            # Cold entities absorb regardless: quarantine protects a WARM
            # baseline from attack inflation; holding a cold entity's batches
            # starves profile-building entirely during detection-phase ingest
            # of fresh data (the course's forced-detection path — found live
            # in the stage-4 dress rehearsal when smith's rate read 0.0/hr)
            and profile.observation_count > warm_up_observations
        ):
            self._bump_quarantine_clock(entity_id)
            try:
                hold_pending(entity_id, entries, source_kind=source_kind)
            except Exception:
                pass  # silent by design: pending-store failure must not break the run (round-3 sweep)
            return  # sets/EWMA/observation_count untouched while held

        profile.observation_count += 1

        # Event RATE EWMA (R4): hour-bucketed observation rate — batch-span
        # division swung wildly on scheduler-sized batches (2 events/1min =
        # 120/hr); event-time bucketing is boundary-independent.
        # N-2/R-1 (round 7): the STATEFUL Rule 6 engine replaces the
        # single-accumulator absolute-hour absorption. One EWMA
        # observation per COMPLETE hour, composed across batches through
        # the profile's persisted open-hours state; late pieces re-open
        # and merge (U-1); the source watermark closes hours (R-16's
        # sweep catches quiet entities at run end).
        src = source_kind or "file"
        # synthetic runs on the 5-minute SCHEDULE — it is a live stream,
        # not an hour-aligned backfill window (V-2 applies to file chunks
        # only; the chunker cuts those at hour boundaries).
        mode = "drain" if bypass_quarantine else (
            "live" if src in ("splunk", "sumologic", "synthetic")
            else "backfill")
        if watermark is None:
            watermark = _lookup_source_watermark(src)
        from nabla.pipeline.watermark import absorb_state
        window = _registry_window_days()
        state_ev = {"open": profile.open_hours, "observed": profile.observed_hours}
        _state_ev, obs_ev, _excl = absorb_state(
            state_ev, watermark, entries,
            source_kind=src, mode=mode, window_days=window)
        profile.open_hours = state_ev["open"]
        profile.observed_hours = state_ev["observed"]
        for _key, _count in obs_ev:
            profile.typical_event_count.update(float(_count))

        # F1: the NETWORK-event rate baseline is learned here, in absorption,
        # like every other baseline — not inside the detector that scores
        # against it. Training inside the detector coupled the two: a detector
        # that could not fire could not learn, and a baseline that could not
        # learn meant the detector could never fire. That is why R13's fix was
        # hollow even before the serialization bug was found. Detection runs
        # before absorption, so this still scores-then-learns.
        # R-2 (round 7): the network stream runs the SAME stateful engine
        # with its own open-hours state and registry (the old shared
        # closed_hours list blocked network observation of any hour the
        # event stream had observed — network hours under-observed).
        net_entries = [
            e for e in entries
            if e.get("action") == "network_connect" or e.get("type") == "network"
        ]
        if net_entries:
            state_net = {"open": profile.net_open_hours,
                         "observed": profile.net_observed_hours}
            _state_net, obs_net, _excl_n = absorb_state(
                state_net, watermark, net_entries,
                source_kind=src, mode=mode, window_days=window)
            profile.net_open_hours = state_net["open"]
            profile.net_observed_hours = state_net["observed"]
            for _key, _count in obs_net:
                profile.network_event_rate.update(float(_count))

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
        # N1b (round 4): decay ONCE per update, outside the batch-hours loop —
        # the R10 comment always said "per-update is the design"; nesting the
        # decay inside the loop made a batch spanning 3 hours apply 0.99^3.
        # Decay FIRST, then add: the batch's own hours must not be taxed on
        # arrival (add-then-decay would shrink fresh counts by 1% every batch,
        # systematically understating activity).
        if _batch_hours:
            for h in profile.hour_histogram:
                profile.hour_histogram[h] *= 0.99
            for hour, n in _batch_hours.items():
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


def absolute_hour_counts(entries: list[dict]) -> "dict[str, int]":
    """N4 (round 4): events per ABSOLUTE hour ("YYYY-MM-DDTH") of event time.

    Hour-of-DAY buckets (0-23) merge days — a 3-day batch reads the same
    24 buckets as a 1-day batch with 3x the counts, so the derived rate
    tracked batch size, not behavior. Absolute hours make one EWMA
    observation equal one COMPLETE hour regardless of how batches split
    it.
    """
    from nabla.utils import parse_iso_timestamp

    buckets: dict[str, int] = {}
    for e in entries:
        dt = parse_iso_timestamp(str(e.get("timestamp", "")))
        if dt is not None:
            key = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H")
            buckets[key] = buckets.get(key, 0) + 1
    return buckets


def observation_rate(entries: list[dict]) -> float:
    """The per-hour rate observation for a batch, hour-bucketed (R4).

    Mean events per active hour (hours with >= 1 event). Robust to batch
    boundaries: a 5-minute scheduler slice of a 6/hr user reads ~6, not
    120. Single-event batches read as 1/hr (the conservative direction —
    understates, never overstates).

    N4 (round 4): this function remains for DETECTION-side reads of a
    batch's current-hour rate and for legacy callers; ABSorption uses
    absorb_absolute_hours (complete-hour observations via the profile's
    accumulator), which is what makes baselines cadence-independent.
    """
    buckets = hourly_counts(entries)
    if not buckets:
        return 0.0
    return sum(buckets.values()) / len(buckets)


def _registry_window_days() -> float:
    """R-7/R-9 (round 7): the observed-hours registry window —
    max(TP-hold days, baseline_min_days). Sized so a TP hold released at
    its 14-day edge still finds the hours it held, and so baseline
    minimum-days reads see their own history."""
    from nabla.config import get_settings
    s = get_settings()
    tp = float(getattr(s, "quarantine_tp_hold_days", 14.0) or 14.0)
    min_days = float(getattr(s, "baseline_min_days", 21) or 21)
    return max(tp, min_days)


def _lookup_source_watermark(source_kind: str) -> str:
    """The persisted watermark for this source ("" if none). The
    orchestration passes its in-memory advanced value instead; this
    read serves callers outside the pipeline (drains, tests)."""
    from nabla.config import get_settings
    from nabla.system_state import load_system_state
    state = load_system_state(get_settings().system_state_file)
    wms = state.get("source_watermarks") or {}
    return str(wms.get(source_kind) or "")


def sweep_profile_hours(store: "EntityProfileStore", sys_state: dict) -> int:
    """R-16/R-17 (round 7): end-of-run close sweep. Every profile's open
    hours close against their OWN source's watermark — a quiet entity
    (no events this run) still gets its finished hours observed, so
    baselines don't stall while the entity is away. Hours closed by the
    sweep are recorded in the registry exactly like live closes (never
    treated as late). Runs BEFORE the profile store save (R-17: the
    watermark persists after — a crash leaves profile-behind-watermark,
    which the idempotent close absorbs on replay).

    Returns the number of observations made."""
    from nabla.pipeline.watermark import close_open
    from nabla.system_state import source_watermarks_view
    watermarks = source_watermarks_view(sys_state)
    window = _registry_window_days()
    total = 0
    for profile in store.users.values():
        ev_state = {"open": profile.open_hours,
                    "observed": profile.observed_hours}
        net_state = {"open": profile.net_open_hours,
                     "observed": profile.net_observed_hours}
        obs_ev = close_open(ev_state, watermarks, window)
        for _key, _count in obs_ev:
            profile.typical_event_count.update(float(_count))
        obs_net = close_open(net_state, watermarks, window)
        for _key, _count in obs_net:
            profile.network_event_rate.update(float(_count))
        total += len(obs_ev) + len(obs_net)
    return total


def hourly_rates(entries: list[dict], profile) -> dict[str, float]:
    """S4 (round 5): per-absolute-hour rates for THIS batch, each composed
    with the profile's open-hour accumulator where it applies. Every hour
    in the batch is scored — a multi-hour upload's 03:00 burst is no
    longer invisible because 23:00 happens to be newest. Callers take
    the PEAK hour and compare it against the family-adjusted threshold.
    """
    buckets = absolute_hour_counts(entries)
    if not buckets:
        return {}
    # N-2 (round 7): the open state is per (source, hour) — compose the
    # batch with this hour's open counts summed across sources.
    open_by_hour: dict[str, int] = {}
    for key, entry in (getattr(profile, "open_hours", None) or {}).items():
        _src, _, hour = key.partition("|")
        open_by_hour[hour] = open_by_hour.get(hour, 0) + int(entry.get("count", 0))
    return {
        hour: float(n + open_by_hour.get(hour, 0))
        for hour, n in buckets.items()
    }


def family_z_threshold(base_z: float, hours: int) -> float:
    """S4 (round 5): Bonferroni family-wise threshold for scoring H hours
    instead of one. Single-hour batches are untouched (the gate-7 demo's
    z=2.021-vs-2.0 arc depends on hours<=1 returning base_z verbatim —
    verified: the attack file spans exactly one hour).

    2.0σ over 24 hours → 3.106σ (NormalDist().inv_cdf(1-(1-cdf(2.0))/24));
    test expectations derive from this function, never from prose.
    """
    if hours <= 1:
        return base_z
    from statistics import NormalDist
    p = 1 - NormalDist().cdf(base_z)
    return NormalDist().inv_cdf(1 - p / hours)


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
# N5 (round 4, Decision 1 — Ryan): the TP hold is time-boxed, 14 data-clock
# days. Discard pending (already done), then auto-release: a remediated
# account resumes learning.
_TP_HOLD_DAYS = 14.0


def _quarantine_file() -> "Path":
    from nabla.config import get_settings
    return Path(get_settings().data_dir) / "baseline_quarantine.json"


def _load_quarantine() -> dict:
    p = _quarantine_file()
    if p.exists():
        import json as _json
        return _json.loads(p.read_text() or "{}")
    return {}


def _save_quarantine(q: dict) -> None:
    """N15 (round 4): UNLOCKED inner writer — callers hold file_lock
    across the whole read-modify-write cycle. Locking only the write is
    how a disposition racing a pipeline run lost updates."""
    from nabla.persistence import atomic_write_json
    p = str(_quarantine_file())
    atomic_write_json(p, q)


def flag_quarantine(entity_ids: list[str], data_clock: "datetime|None" = None) -> None:
    """Detection fired for these entities: hold their batches from baseline
    absorption until dispositioned (or TTL). Called by the pipeline post-
    detection with the entities that produced anomalies."""
    from datetime import datetime, timezone
    from nabla.persistence import file_lock
    with file_lock(str(_quarantine_file())):
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
    from nabla.persistence import file_lock
    with file_lock(str(_quarantine_file())):
        q = _load_quarantine()
        ent = q.get(entity_id)
        if ent:
            ent["held"] = False
            ent["indefinite"] = False
            ent["released_at"] = (data_clock or datetime.now(timezone.utc)).isoformat()
            _save_quarantine(q)


def hold_quarantine(entity_id: str) -> None:
    """true_positive disposition: confirmed attack — hold, time-boxed.

    N5 (round 4, Decision 1): 14 data-clock days, not indefinite. A
    remediated account must resume learning; the indefinite freeze was
    the R6 half this closes. The hold's `since` anchors at the data
    clock so replayed data expires it honestly."""
    from nabla.persistence import file_lock
    with file_lock(str(_quarantine_file())):
        q = _load_quarantine()
        ent = q.get(entity_id) or {}
        ent["held"] = True
        ent["indefinite"] = False  # N5: time-boxed, never forever
        ent["since"] = _data_clock_now().isoformat()  # re-anchor the 14d window
        ent["tp_hold_days"] = _TP_HOLD_DAYS
        q[entity_id] = ent
        _save_quarantine(q)


_PENDING_CAP = 5  # legacy batch-count cap — superseded by N3's span/count cap
_PENDING_SPAN_DAYS = 7.0  # N3: cap by data-clock span (the hold can last 7 days)
_PENDING_EVENT_CAP = 5000  # N3: per-entity event cap (memory bound)


def _pending_file() -> "Path":
    from nabla.config import get_settings
    return Path(get_settings().data_dir) / "baseline_pending.json"


def _load_pending() -> dict:
    p = _pending_file()
    if p.exists():
        import json as _json
        return _json.loads(p.read_text() or "{}")
    return {}


def _save_pending(pend: dict) -> None:
    """N15 (round 4): UNLOCKED inner writer — callers hold file_lock."""
    from nabla.persistence import atomic_write_json
    p = str(_pending_file())
    atomic_write_json(p, pend)


def _pending_entries_stamps(entries: list[dict]) -> str:
    return max((e.get("timestamp", "") for e in entries), default="")


def _batch_entries(batch) -> list[dict]:
    """Held-batch payload. R-4 (round 7): holds wrap each batch as
    {"batch_uid", "entries"}; legacy files (pre-round-7) and older
    fixtures carry bare entry lists. Both shapes drain identically."""
    if isinstance(batch, dict):
        return list(batch.get("entries") or [])
    return list(batch)


def _batch_uid(entity_id: str, batch) -> str:
    """Stable per-batch identity (R-4). Wrapped batches carry the uid
    assigned at HOLD time; legacy bare batches get a deterministic
    content-derived uid so a crash replay computes the same id."""
    if isinstance(batch, dict):
        uid = str(batch.get("batch_uid") or "")
        if uid:
            return uid
        batch = batch.get("entries") or []
    import hashlib
    entries = sorted(
        (str(e.get("event_id", "")), str(e.get("timestamp", "")))
        for e in batch
    )
    material = entity_id + "|" + str(entries)
    return "legacy:" + hashlib.sha256(material.encode()).hexdigest()[:16]


def _batch_source(batch) -> str:
    """N-2 (round 7): the held batch's pipeline source. Wrapped batches
    carry it; legacy wrappers and bare lists default to "file" (the
    pre-round-7 hold path only saw file batches)."""
    if isinstance(batch, dict):
        return str(batch.get("source_kind") or "file")
    return "file"


def hold_pending(entity_id: str, entries: list[dict],
                 *, source_kind: str | None = None) -> None:
    """Hold a quarantined entity's batch for later application (R6).

    N3 (round 4): capped by data-clock span (7 days — the hold's own TTL)
    and per-entity event count (5,000), NOT by batch count. The old
    5-batch cap was 25 minutes at the 5-minute schedule while the hold
    lasted 7 days: most held data would have been dropped by the cap even
    if the disposition path had worked. Batches older than the span cap
    drop at write time; the newest events win on the count cap.
    """
    from nabla.utils import parse_iso_timestamp
    from nabla.persistence import file_lock
    with file_lock(str(_pending_file())):
        pend = _load_pending()
        batches = pend.setdefault(entity_id, [])
        # R-4: identity assigned at HOLD time, per batch
        from uuid import uuid4
        batches.append({"batch_uid": uuid4().hex[:16],
                        "source_kind": source_kind or "file",
                        "entries": entries})
        # span cap: drop whole batches older than the cutoff
        from datetime import timedelta as _td
        now_dc = _data_clock_now()
        cutoff = now_dc - _td(days=_PENDING_SPAN_DAYS)
        kept = []
        for b in batches:
            newest = parse_iso_timestamp(
                _pending_entries_stamps(_batch_entries(b)) or "")
            if newest is not None and newest < cutoff:
                continue  # older than the span cap — drop
            kept.append(b)
        # count cap: newest events win
        total = sum(len(_batch_entries(b)) for b in kept)
        while total > _PENDING_EVENT_CAP and kept:
            drop = kept.pop(0)
            total -= len(drop)
        pend[entity_id] = kept
        _save_pending(pend)


def approve_pending(entity_id: str) -> int:
    """FP/BTP disposition: move the entity's held batches to the approved
    list. The NEXT pipeline run drains them into the profile inside its
    own load-save window (N3: the API path never writes profiles — it
    raced the pipeline's load-save and lost). Returns batches approved."""
    from nabla.persistence import file_lock
    # lock order: approved then pending (drain_released takes pending-
    # then-quarantine; no cycle anywhere)
    with file_lock(str(_approved_file())), file_lock(str(_pending_file())):
        pend = _load_pending()
        batches = pend.pop(entity_id, [])
        if batches:
            apr = _load_approved()
            apr.setdefault(entity_id, []).extend(batches)
            _save_approved(apr)
        _save_pending(pend)
        return len(batches)


def _approved_file() -> "Path":
    from nabla.config import get_settings
    return Path(get_settings().data_dir) / "baseline_approved.json"


def _load_approved() -> dict:
    p = _approved_file()
    if p.exists():
        import json as _json
        return _json.loads(p.read_text() or "{}")
    return {}


def _save_approved(apr: dict) -> None:
    """N15 (round 4): UNLOCKED inner writer — callers hold file_lock."""
    from nabla.persistence import atomic_write_json
    p = str(_approved_file())
    atomic_write_json(p, apr)


def drain_approved_pending(store: "EntityProfileStore") -> dict[str, list[str]]:
    """Pipeline START: apply every approved entity's held batches through
    the normal update_user, inside the caller's load-save window (N3 +
    STRONG 2: ALL approved entities drain — an entity that goes quiet
    after its FP disposition must not silently lose its verdict).

    CLOCK-SPEC Rule 6 / T-1 (round 6): held batches are schedule
    FRAGMENTS (5 minutes on the live schedule), not hours — observing
    each as an hour undercounted ~12x. Batches merge per entity-hour
    before absorption.

    R-3/R-4 (round 7): this drain rewrites NOTHING. It applies through
    update_user, records the applied per-batch IDs on the profile
    (drained_batch_ids, assigned at HOLD time — a whole-set fingerprint
    breaks when a new approval arrives between crash and restart), and
    returns what it processed. The caller's post-save commit
    (commit_drain_after_save) removes exactly those batches from
    approved.json — R-11: a verdict arriving mid-run survives, and a
    crash between save and commit replays as a no-op.

    Returns {entity_id: [batch uids processed]}."""
    from nabla.persistence import file_lock
    with file_lock(str(_approved_file())):
        apr = _load_approved()
        if not apr:
            return {}
        processed: dict[str, list[str]] = {}
        from collections import defaultdict as _dd
        from nabla.pipeline.clock_ingestion import event_hour_key as _ehk
        for entity_id, batches in apr.items():
            profile = store.get_or_create_user(entity_id)
            drained = set(getattr(profile, "drained_batch_ids", None) or [])
            # R-4: filter applied batches FIRST — the by-hour merge must
            # not mix crash-replayed batches into hours the registry
            # already observed (a closed hour would swallow the
            # not-yet-applied fragments merged into it)
            todo = [b for b in batches if _batch_uid(entity_id, b) not in drained]
            new_uids = [_batch_uid(entity_id, b) for b in todo]
            if todo:
                # T-1: merge ALL fragments per (source, hour) — R-15
                # keys state per source; the engine's registry check
                # skips hours already observed (data absorbed live
                # before the hold)
                by_key: dict[tuple[str, str], list[dict]] = _dd(list)
                for b in todo:
                    src = _batch_source(b)
                    for e in _batch_entries(b):
                        h = _ehk(e)
                        if h:
                            by_key[(src, h)].append(e)
                for (src, h) in sorted(by_key):
                    # S6 + T-1: bypass the hold (analyst verdict),
                    # full hour; drain mode observes each hour
                    # immediately, registry-checked
                    store.update_user(entity_id, by_key[(src, h)],
                                      bypass_quarantine=True,
                                      source_kind=src)
                profile.drained_batch_ids = sorted(
                    drained | set(new_uids))[-200:]
            # the commit removes everything already applied — including
            # batches applied in a PREVIOUS crashed run (replay: todo is
            # empty, the uids are in drained, but they still sit in
            # approved.json until a commit removes them)
            drained_after = drained | set(new_uids)
            to_remove = [u for u in (_batch_uid(entity_id, b) for b in batches)
                         if u in drained_after]
            if to_remove:
                processed[entity_id] = to_remove
        return processed


def commit_drain_after_save(applied_approved: "dict[str, list[str]] | None" = None,
                            released: "dict[str, list[str]] | None" = None,
                            hold_tokens: "dict[str, str] | None" = None) -> None:
    """R6-16 + R-11 + R-3 (round 7): the post-save commit for the
    quarantine drains. The caller runs this AFTER the profile store
    persisted — the profile save is what makes the per-batch drained IDs
    durable, so a crash before this point replays as a no-op instead of
    losing the verdict.

    SELECTIVE (R-11): removes only the batches the drains processed. An
    analyst verdict arriving mid-run (between drain and commit) is not
    in the map and survives for the next run. The old whole-file clear
    wiped it.

    Quarantine holds (TTL releases) flip to released only if the hold
    was not re-armed mid-run — the since-token guards a same-run
    re-flag from detection."""
    from nabla.persistence import file_lock
    if applied_approved:
        with file_lock(str(_approved_file())):
            apr = _load_approved()
            for eid, uids in applied_approved.items():
                uid_set = set(uids)
                remaining = [b for b in apr.get(eid, [])
                              if _batch_uid(eid, b) not in uid_set]
                if remaining:
                    apr[eid] = remaining
                else:
                    apr.pop(eid, None)
            _save_approved(apr)
    if released:
        with file_lock(str(_pending_file())), file_lock(str(_quarantine_file())):
            pend = _load_pending()
            q = _load_quarantine()
            for eid, uids in released.items():
                uid_set = set(uids)
                remaining = [b for b in pend.get(eid, [])
                              if _batch_uid(eid, b) not in uid_set]
                if remaining:
                    pend[eid] = remaining
                else:
                    pend.pop(eid, None)
                ent = q.get(eid)
                if ent and ent.get("held"):
                    # flip only the hold the drain drained — a mid-run
                    # re-arm (new since) must survive
                    if not hold_tokens or ent.get("since") == hold_tokens.get(eid):
                        ent["held"] = False
                        ent["released_at"] = _data_clock_now().isoformat()
                        ent["released_by"] = "ttl_apply"
            _save_pending(pend)
            _save_quarantine(q)


def drain_released_pending(
        store: "EntityProfileStore") -> "tuple[dict[str, list[str]], dict[str, str]]":
    """TTL-release drain (final-review REQUIRED 1): a no-disposition TTL
    expiry means 'review window elapsed, treat as normal' — held batches
    APPLY (the self-healing choice; the accepted cost is that the 7-day
    TTL is the maximum attack-absorption lag for undispositioned
    hold-list findings). Entities whose hold has expired route here.

    R-3 (round 7): this drain rewrites NOTHING. The old body popped
    pending.json and saved it (and flipped the quarantine flags) BEFORE
    the profile store persisted — a crash in between lost the held data
    for good. It now applies through update_user, records per-batch IDs
    on the profile (R-4), and returns what it released; the caller's
    post-save commit (commit_drain_after_save) removes those batches
    and flips the holds.

    Returns ({entity_id: [batch uids processed]},
             {entity_id: quarantine since-token at drain time})."""
    from nabla.persistence import file_lock
    # lock order: pending then quarantine (alphabetical file names —
    # approve_pending takes approved-then-pending; no cycle)
    with file_lock(str(_pending_file())), file_lock(str(_quarantine_file())):
        q = _load_quarantine()
        pend = _load_pending()
        processed: dict[str, list[str]] = {}
        hold_tokens: dict[str, str] = {}
        from collections import defaultdict as _dd
        from nabla.pipeline.clock_ingestion import event_hour_key as _ehk
        for entity_id, ent in list(q.items()):
            if not ent.get("held"):
                continue
            if ent.get("tp_hold_days"):
                continue  # TP holds discard, never apply
            if _is_quarantined(entity_id):
                continue  # still inside the TTL window
            batches = pend.get(entity_id, [])
            profile = store.get_or_create_user(entity_id)
            drained = set(getattr(profile, "drained_batch_ids", None) or [])
            todo = [b for b in batches
                    if _batch_uid(entity_id, b) not in drained]
            new_uids = [_batch_uid(entity_id, b) for b in todo]
            if todo:
                by_key: dict[tuple[str, str], list[dict]] = _dd(list)
                for b in todo:
                    src = _batch_source(b)
                    for e in _batch_entries(b):
                        h = _ehk(e)
                        if h:
                            by_key[(src, h)].append(e)
                for (src, h) in sorted(by_key):
                    store.update_user(entity_id, by_key[(src, h)],
                                      bypass_quarantine=True,
                                      source_kind=src)
                profile.drained_batch_ids = sorted(
                    drained | set(new_uids))[-200:]
            # the commit removes everything already applied — including
            # batches applied in a PREVIOUS crashed run (replay: todo is
            # empty, the uids are in drained, but they still sit in
            # pending.json until a commit removes them)
            drained_after = drained | set(new_uids)
            to_remove = [u for u in (_batch_uid(entity_id, b) for b in batches)
                         if u in drained_after]
            if to_remove:
                processed[entity_id] = to_remove
            hold_tokens[entity_id] = str(ent.get("since", ""))
        return processed, hold_tokens


def apply_pending(entity_id: str, store: "EntityProfileStore") -> int:
    """FP/BTP disposition: the held data was NORMAL — apply it to the
    baseline. Returns batches applied. Bucket semantics (review STRONG 2):
    the pending entries merge into the hours they span via the same
    observation_rate path update_user uses (single merged application;
    no double-count — each held batch applies exactly once).
    """
    from nabla.persistence import file_lock
    with file_lock(str(_pending_file())):
        pend = _load_pending()
        batches = pend.pop(entity_id, [])
        _save_pending(pend)
    for b in batches:
        store.update_user(entity_id, _batch_entries(b),
                          bypass_quarantine=True,
                          source_kind=_batch_source(b))
    return len(batches)


def discard_pending(entity_id: str) -> int:
    """TP disposition: confirmed attack — the held data never enters."""
    from nabla.persistence import file_lock
    with file_lock(str(_pending_file())):
        pend = _load_pending()
        n = len(pend.pop(entity_id, []))
        _save_pending(pend)
        return n


def apply_disposition_to_quarantine(entity_id: str, disposition: str,
                                     profile_store: "EntityProfileStore | None" = None) -> None:
    """The four-row truth table (plan stage 2, review REQUIRED 1), with the
    N3 (round 4) semantics: FP/BTP release the hold AND approve the held
    batches — the NEXT pipeline run applies them inside its own load-save
    window (the API path never writes profiles; it raced the pipeline and
    lost, which is how held data died). TP holds (time-boxed, 14 days) AND
    discards pending (attack never enters); no-disposition rides the TTL,
    which APPLIES on expiry (the self-healing choice).
    profile_store is accepted for signature compatibility and ignored."""
    if disposition in ("false_positive", "benign_true_positive"):
        release_quarantine(entity_id)
        approve_pending(entity_id)
    elif disposition == "true_positive":
        hold_quarantine(entity_id)
        discard_pending(entity_id)
    # no-disposition row: the TTL in _is_quarantined + drain_released_pending


def _data_clock_now() -> "datetime":
    """The A7 data clock (newest ingested event), wall fallback."""
    from datetime import datetime, timezone
    try:
        import json as _json
        from nabla.config import get_settings
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
    from nabla.utils import parse_iso_timestamp
    q = _load_quarantine()
    ent = q.get(entity_id)
    if not ent or not ent.get("held"):
        return False
    # N5: `indefinite` is retired — legacy records carrying it read as the
    # TP hold (time-boxed from their original since stamp).
    since = parse_iso_timestamp(ent.get("since", ""))
    if since is None:
        return False
    ttl = _TP_HOLD_DAYS if ent.get("tp_hold_days") else _QUARANTINE_TTL_DAYS
    age_days = (_data_clock_now() - since).total_seconds() / 86400.0
    return age_days < ttl


def quarantine_summary(entity_id: str) -> dict | None:
    """Public read for the entities API (Phase 2 UI): the entity's
    quarantine state as the UI shows it — held or not, the data-clock
    TTL window, and the held-event count from the pending store.

    Single source of truth: the TTL window is computed by the same
    logic _is_quarantined uses (TP holds 14 data-clock days, no-
    disposition holds 7), never re-derived in the API layer.

    N-1 (round 8): this function once carried its own copy of the
    summary logic — and a loop-variable typo (`eid`) the plural never
    had, which 500'd the detail endpoint for every quarantined entity.
    One implementation now: the singular delegates to the plural."""
    return quarantine_summaries([entity_id]).get(entity_id)


def quarantine_summaries(entity_ids: list[str]) -> dict[str, dict | None]:
    """Bulk read for list endpoints — one quarantine + one pending load
    for the whole page, not two file reads per entity row."""
    from nabla.utils import parse_iso_timestamp
    q = _load_quarantine()
    try:
        pend = _load_pending()
    except Exception:
        pend = {}

    out: dict[str, dict | None] = {}
    for eid in entity_ids:
        ent = q.get(eid)
        if not ent:
            out[eid] = None
            continue
        held = _is_quarantined(eid)
        since = parse_iso_timestamp(ent.get("since", ""))
        ttl = _TP_HOLD_DAYS if ent.get("tp_hold_days") else _QUARANTINE_TTL_DAYS
        days_left = None
        if held and since is not None:
            age_days = (_data_clock_now() - since).total_seconds() / 86400.0
            days_left = max(0, round(ttl - age_days))
        held_events = sum(len(_batch_entries(b)) for b in pend.get(eid, []))
        out[eid] = {
            "held": held,
            "since": ent.get("since"),
            "days_left": days_left,
            "tp_hold": bool(ent.get("tp_hold_days")),
            "batches_held": ent.get("batches_held", 0),
            "held_batches": len(pend.get(eid, [])),
            "held_events": held_events,
            "released_at": ent.get("released_at"),
        }
    return out
