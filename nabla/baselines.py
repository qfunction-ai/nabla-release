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
        alpha: Smoothing factor (0-1). Higher = faster adaptation.
            0.3 adapts within ~5 observations; 0.1 within ~15.
    """

    value: float = 0.0
    variance: float = 0.0
    alpha: float = 0.3

    def update(self, observation: float) -> None:
        """Update the EWMA with a new observation.

        Args:
            observation: New value to incorporate into the running average.
        """
        diff = observation - self.value
        self.value = self.alpha * observation + (1 - self.alpha) * self.value
        self.variance = self.alpha * diff ** 2 + (1 - self.alpha) * self.variance

    @property
    def std(self) -> float:
        """Current standard deviation estimate."""
        return self.variance ** 0.5 if self.variance > 0 else 0.01

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
        return {"value": self.value, "variance": self.variance, "alpha": self.alpha}

    @classmethod
    def from_dict(cls, data: dict) -> EWMAProfile:
        """Deserialize from a dict.

        Args:
            data: Dict with value, variance, and optionally alpha keys.

        Returns:
            EWMAProfile instance.
        """
        return cls(
            value=data.get("value", 0.0),
            variance=data.get("variance", 0.0),
            alpha=data.get("alpha", 0.3),
        )


# ---------------------------------------------------------------------------
# Entity profiles
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return current UTC time as ISO format string."""
    return datetime.now(timezone.utc).isoformat()


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
    _EWMA_FIELDS: set[str] = set()

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict using field introspection."""
        result = {}
        for f in fields(self):
            val = getattr(self, f.name)
            if f.name in self._SET_FIELDS:
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
            if f.name in cls._SET_FIELDS:
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

    _SET_FIELDS = {"typical_ips", "typical_hours"}
    _EWMA_FIELDS = {"typical_event_count", "auth_failure_ratio", "off_hours_ratio"}

    entity_id: str = ""
    first_seen: str = ""
    last_seen: str = ""
    observation_count: int = 0
    account_created_at: str = ""
    typical_event_count: EWMAProfile = field(default_factory=EWMAProfile)
    typical_ips: set[str] = field(default_factory=set)
    typical_hours: set[int] = field(default_factory=set)
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
        """Save all profiles to the JSON file atomically.

        Uses atomic_write_json to prevent partial writes.
        """
        data = {
            "users": {k: v.to_dict() for k, v in self.users.items()},
            "hosts": {k: v.to_dict() for k, v in self.hosts.items()},
            "ips": {k: v.to_dict() for k, v in self.ips.items()},
        }
        try:
            atomic_write_json(self.path, data)
            logger.info(
                "Saved entity profiles: %d users, %d hosts, %d IPs",
                len(self.users), len(self.hosts), len(self.ips),
            )
        except OSError as e:
            logger.warning("Failed to save entity profiles to %s: %s", self.path, e)

    # --- Getters ---

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
        profile.observation_count += 1

        # Event count EWMA
        profile.typical_event_count.update(len(entries))

        # IPs (only publicly routable — private IPs are not useful for
        # impossible-travel detection and would cause false positives)
        for e in entries:
            ip = e.get("source_ip", e.get("src_ip", e.get("client_ip", "")))
            if ip and is_routable_ip(ip):
                profile.typical_ips.add(ip)
        _capped_set(profile.typical_ips, _MAX_IPS)

        # Hours
        for e in entries:
            ts = e.get("timestamp", "")
            if ts:
                try:
                    hour = int(ts[11:13])
                    profile.typical_hours.add(hour)
                except (ValueError, IndexError):
                    pass  # silent by design: unparseable timestamp in profile data (2026-09 sweep)

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
            if e.get("timestamp", "")[11:13]
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
        profile.typical_process_count.update(len(current_processes))

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

        # Event count EWMA
        profile.typical_event_count.update(len(entries))

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
