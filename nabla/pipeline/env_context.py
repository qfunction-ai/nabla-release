"""Environment context — loading, auto-detection, and formatting for pipeline blocks."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from nabla.log import get_logger

if TYPE_CHECKING:
    from nabla.baselines import EntityProfileStore

logger = get_logger("pipeline")


def _load_environment_context(path: str) -> dict:
    """Load environment context from JSON file.

    The file contains environment facts, per-entity facts, network ranges,
    new/service/admin accounts, and benign patterns that help reduce false
    positives. If the file doesn't exist, returns an empty dict (all features
    degrade gracefully).

    Args:
        path: Path to the environment_context.json file.

    Returns:
        Dict with keys: environment, entities, network_ranges, new_accounts,
        service_accounts, admin_accounts, benign_patterns. Each may be empty.
    """
    import json as _json

    result = {
        "environment": [],
        "entities": {},
        "network_ranges": [],
        "new_accounts": set(),
        "service_accounts": set(),
        "admin_accounts": set(),
        "benign_patterns": [],
    }

    if not os.path.exists(path):
        logger.debug("No environment context file at %s (using defaults)", path)
        return result

    try:
        with open(path, "r") as f:
            data = _json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load environment context: %s", e)
        return result

    result["environment"] = data.get("environment", [])
    result["entities"] = data.get("entities", {})
    result["network_ranges"] = data.get("network_ranges", [])
    result["new_accounts"] = set(data.get("new_accounts", []))
    result["service_accounts"] = set(data.get("service_accounts", []))
    result["admin_accounts"] = set(data.get("admin_accounts", []))
    result["benign_patterns"] = data.get("benign_patterns", [])

    return result


def _auto_detect_network_ranges(entries: list[dict]) -> list[str]:
    """Auto-detect private network ranges from log entries.

    Scans all source IPs and groups private IPs into their class-C
    subnets (e.g., 10.0.1.0/24, 172.31.94.0/24). This gives the
    supervisor environmental context about the network topology.

    Args:
        entries: List of log entry dicts.

    Returns:
        List of CIDR strings for detected private network ranges.
    """
    import ipaddress as _ip

    private_subnets = set()
    for e in entries:
        ip = e.get("source_ip", e.get("src_ip", e.get("client_ip", "")))
        if not ip:
            continue
        try:
            addr = _ip.ip_address(ip)
        except ValueError:
            pass  # silent by design: unparseable timestamp in env detection (2026-09 sweep)
        if addr.is_private:
            # Group into /24 subnet
            if addr.version == 4:
                net = _ip.ip_network(f"{addr}/24", strict=False)
                private_subnets.add(str(net))
            elif addr.version == 6:
                # Group into /64 for IPv6
                net = _ip.ip_network(f"{addr}/64", strict=False)
                private_subnets.add(str(net))

    return sorted(private_subnets)


def _auto_detect_new_accounts(
    entries: list[dict],
    entity_profiles: EntityProfileStore | None = None,
    grace_days: int = 30,
) -> dict[str, str]:
    """Auto-detect newly created accounts from log entries.

    Scans entries for AD Event ID 4720 (account_created action) and
    cross-references entity profiles for accounts with known creation
    dates. Returns a dict of {username: creation_timestamp} for accounts
    created within the grace period.

    Args:
        entries: List of log entry dicts from the current run.
        entity_profiles: Entity baseline profiles. If provided, also
            checks UserProfile.account_created_at for accounts detected
            in previous runs.
        grace_days: Number of days after creation to consider an account
            "new". Defaults to 30.

    Returns:
        Dict mapping username → ISO timestamp of account creation.
    """
    from datetime import datetime as _dt, timedelta, timezone as _tz

    created_accounts: dict[str, str] = {}

    # Detect from current entries
    for e in entries:
        if e.get("action") == "account_created" or e.get("event_code") == "4720":
            user = e.get("user", "")
            if not user:
                continue
            ts = e.get("timestamp", "")
            if ts:
                created_accounts[user] = ts

    # Also check entity profiles for accounts detected in previous runs
    if entity_profiles is not None:
        for user_id, profile in entity_profiles.users.items():
            if profile.account_created_at and user_id not in created_accounts:
                created_accounts[user_id] = profile.account_created_at

    # Filter to accounts within grace period
    now = _dt.now(_tz.utc)
    grace_cutoff = now - timedelta(days=grace_days)
    recent: dict[str, str] = {}
    for user, ts_str in created_accounts.items():
        try:
            ts = _dt.fromisoformat(ts_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=_tz.utc)
            if ts >= grace_cutoff:
                recent[user] = ts_str
        except (ValueError, TypeError):
            # If we can't parse the timestamp, include it anyway
            recent[user] = ts_str

    return recent


def _entity_baseline_lines(
    entity_id: str, profile, run_stats: dict[str, dict] | None, risk_store: Any = None
) -> list[str]:
    """Build the baseline-summary lines for one anomalous entity (UI2b).

    Typical vs this-run side by side, peer positioning, risk trend.
    Cold entities get a one-liner.
    """
    lines = [f"  {entity_id}:"]
    if profile is None or getattr(profile, "observation_count", 0) < 3:
        obs = getattr(profile, "observation_count", 0) if profile else 0
        lines.append(f"    * no baseline yet — {obs}/3 observations")
        return lines

    # Typical behavior from the profile
    typical = []
    th = getattr(profile, "typical_hours", None)
    if th:
        hours = sorted(int(h) for h in th if str(h).isdigit())
        if hours:
            typical.append(
                f"typical hours {hours[0]:02d}:00-{hours[-1]:02d}:00"
            )
    tips = getattr(profile, "typical_ips", None)
    if tips:
        sample = ", ".join(list(tips)[:3])
        more = f" (+{len(tips)-3} more)" if len(tips) > 3 else ""
        typical.append(f"{len(tips)} typical addresses ({sample}{more})")
    tec = getattr(profile, "typical_event_count", None)
    if tec is not None and getattr(tec, "value", 0) > 0:
        typical.append(f"~{tec.value:.0f} events/run typical")
    if typical:
        lines.append(f"    * baseline: {'; '.join(typical)}")
    else:
        lines.append("    * baseline: warm profile (limited detail)")

    # This-run stats when available
    rs = (run_stats or {}).get(entity_id)
    if rs:
        parts = [f"{rs.get('events', '?')} events this run"]
        if rs.get("new_ips"):
            parts.append(f"{rs['new_ips']} new addresses")
        if rs.get("off_hours"):
            parts.append(f"{rs.get('off_hours', 0)} off-hours events")
        lines.append(f"    * this run: {', '.join(parts)}")

    # Risk + trend
    if risk_store is not None:
        try:
            risk = risk_store.scores.get(entity_id)
            if risk is not None:
                from nabla.risk import get_trend_label
                lines.append(
                    f"    * risk {risk.overall:.0f} ({get_trend_label(risk.trend)})"
                )
        except Exception as e:
            logger.warning("env context load failed (non-fatal): %s", e, exc_info=True)
    return lines


def _format_env_context_block(
    env_context: dict,
    auto_ranges: list[str],
    auto_new_accounts: dict[str, str] | None = None,
    anomalous_entities: set[str] | None = None,
    entity_profiles: Any = None,
    run_stats: dict[str, dict] | None = None,
    risk_store: Any = None,
) -> str:
    """Format environment context into a human-readable block for the supervisor.

    The block has four sections:
    1. Environment Facts — user-declared structural facts (never overwritten)
    2. Entity Context — per-entity facts for anomalous entities only
    3. Entity Baselines — typical vs this-run behavior for anomalous entities (UI2b)
    4. Mutable State — auto-detected ranges, new accounts with dates, account lists

    Args:
        env_context: Loaded environment context dict.
        auto_ranges: Auto-detected network ranges from log entries.
        auto_new_accounts: Auto-detected new accounts {username: creation_ts}.
        anomalous_entities: Set of entity names that appear in anomalies.
            Only entity facts for these entities are included.
        entity_profiles: EntityProfileStore — supplies per-entity baselines.
        run_stats: Per-entity this-run counts {entity: {events, new_ips, off_hours}}.
        risk_store: EntityRiskStore — supplies risk + trend summaries.

    Returns:
        Formatted text block for the environment_context shared block.
    """
    import json as _json
    from typing import Any as _Any  # noqa: F401

    if auto_new_accounts is None:
        auto_new_accounts = {}
    if anomalous_entities is None:
        anomalous_entities = set()

    lines = ["=== ENVIRONMENT CONTEXT ==="]

    # --- Section 1: Environment Facts (user-declared) ---
    env_facts = env_context.get("environment", [])
    if env_facts:
        lines.append("")
        lines.append("--- Environment Facts (user-declared, do not modify) ---")
        for fact in env_facts:
            lines.append(f"  * {fact}")

    # --- Section 2: Entity Context (anomalous entities only) ---
    entity_facts = env_context.get("entities", {})
    if entity_facts and anomalous_entities:
        relevant_entities = {
            k: v for k, v in entity_facts.items()
            if k in anomalous_entities
        }
        if relevant_entities:
            lines.append("")
            lines.append("--- Entity Context (anomalous entities this run) ---")
            for entity_name in sorted(relevant_entities):
                facts = relevant_entities[entity_name]
                lines.append(f"  {entity_name}:")
                for fact in facts:
                    lines.append(f"    * {fact}")

    # --- Section 3: Entity Baselines (anomalous entities, UI2b) ---
    if anomalous_entities and entity_profiles is not None:
        baseline_lines: list[str] = []
        for ent in sorted(anomalous_entities)[:12]:  # hard cap: 12 entities
            profile = None
            for store_dict in (
                getattr(entity_profiles, "users", {}),
                getattr(entity_profiles, "hosts", {}),
                getattr(entity_profiles, "ips", {}),
            ):
                if ent in store_dict:
                    profile = store_dict[ent]
                    break
            baseline_lines.extend(
                _entity_baseline_lines(ent, profile, run_stats, risk_store)
            )
        if baseline_lines:
            lines.append("")
            lines.append(
                "--- Entity Baselines (what these entities NORMALLY do — "
                "findings deviating from baseline deserve more weight) ---"
            )
            lines.extend(baseline_lines[:30])  # hard cap: 30 lines

    # --- Section 4: Mutable State (auto-detected + user-declared) ---
    # Merge user-configured ranges with auto-detected ranges
    configured_ranges = set(env_context.get("network_ranges", []))
    all_ranges = sorted(configured_ranges | set(auto_ranges))

    # Merge user-declared new accounts with auto-detected ones
    user_declared_new = env_context.get("new_accounts", set())
    all_new_accounts: dict[str, str] = {}
    # Auto-detected accounts (with timestamps)
    for user, ts in auto_new_accounts.items():
        all_new_accounts[user] = ts
    # User-declared accounts (without timestamps — use "user-declared" marker)
    for user in user_declared_new:
        if user not in all_new_accounts:
            all_new_accounts[user] = "user-declared"

    has_mutable = all_ranges or all_new_accounts or env_context.get("service_accounts") or env_context.get("admin_accounts") or env_context.get("benign_patterns")
    if has_mutable:
        lines.append("")
        lines.append("--- Mutable State (auto-detected, updated each run) ---")

        if all_new_accounts:
            lines.append("  New accounts (grace period — high volume expected):")
            for a in sorted(all_new_accounts):
                ts = all_new_accounts[a]
                if ts == "user-declared":
                    lines.append(f"    - {a} (user-declared)")
                else:
                    lines.append(f"    - {a} (created {ts[:10]})")

        if all_ranges:
            lines.append("  Network ranges (private IPs in these ranges are expected):")
            for r in all_ranges:
                lines.append(f"    - {r}")

        svc_accts = env_context.get("service_accounts", set())
        if svc_accts:
            lines.append("  Service accounts (automated — expected off-hours activity):")
            for a in sorted(svc_accts):
                lines.append(f"    - {a}")

        admin_accts = env_context.get("admin_accounts", set())
        if admin_accts:
            lines.append("  Admin accounts (expected privileged activity):")
            for a in sorted(admin_accts):
                lines.append(f"    - {a}")

        patterns = env_context.get("benign_patterns", [])
        if patterns:
            lines.append("  Known benign patterns:")
            for p in patterns:
                lines.append(f"    - {p}")

    # Add JSON block for structured access
    lines.append("")
    lines.append("--- JSON ---")
    context_json = {
        "environment": env_facts,
        "entities": {k: v for k, v in entity_facts.items() if k in anomalous_entities} if anomalous_entities else {},
        "network_ranges": all_ranges,
        "new_accounts": {a: all_new_accounts.get(a, "user-declared") for a in sorted(all_new_accounts)},
        "service_accounts": sorted(env_context.get("service_accounts", set())),
        "admin_accounts": sorted(env_context.get("admin_accounts", set())),
        "benign_patterns": env_context.get("benign_patterns", []),
    }
    lines.append(_json.dumps(context_json, indent=2))

    return "\n".join(lines)
