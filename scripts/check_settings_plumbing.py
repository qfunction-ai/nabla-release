#!/usr/bin/env python3
"""N8 (round 4): settings-plumbing guard, driven by Settings.model_fields.

The old guard checked .env.example keys against compose — a file with 4
documented keys checked 4 keys while 60+ Settings fields were silently
unforwarded. This guard checks the real contract:

  1. EVERY Settings field reaches the nabla service in docker-compose.yml
     (reachability is mechanical — a field not forwarded is unreachable
     in Docker, the D1/R14/N9 class). Exclusions only via
     INTERNAL_COMPOSE_EXCLUSIONS, each with a justification a reviewer
     can check.
  2. .env.example equals the curated OPERATOR_SET exactly, both
     directions: what operators touch is documented, and detection
     internals stay Settings-only as a REVIEWED omission
     (fields not in the operator set), not an accident.

Usage: python3 scripts/check_settings_plumbing.py  (exit 1 on violation)
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Settings keys deliberately NOT forwarded to the container. Each entry
# needs a justification. Image-fixed values belong here only if the
# compose default must never be overridden by an operator env var.
INTERNAL_COMPOSE_EXCLUSIONS: set[str] = set()

# The curated operator set (round-4 Decision 5): what .env.example
# documents. Everything else is a reviewed documentation omission.
OPERATOR_SET: set[str] = {
    # models + Ollama tuning
    "llm_model", "embedding_model", "embedding_endpoint",
    "ollama_keep_alive", "ollama_flash_attention",
    "ollama_max_loaded_models",
    "letta_compaction_model", "supervisor_context_window",
    "review_context_window",
    # setup + dev
    "setup_token", "dev_mode",
    # LettaLocal authentication (M-3, v0.16.38 migration) — one value,
    # two env names: NABLA_LETTA_API_KEY in .env, mapped by compose to
    # LETTA_SERVER_PASSWORD on the letta service.
    "letta_api_key",
    # F-1: shipped ATT&CK bundle path (course fixtures — hermetic builds)
    "attack_bundle_local_path",
    # baselining behavior
    "baseline_days", "entity_warmup_observations", "new_account_grace_days",
    # site identity
    "timezone", "operator",
    # account classification (N9)
    "machine_accounts", "human_accounts",
    # exfil allowlist
    "sanctioned_services",
    # SIEM block
    "splunk_host", "splunk_token", "splunk_username", "splunk_password",
    "splunk_auth_query", "splunk_network_query", "splunk_dns_query",
    "splunk_endpoint_query",
    # SumoLogic block
    "sumologic_host", "sumologic_access_id", "sumologic_access_key",
    "sumologic_auth_query", "sumologic_network_query",
    "sumologic_dns_query", "sumologic_endpoint_query",
    # scheduled ingestion
    "schedule_enabled", "schedule_interval_minutes",
    "schedule_log_types", "schedule_log_count",
    # web + auth
    "web_host", "web_port", "jwt_expire_minutes",
    "forwarded_allow_ips",  # R6-11: X-Forwarded-For trust (nginx fixed IP)
    # risk tuning operators see in the UI
    "risk_score_decay_half_life_hours", "risk_score_investigation_cutoff",
}


def settings_fields() -> set[str]:
    from nabla.config import Settings
    return set(Settings.model_fields)


def compose_env_keys() -> set[str]:
    """NABLA_* keys declared in docker-compose.yml (textual — no docker
    needed; compose interpolation ${NABLA_X:-default} is declared in the
    file itself)."""
    src = (ROOT / "docker-compose.yml").read_text()
    return {m.lower().removeprefix("nabla_")
            for m in re.findall(r"NABLA_[A-Z0-9_]+", src)}


def env_example_keys() -> set[str]:
    src = (ROOT / ".env.example").read_text()
    return {m.lower().removeprefix("nabla_")
            for m in re.findall(r"^NABLA_[A-Z0-9_]+", src, re.M)}


def check() -> list[str]:
    problems: list[str] = []
    fields = settings_fields()

    unknown_excl = INTERNAL_COMPOSE_EXCLUSIONS - fields
    if unknown_excl:
        problems.append(f"INTERNAL_COMPOSE_EXCLUSIONS names non-Settings keys: {sorted(unknown_excl)}")
    unknown_op = OPERATOR_SET - fields
    if unknown_op:
        problems.append(f"OPERATOR_SET names non-Settings keys: {sorted(unknown_op)}")

    missing_compose = fields - INTERNAL_COMPOSE_EXCLUSIONS - compose_env_keys()
    if missing_compose:
        problems.append(
            f"Settings fields not forwarded to the nabla service "
            f"(unreachable in Docker): {sorted(missing_compose)}"
        )

    example = env_example_keys()
    extra = example - OPERATOR_SET
    missing = OPERATOR_SET - example
    if extra or missing:
        problems.append(
            f".env.example must equal OPERATOR_SET exactly. "
            f"extra: {sorted(extra)} | missing: {sorted(missing)}"
        )

    # M-3 (v0.16.38 migration): the key must be fail-loud on both sides
    # and mapped by name — an empty default silently boots into an
    # unauthable state once the server runs secure mode.
    compose_src = (ROOT / "docker-compose.yml").read_text()
    if "LETTA_SERVER_PASSWORD=${NABLA_LETTA_API_KEY:?" not in compose_src:
        problems.append(
            "letta service must map LETTA_SERVER_PASSWORD from NABLA_LETTA_API_KEY "
            "(fail-loud :? interpolation)"
        )
    if "NABLA_LETTA_API_KEY=${NABLA_LETTA_API_KEY:?" not in compose_src:
        problems.append(
            "nabla service must require NABLA_LETTA_API_KEY (fail-loud :? interpolation)"
        )
    if "NABLA_LETTA_API_KEY:-" in compose_src:
        problems.append(
            "NABLA_LETTA_API_KEY must not default to empty (:-) — that boots "
            "into an unauthable state under secure mode"
        )
    return problems


def main() -> int:
    problems = check()
    for p in problems:
        print(f"SETTINGS-PLUMBING: {p}", file=sys.stderr)
    if problems:
        return 1
    print("settings plumbing OK: all Settings fields forwarded; "
          ".env.example matches the operator set")
    return 0


if __name__ == "__main__":
    sys.exit(main())
