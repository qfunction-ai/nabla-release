"""Pipeline status — read system status from the supervisor agent."""

from __future__ import annotations

import os

from letta_client import Letta

from nabla.agents.registry import find_all_agents
from nabla.log import get_logger
from nabla.pipeline.helpers import _read_supervisor_blocks

logger = get_logger(__name__)


def get_status(client: Letta | None = None) -> dict:
    """Get current system status by reading shared blocks from the supervisor agent."""
    if client is None:
        from nabla.client import get_client
        client = get_client()

    agents = find_all_agents(client)
    if "supervisor" not in agents:
        return {"error": "Supervisor agent not found. Run `nabla bootstrap` first."}

    blocks = client.agents.blocks.list(agent_id=agents["supervisor"])
    status = {}
    for b in blocks:
        status[b.label] = b.value

    # Also list all nabla agents
    from nabla.config import get_settings
    all_agents = client.agents.list(limit=get_settings().agent_list_limit)
    agent_info = []
    for a in all_agents:
        if a.name and a.name.startswith("nabla-"):
            role = a.name.replace("nabla-", "")
            agent_info.append({"id": a.id, "name": a.name, "role": role})

    # Add system phase info
    from nabla.system_state import load_system_state, baseline_days_remaining, warm_up_summary
    settings = get_settings()
    sys_state = load_system_state(settings.system_state_file)
    status["system_phase"] = sys_state.get("phase", "detection")
    if sys_state.get("first_ingestion_at"):
        status["first_ingestion_at"] = sys_state["first_ingestion_at"]
    if sys_state.get("phase") == "baseline":
        remaining = baseline_days_remaining(sys_state)
        status["baseline_days_remaining"] = remaining

    # Add entity warm-up progress
    try:
        from nabla.baselines import EntityProfileStore
        if os.path.exists(settings.entity_profiles_file):
            profiles = EntityProfileStore(settings.entity_profiles_file)
            status["warm_up"] = warm_up_summary(profiles)
    except Exception as e:
        logger.debug("Could not load entity profiles for warm-up summary: %s", e)

    return {"blocks": status, "agents": agent_info}
