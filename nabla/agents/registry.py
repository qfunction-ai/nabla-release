"""Agent lookup by name prefix."""

from __future__ import annotations

from letta_client import Letta

from nabla.log import get_logger

logger = get_logger("registry")

# Map from role to agent name
ROLE_NAMES = {
    "supervisor": "nabla-supervisor",
}


def find_agent(client: Letta, role: str) -> object | None:
    """Find a Nabla agent by role. Returns agent object or None."""
    target_name = ROLE_NAMES.get(role)
    if not target_name:
        logger.warning("Unknown role '%s'", role)
        return None
    from nabla.config import get_settings
    agents = client.agents.list(limit=get_settings().agent_list_limit)
    for agent in agents:
        if agent.name == target_name:
            logger.debug("Found agent '%s' (role=%s, id=%s)", target_name, role, agent.id)
            return agent
    logger.debug("Agent '%s' not found (role=%s)", target_name, role)
    return None


def find_all_agents(client: Letta) -> dict[str, str]:
    """Find all Nabla agents. Returns {role: agent_id}."""
    from nabla.config import get_settings
    result = {}
    agents = client.agents.list(limit=get_settings().agent_list_limit)
    for agent in agents:
        for role, name in ROLE_NAMES.items():
            if agent.name == name:
                result[role] = agent.id
                break
    if len(result) < len(ROLE_NAMES):
        missing = [n for n in ROLE_NAMES.values() if n not in {a.name for a in agents if a.name}]
        logger.warning("Found %d/%d agents — missing: %s", len(result), len(ROLE_NAMES), missing)
    else:
        logger.debug("Found all %d Nabla agents", len(result))
    return result
