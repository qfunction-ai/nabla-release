"""RL threshold update — adapt detection thresholds based on supervisor feedback."""

from __future__ import annotations

from letta_client import Letta

from nabla.log import get_logger
from nabla.pipeline.helpers import _read_supervisor_blocks

logger = get_logger(__name__)


def run_rl_update(client: Letta, agents: dict[str, str], _results: dict[str, str]) -> None:
    """Run the RL threshold update after a pipeline step.

    Reads Supervisor review outcomes, computes rewards, updates Q-tables
    and bandit, and writes updated thresholds to the rl_thresholds block.
    """
    from nabla.config import get_settings
    from nabla.rl.thresholds import ThresholdAgent, format_thresholds_block
    from nabla.rl.reward import compute_reward
    from nabla.rl.state import extract_state
    from nabla.rl.bandit import DetectionMethodBandit

    settings = get_settings()

    # Read shared blocks from the supervisor agent
    blocks = _read_supervisor_blocks(client, agents["supervisor"], "anomaly_queue", "threat_findings")
    anomaly_queue_text = blocks["anomaly_queue"]
    findings_text = blocks["threat_findings"]

    # Load RL state
    agent = ThresholdAgent.load(settings.rl_state_file)
    bandit = DetectionMethodBandit.load(settings.rl_state_file)

    # Extract state
    state = extract_state(anomaly_queue_text, findings_text)
    anomaly_count = state["anomaly_count"]
    precision = state["precision"]

    # No anomalies detected — skip RL update. No reward signal means
    # no threshold changes, preventing the system from rewarding
    # higher thresholds when it finds nothing.
    if anomaly_count == 0:
        logger.info("No anomalies detected — skipping RL update")
        return

    # Compute rewards
    rewards = compute_reward(findings_text, anomaly_count)

    # Update Q-tables for each threshold
    for name in rewards:
        if name not in agent.current_values:
            continue  # Skip thresholds not in the Q-table agent
        action = agent.choose_action(name, precision, anomaly_count)
        # For the "next" state, we use the same precision/count (simplified)
        # In a full implementation, this would be the state after the action
        agent.update(
            name=name,
            precision=precision,
            alert_count=anomaly_count,
            action=action,
            reward=rewards[name],
            next_precision=precision,
            next_alert_count=anomaly_count,
        )

    # Update bandit based on confirmed/dismissed findings
    from nabla.rl.reward import parse_findings
    findings = parse_findings(findings_text)
    for f in findings["confirmed"]:
        method = f.get("detection_method", "unknown")
        bandit.update(method, confirmed=True)
    for f in findings["dismissed"]:
        method = f.get("detection_method", "unknown")
        bandit.update(method, confirmed=False)

    # Write updated thresholds to the rl_thresholds block
    new_thresholds = agent.get_thresholds()
    new_block_text = format_thresholds_block(new_thresholds)

    # Update the block via the supervisor agent
    client.agents.blocks.update(
        agent_id=agents["supervisor"],
        block_label="rl_thresholds",
        value=new_block_text,
    )

    # Save RL state atomically (threshold agent + bandit in one file)
    from nabla.persistence import atomic_write_json, file_lock
    state_data = agent.to_dict()
    state_data["bandit"] = bandit.to_dict()
    with file_lock(settings.rl_state_file):
        atomic_write_json(settings.rl_state_file, state_data)

    logger.info(
        "RL thresholds updated: %s",
        {k: round(v, 2) for k, v in new_thresholds.items()},
    )
