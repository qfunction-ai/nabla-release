"""Reward computation from Supervisor review outcomes.

Parses the threat_findings block text to determine which anomalies
were confirmed vs dismissed, and computes per-threshold rewards.
"""

import re
from nabla.log import get_logger

logger = get_logger("rl.reward")

# Detection method to threshold mapping
METHOD_TO_THRESHOLD = {
    "z_score_spike": "z_score_sigma",
    "z_score": "z_score_sigma",
    "brute_force_attempt": "brute_force_ratio",
    "failed_login_ratio": "brute_force_ratio",
    "off_hours_activity": "off_hours_count",
    "off_hours": "off_hours_count",
    "impossible_travel": "multi_ip_count",
    "multi_ip": "multi_ip_count",
    "activity_spike": "spike_multiplier",
    "lolbin_abuse": "lolbin_sensitivity",
    "lolbin": "lolbin_sensitivity",
    "known_attack_script": "lolbin_sensitivity",
    "attack_script": "lolbin_sensitivity",
    "enumeration_behavior": "enumeration_sensitivity",
    "renamed_attack_tool": "enumeration_sensitivity",
    "renamed_tool": "enumeration_sensitivity",
    "suspicious_parent_child": "parent_child_sensitivity",
    "parent_child": "parent_child_sensitivity",
    "critical_host_escalation": "critical_host_sensitivity",
    "unusual_process": "unusual_process_sensitivity",
    "rapid_action_sequence": "action_sequence_window_minutes",
    "action_sequence": "action_sequence_window_minutes",
    "gcn_lof": "gcn_lof_threshold",
    "provenance_community": "provenance_anomaly_density",
    "temporal_chain": "temporal_chain_window_minutes",
    "suspicious_file_path": "suspicious_path_sensitivity",
    "suspicious_path": "suspicious_path_sensitivity",
    "integrity_anomaly": "integrity_anomaly_sensitivity",
    "registry_abuse": "registry_abuse_sensitivity",
    "network_anomaly": "network_anomaly_sensitivity",
    "ewma_drift": "ewma_sensitivity",
    "ewma": "ewma_sensitivity",
    "cusum_shift": "cusum_sensitivity",
    "cusum_drop": "cusum_sensitivity",
    "cusum": "cusum_sensitivity",
    "entity_event_count_spike": "entity_event_count_sigma",
    "entity_z_score": "entity_event_count_sigma",
    "entity_auth_failure_spike": "entity_auth_failure_sigma",
    "entity_auth_failure": "entity_auth_failure_sigma",
    "entity_off_hours_activity": "off_hours_count",
    "entity_off_hours": "off_hours_count",
    "entity_new_ip": "entity_new_ip_threshold",
    "entity_activity_spike": "spike_multiplier",
    "entity_new_process": "entity_new_process_threshold",
    "entity_unusual_process": "entity_new_process_threshold",
    "entity_host_composite": "entity_behavior_composite_threshold",
    "entity_behavior_composite": "entity_behavior_composite_threshold",
}

# Negation patterns — lines containing these should NOT be counted as confirmed
NEGATION_PATTERNS = [
    "no confirmed", "no threats", "no findings", "no escalated",
    "0 confirmed", "0 escalated", "0 threats", "0 findings",
    "none confirmed", "none escalated", "none found",
    "no action required", "no suspicious",
]

# Reward weights
REWARD_CONFIRMED = 10.0
REWARD_DISMISSED = -2.0
REWARD_VOLUME_PENALTY = -0.1  # Per alert in the batch


def parse_findings(findings_text: str) -> dict:
    """Parse the threat_findings block text into structured results.

    Returns:
        {
            "confirmed": [{"type": str, "detection_method": str, ...}],
            "dismissed": [{"type": str, "detection_method": str, ...}],
            "total_anomalies": int,
            "confirmed_count": int,
            "dismissed_count": int,
        }
    """
    confirmed = []
    dismissed = []
    total_anomalies = 0

    if not findings_text:
        return {
            "confirmed": confirmed,
            "dismissed": dismissed,
            "total_anomalies": 0,
            "confirmed_count": 0,
            "dismissed_count": 0,
        }

    # Look for confirmed/escalated findings
    # The Supervisor writes findings like "ESCALATED: [HIGH] brute_force_attempt: ..."
    # or "Confirmed: ..." or "Dismissed: ..."
    for line in findings_text.strip().split("\n"):
        line_lower = line.strip().lower()
        if not line_lower:
            continue

        # Skip negation lines — "No confirmed threats found" should not count as confirmed
        if any(neg in line_lower for neg in NEGATION_PATTERNS):
            continue

        # Extract detection method from the line
        method = _extract_detection_method(line_lower)

        if any(kw in line_lower for kw in ["escalated", "confirmed", "critical", "high severity"]):
            confirmed.append({"detection_method": method})
        elif any(kw in line_lower for kw in ["dismissed", "false positive", "benign", "no action"]):
            dismissed.append({"detection_method": method})

    # Count total anomalies from the anomaly_queue if referenced
    total_match = re.search(r"(\d+)\s+anomal", findings_text.lower())
    if total_match:
        total_anomalies = int(total_match.group(1))

    return {
        "confirmed": confirmed,
        "dismissed": dismissed,
        "total_anomalies": total_anomalies,
        "confirmed_count": len(confirmed),
        "dismissed_count": len(dismissed),
    }


def _extract_detection_method(text: str) -> str:
    """Extract a detection method name from a line of text."""
    for method in METHOD_TO_THRESHOLD:
        if method in text:
            return method
    return "unknown"


def compute_reward(findings_text: str, anomaly_count: int = 0) -> dict[str, float]:
    """Compute per-threshold reward from Supervisor review outcomes.

    Args:
        findings_text: The threat_findings block text.
        anomaly_count: Total anomalies in the batch (from anomaly_queue).

    Returns:
        {threshold_name: reward_value}
    """
    findings = parse_findings(findings_text)

    # Initialize rewards for all thresholds
    rewards = {name: 0.0 for name in METHOD_TO_THRESHOLD.values()}

    # Positive reward for confirmed findings
    for f in findings["confirmed"]:
        method = f.get("detection_method", "unknown")
        threshold = METHOD_TO_THRESHOLD.get(method)
        if threshold:
            rewards[threshold] += REWARD_CONFIRMED

    # Negative reward for dismissed findings
    for f in findings["dismissed"]:
        method = f.get("detection_method", "unknown")
        threshold = METHOD_TO_THRESHOLD.get(method)
        if threshold:
            rewards[threshold] += REWARD_DISMISSED

    # Volume penalty — too many alerts is costly even if some are real
    total_alerts = max(anomaly_count, findings["total_anomalies"],
                       findings["confirmed_count"] + findings["dismissed_count"])
    if total_alerts > 0:
        volume_penalty = REWARD_VOLUME_PENALTY * total_alerts
        for name in rewards:
            rewards[name] += volume_penalty / len(rewards)

    logger.info(
        "Reward computed: confirmed=%d, dismissed=%d, total=%d → %s",
        findings["confirmed_count"], findings["dismissed_count"],
        total_alerts,
        {k: round(v, 2) for k, v in rewards.items()},
    )

    return rewards
