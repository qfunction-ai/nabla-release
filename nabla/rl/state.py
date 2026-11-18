"""State extraction from shared memory blocks for RL.

Reads the anomaly_queue and threat_findings blocks and extracts
the discretized state features needed by the Q-learning agent.
"""

import re


def extract_anomaly_count(anomaly_queue_text: str) -> int:
    """Extract the total anomaly count from the anomaly_queue block."""
    if not anomaly_queue_text:
        return 0
    match = re.search(r"Pending anomalies:\s*(\d+)", anomaly_queue_text)
    if match:
        return int(match.group(1))
    # Fallback: count numbered lines
    lines = anomaly_queue_text.strip().split("\n")
    count = sum(1 for ln in lines if re.match(r"\s*\d+\.", ln))
    return count


def extract_method_counts(anomaly_queue_text: str) -> dict[str, int]:
    """Extract per-detection-method anomaly counts from the queue.

    Returns:
        {method_name: count} e.g. {"brute_force_attempt": 3, "z_score_spike": 2}
    """
    counts = {}
    if not anomaly_queue_text:
        return counts

    method_keywords = {
        "z_score_spike": ["z_score", "z-score", "z="],
        "brute_force_attempt": ["brute_force", "failed login", "failed logins"],
        "off_hours_activity": ["off_hours", "off-hours"],
        "multiple_source_ips": ["multiple_source_ips", "unique IPs", "multi-ip"],
        "activity_spike": ["activity_spike", "spike"],
        "pre_flagged": ["pre-flagged", "pre_flagged"],
        "lolbin_abuse": ["lolbin_abuse", "lolbin"],
        "suspicious_file_path": ["suspicious_file_path", "suspicious_path"],
        "integrity_anomaly": ["integrity_anomaly"],
        "registry_abuse": ["registry_abuse"],
        "network_anomaly": ["network_anomaly"],
    }

    for line in anomaly_queue_text.strip().split("\n"):
        line_lower = line.lower()
        for method, keywords in method_keywords.items():
            if any(kw in line_lower for kw in keywords):
                counts[method] = counts.get(method, 0) + 1
                break

    return counts


def extract_state(anomaly_queue_text: str, findings_text: str) -> dict:
    """Extract the full RL state from shared block texts.

    Returns:
        {
            "anomaly_count": int,
            "method_counts": {method: int},
            "precision": float,
            "confirmed_count": int,
            "dismissed_count": int,
        }
    """
    from nabla.rl.reward import parse_findings

    anomaly_count = extract_anomaly_count(anomaly_queue_text)
    method_counts = extract_method_counts(anomaly_queue_text)
    findings = parse_findings(findings_text)

    total = max(anomaly_count, findings["confirmed_count"] + findings["dismissed_count"])
    precision = findings["confirmed_count"] / total if total > 0 else 0.5

    return {
        "anomaly_count": anomaly_count,
        "method_counts": method_counts,
        "precision": precision,
        "confirmed_count": findings["confirmed_count"],
        "dismissed_count": findings["dismissed_count"],
    }
