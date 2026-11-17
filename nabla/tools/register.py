"""Legacy tool name registry for teardown cleanup.

Since Phase 44, the supervisor agent has no tools — it reads shared blocks
directly from its context window. This module exists solely to provide
LEGACY_TOOL_NAMES for teardown to clean up leftover tools from older bootstraps.
"""

# Legacy tool names that may still exist from older bootstraps
LEGACY_TOOL_NAMES = {
    # Supervisor tools (removed Phase 44)
    "check_system_health",
    "review_anomalies",
    "escalate_finding",
    "generate_report",
    # Threat tools (removed Phase 44)
    "fetch_anomalies",
    "fetch_graph_context",
    "correlate_events",
    "assess_threat_level",
    "produce_finding",
    "build_timeline",
    # Anomaly tools (removed Phase 44)
    "fetch_recent_logs",
    "compute_baseline",
    "detect_anomalies",
    "update_anomaly_queue",
    "fetch_historical_baseline",
}
