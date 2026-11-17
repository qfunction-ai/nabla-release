"""Tabular Q-learning for adaptive anomaly detection thresholds.

Each detection threshold has its own Q-table with a small state-action space.
The RL module runs as a post-pipeline step — separate from the LLM agents,
no neural network, no LLM calls. Pure Python, runs on any CPU.

Thresholds and their bounds:
  z_score_sigma:                  2.0 – 4.0, step 0.25, default 2.0
  brute_force_ratio:              0.3 – 0.8, step 0.1,  default 0.5
  off_hours_count:                2 – 8,    step 1,     default 3
  multi_ip_count:                 2 – 6,    step 1,     default 3
  spike_multiplier:               2.0 – 6.0, step 0.5,  default 3.0
  lolbin_sensitivity:             0.3 – 1.0, step 0.1,  default 0.7
  parent_child_sensitivity:       0.3 – 1.0, step 0.1,  default 0.7
  critical_host_sensitivity:       0.3 – 1.0, step 0.1,  default 0.7
  unusual_process_sensitivity:     0.3 – 1.0, step 0.1,  default 0.5
  action_sequence_window_minutes: 5 – 120,  step 5,     default 30
"""

import json
import os
from nabla.log import get_logger

logger = get_logger("rl.thresholds")

# Threshold definitions: name -> (min, max, step, default)
THRESHOLDS = {  # noqa: E241
    "z_score_sigma":                  (2.0, 4.0, 0.25, 2.0),
    "brute_force_ratio":              (0.3, 0.8, 0.1,  0.5),
    "off_hours_count":                (2,   8,   1,    3),
    "multi_ip_count":                 (2,   6,   1,    3),
    "spike_multiplier":               (2.0, 6.0, 0.5,  3.0),
    "lolbin_sensitivity":             (0.3, 1.0, 0.1,  0.7),
    "parent_child_sensitivity":       (0.3, 1.0, 0.1,  0.7),
    "critical_host_sensitivity":       (0.3, 1.0, 0.1,  0.7),
    "unusual_process_sensitivity":     (0.3, 1.0, 0.1,  0.5),
    "action_sequence_window_minutes": (5,   120, 5,    30),
    "gcn_lof_alpha":                  (0.3, 0.7, 0.1,  0.5),
    "gcn_lof_threshold":              (0.5, 0.95, 0.05, 0.75),
    "provenance_anomaly_density":     (0.1, 0.5, 0.05, 0.3),
    "provenance_min_community_size":  (2,   10,  1,    3),
    "temporal_chain_window_minutes":  (5,   120, 5,    30),
    "temporal_min_chain_length":      (2,   6,   1,    3),
    "suspicious_path_sensitivity":    (0.3, 1.0, 0.1,  0.7),
    "integrity_anomaly_sensitivity":  (0.3, 1.0, 0.1,  0.7),
    "registry_abuse_sensitivity":     (0.3, 1.0, 0.1,  0.7),
    "network_anomaly_sensitivity":    (0.3, 1.0, 0.1,  0.7),
    "ewma_sensitivity":               (0.3, 1.0, 0.1,  0.7),
    "cusum_sensitivity":             (0.3, 1.0, 0.1,  0.7),
    "enumeration_sensitivity":       (0.3, 1.0, 0.1,  0.7),
    "entity_event_count_sigma":     (1.0, 4.0, 0.25, 2.0),
    "entity_new_ip_threshold":      (1,   5,   1,    2),
    "entity_auth_failure_sigma":    (1.0, 4.0, 0.25, 2.0),
    "entity_new_process_threshold":  (1,   10,  1,    3),
    "entity_new_user_threshold":    (1,   5,   1,    1),
    "entity_behavior_composite_threshold": (0.1, 1.0, 0.1, 0.6),
    "risk_score_investigation_cutoff":    (20.0, 80.0, 5.0, 50.0),
}

# Discretized state buckets
PRECISION_BUCKETS = ["low", "medium", "high"]       # <0.3, 0.3-0.7, >0.7
VOLUME_BUCKETS = ["low", "medium", "high"]          # <10, 10-30, >30

# Actions
ACTIONS = ["increase", "keep", "decrease"]

# RL hyperparameters
ALPHA = 0.1    # Learning rate
GAMMA = 0.3    # Discount factor (low — emphasizes recent experience)
EPSILON = 0.1  # Exploration rate


def _discretize_threshold(name: str, value: float) -> int:
    """Map a continuous threshold value to a discrete bin index."""
    lo, hi, step, _ = THRESHOLDS[name]
    n_bins = int((hi - lo) / step) + 1
    idx = round((value - lo) / step)
    return max(0, min(idx, n_bins - 1))


def _threshold_from_bin(name: str, idx: int) -> float:
    """Map a bin index back to a threshold value."""
    lo, hi, step, _ = THRESHOLDS[name]
    return lo + idx * step


def _discretize_precision(precision: float) -> int:
    """Map precision (0-1) to a bucket index."""
    if precision < 0.3:
        return 0
    elif precision < 0.7:
        return 1
    else:
        return 2


def _discretize_volume(count: int) -> int:
    """Map alert count to a volume bucket index."""
    if count < 10:
        return 0
    elif count < 30:
        return 1
    else:
        return 2


class ThresholdAgent:
    """Tabular Q-learning agent for adaptive threshold tuning.

    State per threshold: (threshold_bin, precision_bucket, volume_bucket)
    Actions: increase, keep, decrease
    """

    def __init__(self):
        self.q_tables: dict[str, dict[tuple, list[float]]] = {}
        self.current_values: dict[str, float] = {}
        self.update_counts: dict[str, int] = {}

        for name, (lo, hi, step, default) in THRESHOLDS.items():
            self.q_tables[name] = {}
            self.current_values[name] = default
            self.update_counts[name] = 0

    def _state_key(self, name: str, precision: float, alert_count: int) -> tuple:
        """Build the discretized state key for a threshold."""
        t_bin = _discretize_threshold(name, self.current_values[name])
        p_bin = _discretize_precision(precision)
        v_bin = _discretize_volume(alert_count)
        return (t_bin, p_bin, v_bin)

    def _get_q(self, name: str, state: tuple) -> list[float]:
        """Get Q-values for a state, initializing if unseen."""
        if state not in self.q_tables[name]:
            self.q_tables[name][state] = [0.0, 0.0, 0.0]  # increase, keep, decrease
        return self.q_tables[name][state]

    def choose_action(self, name: str, precision: float, alert_count: int) -> str:
        """Choose an action using epsilon-greedy policy."""
        import random
        state = self._state_key(name, precision, alert_count)
        q_values = self._get_q(name, state)

        if random.random() < EPSILON:
            idx = random.randint(0, 2)
        else:
            idx = q_values.index(max(q_values))

        return ACTIONS[idx]

    def update(
        self,
        name: str,
        precision: float,
        alert_count: int,
        action: str,
        reward: float,
        next_precision: float,
        next_alert_count: int,
    ) -> None:
        """Perform a Q-learning update."""
        state = self._state_key(name, precision, alert_count)
        next_state = self._state_key(name, next_precision, next_alert_count)

        q_values = self._get_q(name, state)
        next_q_values = self._get_q(name, next_state)

        action_idx = ACTIONS.index(action)
        td_target = reward + GAMMA * max(next_q_values)
        q_values[action_idx] += ALPHA * (td_target - q_values[action_idx])

        self.update_counts[name] += 1

        # Apply the action to the current value
        self._apply_action(name, action)

    def _apply_action(self, name: str, action: str) -> None:
        """Apply an action to adjust the current threshold value."""
        lo, hi, step, _ = THRESHOLDS[name]
        current = self.current_values[name]

        if action == "increase":
            new_val = current + step
        elif action == "decrease":
            new_val = current - step
        else:
            return

        # Clamp to bounds
        self.current_values[name] = max(lo, min(hi, new_val))

    def get_thresholds(self) -> dict[str, float]:
        """Return current threshold values."""
        return dict(self.current_values)

    def to_dict(self) -> dict:
        """Serialize agent state for persistence."""
        # Convert tuple keys to strings for JSON
        q_tables_str = {}
        for name, table in self.q_tables.items():
            q_tables_str[name] = {
                str(k): v for k, v in table.items()
            }
        return {
            "q_tables": q_tables_str,
            "current_values": self.current_values,
            "update_counts": self.update_counts,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ThresholdAgent":
        """Deserialize agent state from persistence."""
        agent = cls.__new__(cls)
        agent.q_tables = {}
        agent.current_values = data.get("current_values", {})
        agent.update_counts = data.get("update_counts", {})

        # Ensure all thresholds exist (including q_tables for new thresholds)
        for name in THRESHOLDS:
            if name not in agent.current_values:
                agent.current_values[name] = THRESHOLDS[name][3]
            if name not in agent.update_counts:
                agent.update_counts[name] = 0
            if name not in agent.q_tables:
                agent.q_tables[name] = {}

        # Convert string keys back to tuples
        for name, table_str in data.get("q_tables", {}).items():
            agent.q_tables[name] = {}
            for k_str, v in table_str.items():
                # Parse tuple from string like "(0, 1, 2)"
                k = tuple(int(x.strip()) for x in k_str.strip("()").split(","))
                agent.q_tables[name][k] = v

        return agent

    def save(self, filepath: str) -> None:
        """Save agent state to a JSON file atomically."""
        from nabla.persistence import atomic_write_json
        atomic_write_json(filepath, self.to_dict())
        logger.info("Saved RL state to %s", filepath)

    @classmethod
    def load(cls, filepath: str) -> "ThresholdAgent":
        """Load agent state from a JSON file.

        The threshold agent state is stored at the top level of the
        combined RL state file (bandit is under "bandit" key).
        """
        if not os.path.exists(filepath):
            logger.info("No RL state file at %s, using defaults", filepath)
            return cls()
        with open(filepath) as f:
            full_data = json.load(f)
        # Threshold agent data is at the top level (bandit is under "bandit" key)
        data = {k: v for k, v in full_data.items() if k != "bandit"}
        agent = cls.from_dict(data)
        logger.info("Loaded RL state from %s (%d updates)",
                    filepath, sum(agent.update_counts.values()))
        return agent


def format_thresholds_block(thresholds: dict[str, float]) -> str:
    """Format thresholds as text for the shared memory block."""
    lines = []
    for name, value in thresholds.items():
        lines.append(f"{name}: {value}")
    return "\n".join(lines)
