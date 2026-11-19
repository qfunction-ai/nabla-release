"""Multi-armed bandit for detection method effectiveness.

Uses Thompson Sampling with Beta distributions to track which
detection methods produce the most confirmed findings.
~50 lines of actual logic, no neural network needed.
"""

import json
import os
from nabla.log import get_logger

logger = get_logger("rl.bandit")

DETECTION_METHODS = [
    "pre_flagged",
    "z_score",
    "entity_z_score",
    "failed_login_ratio",
    "entity_auth_failure",
    "off_hours",
    "entity_off_hours",
    "multi_ip",
    "entity_new_ip",
    "activity_spike",
    "entity_activity_spike",
    "lolbin",
    "parent_child",
    "critical_host_escalation",
    "unusual_process",
    "entity_new_process",
    "entity_unusual_process",
    "action_sequence",
    "suspicious_path",
    "integrity_anomaly",
    "registry_abuse",
    "network_anomaly",
    "gcn_lof",
    "provenance_community",
    "temporal_chain",
    "entity_behavior_composite",
    "entity_host_composite",
]


class DetectionMethodBandit:
    """Thompson Sampling bandit for detection method effectiveness.

    Each method is an arm. The reward is whether the Supervisor
    confirmed a finding from that method (1) or dismissed it (0).
    Beta(alpha, beta) posterior for each arm.
    """

    def __init__(self, methods: list[str] | None = None):
        self.methods = list(methods or DETECTION_METHODS)
        self.alpha: dict[str, float] = {m: 1.0 for m in self.methods}
        self.beta: dict[str, float] = {m: 1.0 for m in self.methods}
        self.update_counts: dict[str, int] = {m: 0 for m in self.methods}

    def update(self, method: str, confirmed: bool) -> None:
        """Update the bandit with a new observation."""
        if method not in self.alpha:
            # Auto-register unknown methods
            self.alpha[method] = 1.0
            self.beta[method] = 1.0
            self.update_counts[method] = 0
            self.methods.append(method)

        if confirmed:
            self.alpha[method] += 1
        else:
            self.beta[method] += 1
        self.update_counts[method] += 1

    def get_weights(self) -> dict[str, float]:
        """Sample from Beta distributions to get current weights."""
        import random
        return {
            m: random.betavariate(self.alpha[m], self.beta[m])
            for m in self.methods
        }

    def get_ranking(self) -> list[tuple[str, float]]:
        """Return methods sorted by Thompson-sampled effectiveness (descending).

        Each call samples from the Beta posteriors, so rankings may vary
        between calls. For deterministic ordering, use get_means().
        """
        import random
        ranked = sorted(
            ((m, random.betavariate(self.alpha[m], self.beta[m])) for m in self.methods),
            key=lambda x: x[1],
            reverse=True,
        )
        return ranked

    def get_means(self) -> dict[str, float]:
        """Return the expected value (mean) of each Beta distribution."""
        return {
            m: self.alpha[m] / (self.alpha[m] + self.beta[m])
            for m in self.methods
        }

    def to_dict(self) -> dict:
        """Serialize bandit state."""
        return {
            "methods": self.methods,
            "alpha": self.alpha,
            "beta": self.beta,
            "update_counts": self.update_counts,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DetectionMethodBandit":
        """Deserialize bandit state. Methods missing from the stored
        alpha/beta (a partial state file) get uniform priors rather than
        a KeyError on first sample."""
        bandit = cls(methods=data.get("methods", list(DETECTION_METHODS)))
        bandit.alpha = {m: float(data.get("alpha", {}).get(m, 1.0)) for m in bandit.methods}
        bandit.beta = {m: float(data.get("beta", {}).get(m, 1.0)) for m in bandit.methods}
        bandit.update_counts = {m: int(data.get("update_counts", {}).get(m, 0)) for m in bandit.methods}
        return bandit

    def save(self, filepath: str) -> None:
        """Save bandit state to a JSON file atomically."""
        from nabla.persistence import atomic_write_json
        atomic_write_json(filepath, self.to_dict())

    @classmethod
    def load(cls, filepath: str) -> "DetectionMethodBandit":
        """Load bandit state from a JSON file.

        The bandit state is stored under the "bandit" key in the
        combined RL state file.

        N6 (round 4): schema-gated one-time reset. State files without
        schema>=2 carry alpha/beta learned by the retired text parser
        (which mislabeled findings — that state scales risk weights
        under wrong premises). Loading a pre-schema file yields uniform
        priors, and the file is rewritten atomically WITH the marker so
        the reset runs exactly once. Post-schema state loads normally.
        """
        if not os.path.exists(filepath):
            logger.info("No bandit state file at %s, using defaults", filepath)
            return cls()
        with open(filepath) as f:
            full_data = json.load(f)
        # Extract bandit section from combined state file
        data = full_data.get("bandit", full_data)
        if int(full_data.get("schema", 1)) < 2:
            logger.warning(
                "Bandit state pre-schema (learned by the retired text parser) — "
                "resetting to uniform priors (one-time, schema marker 2)")
            bandit = cls()
            try:
                full_data["schema"] = 2
                full_data["bandit"] = {"alpha": {}, "beta": {}}
                from nabla.persistence import atomic_write_json
                atomic_write_json(filepath, full_data)
            except OSError as e:
                logger.warning("Could not stamp schema marker: %s", e)
            return bandit
        bandit = cls.from_dict(data)
        logger.info("Loaded bandit state from %s (%d updates)",
                    filepath, sum(bandit.update_counts.values()))
        return bandit
