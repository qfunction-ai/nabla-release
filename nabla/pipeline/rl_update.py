"""RL threshold update — adapt detection thresholds based on supervisor feedback."""

from __future__ import annotations

from letta_client import Letta

from nabla.log import get_logger
from nabla.pipeline.helpers import _read_supervisor_blocks

logger = get_logger(__name__)


def run_rl_update(client: Letta, agents: dict[str, str], _results: dict[str, str]) -> None:
    """Run the RL threshold update after a pipeline step.

    DISABLED (external review 2026-11-17, finding A1-A3): the reward signal
    was computed from the correlation step's own output (not supervisor or
    analyst judgments), the text parsing mislabeled findings, and the
    Q-learning credit assignment random-walked thresholds on noise. Until
    label-driven calibration lands (remediation plan), thresholds stay at
    their configured defaults — detection stops drifting.
    Reads Supervisor review outcomes, computes rewards, updates Q-tables
    and bandit, and writes updated thresholds to the rl_thresholds block.
    """
    from nabla.log import get_logger
    get_logger("pipeline.rl_update").info(
        "RL threshold update disabled (A1-A3 remediation) — thresholds pinned at defaults")
    # NOTE: the body below the return is unreachable, RETAINED DELIBERATELY
    # as the reference shape for Phase 3 (label-driven calibration replaces
    # it wholesale). Do not "clean it up" — see the remediation plan.
    return
    # The Phase 3 calibration module (nabla/rl/calibration.py) replaces the
    # body wholesale; the Q-learning implementation was deleted with
    # thresholds.py/reward.py — git history holds it.
