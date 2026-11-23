"""Supervisor agent evaluation scenarios.

Five scenarios that test the critical behaviors of the Nabla supervisor agent:

1. Finding acknowledgment — supervisor must acknowledge all confirmed findings
2. Contradiction detection — supervisor must never claim "no threats" when findings > 0
3. False positive reasoning — when marking FP, supervisor must explain why
4. Phase awareness — baseline vs detection phase behavior
5. Attack narrative coherence — related findings should be connected

The supervisor is called through the Letta API. Each scenario:
1. Sets up the shared memory blocks (threat_findings, system_phase, etc.)
2. Sends a prompt to the supervisor
3. Checks the response

Usage:
    python -m nabla.evals.supervisor_evals
    # or via CLI:
    nabla eval
"""

from __future__ import annotations

import asyncio

from nabla.evals.framework import (
    SuiteResult,
    LLMJudge,
    NotStringMatching,
    Scenario,
    StringMatching,
    Suite,
)
from nabla.log import get_logger
from nabla.pipeline.structured_report import build_structured_prompt

_BASELINE_PHASE_NOTE = (
    " NOTE: The system is currently in BASELINE phase. "
    "Only signature-based detection methods are active. "
    "These findings are based on known attack patterns, "
    "not statistical deviation. Read the system_phase "
    "block for details on which methods are active/suppressed."
)

logger = get_logger("evals.supervisor")


# ---------------------------------------------------------------------------
# Supervisor wrapper
# ---------------------------------------------------------------------------

def call_supervisor(prompt: str) -> str:
    """Call the Nabla supervisor agent through the Letta API.

    This is the System Under Test (SUT) for evaluation scenarios.

    Args:
        prompt: The prompt to send to the supervisor.

    Returns:
        The supervisor's text response.
    """
    from nabla.client import get_client
    from nabla.agents.registry import find_all_agents
    from nabla.pipeline.helpers import _extract_assistant_message

    client = get_client()
    agents = find_all_agents(client)
    supervisor_id = agents.get("supervisor")
    if not supervisor_id:
        raise RuntimeError("Supervisor agent not found. Run `nabla bootstrap` first.")

    response = client.agents.messages.create(
        agent_id=supervisor_id,
        messages=[{"role": "user", "content": prompt}],
    )
    return _extract_assistant_message(response)


def set_block(label: str, value: str) -> None:
    """Set a shared memory block's value."""
    from nabla.client import get_client

    client = get_client()
    blocks = client.blocks.list(label=label, limit=1)
    block = next(iter(blocks), None)
    if block:
        client.blocks.update(block_id=block.id, value=value)
    else:
        raise ValueError(f"Block '{label}' not found")


# ---------------------------------------------------------------------------
# Canned findings for test scenarios
# ---------------------------------------------------------------------------

_FINDINGS_SINGLE = """Confirmed threats: 1

Finding 1: Brute Force Attack on Domain Controller
Severity: HIGH
Entity: admin_svc (user)
Detection: brute_force_attempt (9 failed logins in 12 minutes, threshold: 5)
MITRE ATT&CK: T1110.001 (Password Guessing)
[anomaly_ids: e1f2a3b4c5d6f7a8]
Evidence: 9 auth failures from 10.0.1.50 to DC01 within 12 minutes
[anomaly_ids: e1f2a3b4c5d6f7a8]
Counterfactuals: If auth failure count were 5 or fewer, this finding would not trigger
Graph context: admin_svc is flagged in provenance community 3 (high anomaly density)
"""

_FINDINGS_MULTI = """Confirmed threats: 3

Finding 1: Brute Force Attack
Severity: HIGH
Entity: admin_svc (user)
Detection: brute_force_attempt (9 failed logins in 12 minutes)
MITRE ATT&CK: T1110.001
[anomaly_ids: aabb001122334455]

Finding 2: LOLBIN Execution — certutil
Severity: HIGH
Entity: WORKSTATION-04 (host)
Detection: lolbin_abuse (certutil.exe with download flags)
MITRE ATT&CK: T1105 (Ingress Tool Transfer)
Tools: certutil
[anomaly_ids: bbcc112233445566]

Finding 3: Network Exfiltration to Cloud Storage
Severity: CRITICAL
Entity: admin_svc (user)
Detection: exfil_destination (cloud storage: drive.google.com on port 443)
MITRE ATT&CK: T1567.002 (Exfiltration to Cloud Storage)
Evidence: 2.3 GB transferred to drive.google.com in 45 minutes
[anomaly_ids: ccdd223344556677]
"""

_FINDINGS_BASELINE = """Confirmed threats: 1

Finding 1: LOLBIN Execution — powershell
Severity: MEDIUM
Entity: DEV-WIN10 (host)
Detection: lolbin_abuse (powershell.exe -enc with encoded command)
MITRE ATT&CK: T1059.001 (PowerShell)
Evidence: Encoded PowerShell command executing from cmd.exe
[anomaly_ids: ddee334455667788]
Note: This is the only active finding during BASELINE phase.
"""

_FINDINGS_NONE = """Confirmed threats: none
"""

_NO_THREAT_PATTERNS = [
    "no correlated threats", "no threats detected",
    "no threats found", "no findings", "clear of",
    "no acute", "no high-confidence correlated",
]


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------

def build_acknowledgment_scenario() -> Scenario:
    """Scenario 1: Supervisor must acknowledge all confirmed findings.

    With 3 findings in the threat_findings block, the supervisor
    must mention each finding entity or type in its response.
    """
    return (
        Scenario("finding_acknowledgment")
        .interact(
            inputs="The threat_findings block contains 3 confirmed threat(s). Read the threat_findings block carefully. For each finding: assess whether it is a true positive or false positive, connect related findings into coherent attack narratives, and generate a concise report.",
            outputs_fn=lambda _: call_supervisor(
                build_structured_prompt(3, "", "")
            ),
        )
        .check(
            StringMatching(
                name="acknowledges_admin_svc",
                keyword="admin_svc",
            )
        )
        .check(
            StringMatching(
                name="acknowledges_certutil",
                keyword="certutil",
            )
        )
        .check(
            StringMatching(
                name="acknowledges_exfiltration",
                keyword="exfil",
            )
        )
    )


def build_contradiction_scenario() -> Scenario:
    """Scenario 2: Supervisor must never claim "no threats" when findings > 0.

    This tests the critical failure mode where the LLM contradicts
    the deterministic pipeline's findings count.
    """
    return (
        Scenario("contradiction_detection")
        .interact(
            inputs="The threat_findings block contains 1 confirmed threat(s). Read the threat_findings block carefully.",
            outputs_fn=lambda _: call_supervisor(
                build_structured_prompt(1, "", "")
            ),
        )
        .check(
            NotStringMatching(
                name="no_no_threats_claim",
                keyword="no threats detected",
            )
        )
        .check(
            NotStringMatching(
                name="no_no_findings_claim",
                keyword="no findings",
            )
        )
        .check(
            NotStringMatching(
                name="no_clear_of_claim",
                keyword="clear of",
            )
        )
    )


def build_fp_reasoning_scenario() -> Scenario:
    """Scenario 3: When marking a finding as FP, the supervisor must explain why.

    This requires an LLM judge to evaluate whether any FP claims
    are supported by evidence from the findings.
    """
    # The judge_prompt uses Python format strings (not Jinja2)
    judge_prompt = (
        "Evaluate whether the supervisor's report properly justifies any "
        "false positive claims.\n\n"
        "Findings given to supervisor:\n{_FINDINGS_MULTI}\n\n"
        "Supervisor's report:\n{outputs}\n\n"
        "Criteria:\n"
        "1. If the supervisor marks any finding as a false positive, "
        "does it explain WHY based on the evidence?\n"
        "2. If the supervisor accepts all findings as true positives, "
        "that is also acceptable (pass).\n"
        "3. If the supervisor marks a finding as FP without explanation, fail.\n\n"
        "Return 'passed: true' if all FP claims are properly justified, "
        "or if no FP claims are made. Return 'passed: false' if an FP "
        "claim lacks justification."
    ).replace("{_FINDINGS_MULTI}", _FINDINGS_MULTI)

    return (
        Scenario("fp_reasoning")
        .interact(
            inputs="The threat_findings block contains 3 confirmed threat(s). Read the threat_findings block carefully.",
            outputs_fn=lambda _: call_supervisor(
                build_structured_prompt(3, "", "")
            ),
        )
        .check(
            LLMJudge(
                name="fp_justified",
                judge_prompt=judge_prompt,
                judge_fn=_make_judge_fn(),
            )
        )
    )


def build_phase_awareness_scenario() -> Scenario:
    """Scenario 4: Supervisor must respect baseline phase constraints.

    During baseline, the supervisor must not flag the absence of
    statistical findings as a gap.
    """
    judge_prompt = (
        "Evaluate whether the supervisor respects baseline phase constraints.\n\n"
        "Context: The system is in BASELINE phase. Only signature-based "
        "detection methods are active. Statistical methods (z-score, off-hours, "
        "activity spike, multi-IP, EWMA, CUSUM) are intentionally suppressed.\n\n"
        "Supervisor's report:\n{outputs}\n\n"
        "Criteria:\n"
        "1. The supervisor should NOT flag the absence of statistical findings "
        "as a gap or concern during baseline.\n"
        "2. The supervisor should acknowledge that baseline phase means "
        "fewer findings are expected.\n"
        "3. The supervisor should NOT recommend activating statistical methods "
        "before the system is ready.\n\n"
        "Return 'passed: true' if the supervisor respects baseline phase. "
        "Return 'passed: false' if it incorrectly flags missing statistical findings."
    )

    return (
        Scenario("phase_awareness")
        .interact(
            inputs="The threat_findings block contains 1 confirmed threat(s). Read the threat_findings block carefully. NOTE: The system is currently in BASELINE phase.",
            outputs_fn=lambda _: call_supervisor(
                build_structured_prompt(1, _BASELINE_PHASE_NOTE, "")
            ),
        )
        .check(
            NotStringMatching(
                name="no_missing_stats_flag",
                keyword="missing statistical",
            )
        )
        .check(
            NotStringMatching(
                name="no_off_hours_gap",
                keyword="off-hours detection should be active",
            )
        )
        .check(
            LLMJudge(
                name="respects_baseline",
                judge_prompt=judge_prompt,
                judge_fn=_make_judge_fn(),
            )
        )
    )


def build_narrative_coherence_scenario() -> Scenario:
    """Scenario 5: Supervisor should connect related findings into attack narratives.

    The 3 findings (brute force, LOLBIN, exfiltration) form a coherent
    attack chain: initial access → execution → exfiltration. The supervisor
    should identify this narrative.
    """
    judge_prompt = (
        "Evaluate whether the supervisor connects related findings into "
        "coherent attack narratives.\n\n"
        "Findings given to supervisor:\n{_FINDINGS_MULTI}\n\n"
        "Supervisor's report:\n{outputs}\n\n"
        "The three findings form a potential attack chain:\n"
        "- Finding 1 (brute force) = initial access / credential compromise\n"
        "- Finding 2 (certutil LOLBIN) = tool transfer / execution\n"
        "- Finding 3 (cloud exfiltration) = data theft\n\n"
        "Criteria:\n"
        "1. Does the supervisor identify that these findings are related?\n"
        "2. Does the supervisor describe them as an attack chain or narrative?\n"
        "3. The supervisor does NOT need to use the exact phrase 'attack chain' "
        "— any coherent connection counts.\n\n"
        "Return 'passed: true' if the report connects the findings. "
        "Return 'passed: false' if it treats each finding in isolation."
    ).replace("{_FINDINGS_MULTI}", _FINDINGS_MULTI)

    return (
        Scenario("narrative_coherence")
        .interact(
            inputs="The threat_findings block contains 3 confirmed threat(s). Read the threat_findings block carefully.",
            outputs_fn=lambda _: call_supervisor(
                build_structured_prompt(3, "", "")
            ),
        )
        .check(
            LLMJudge(
                name="connects_findings",
                judge_prompt=judge_prompt,
                judge_fn=_make_judge_fn(),
            )
        )
    )


# ---------------------------------------------------------------------------
# Judge function factory
# ---------------------------------------------------------------------------

def _make_judge_fn() -> callable:
    """Create an LLM judge function using the same Letta/Ollama infrastructure.

    The judge uses a direct Ollama call to avoid the dependency on
    having a separate judge agent. It reuses the same model the
    supervisor uses.
    """
    def judge_fn(prompt: str) -> str:
        try:
            import httpx
            from nabla.config import get_settings
            settings = get_settings()

            # Use Ollama directly for the judge (lighter weight than
            # going through the Letta agent API)
            ollama_url = settings.ollama_base_url or "http://localhost:11434"
            model = settings.ollama_model or "gemma3:4b"

            response = httpx.post(
                f"{ollama_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1},
                },
                timeout=120,
            )
            data = response.json()
            return data.get("response", "")
        except Exception as e:
            logger.warning("LLM judge call failed: %s", e)
            return f"Judge error: {e}"

    return judge_fn


# ---------------------------------------------------------------------------
# Suite builder
# ---------------------------------------------------------------------------

def build_supervisor_suite() -> Suite:
    """Build the complete supervisor evaluation suite.

    Call setup_blocks() before running to populate the shared blocks
    with test data.
    """
    suite = Suite("nabla-supervisor-evals")
    suite.add(build_acknowledgment_scenario())
    suite.add(build_contradiction_scenario())
    suite.add(build_fp_reasoning_scenario())
    suite.add(build_phase_awareness_scenario())
    suite.add(build_narrative_coherence_scenario())
    return suite


def setup_blocks_for_eval() -> None:
    """Set up shared memory blocks with test data for evaluation.

    This must be called before running the eval suite. It populates
    the threat_findings and system_phase blocks with known test data.
    """
    try:
        set_block("threat_findings", _FINDINGS_MULTI)
        set_block("system_phase", (
            "Phase: DETECTION\n"
            "Active methods: all (signature + statistical)\n"
            "Baseline complete: 2026-05-01\n"
            "Warm users: 15"
        ))
        set_block("environment_context", (
            "Environment Facts:\n"
            "- Domain: corp.example.com\n"
            "- Domain Controller: DC01 (10.0.1.1)\n"
            "- Admin service account: admin_svc (expected to auth from 10.0.1.50)\n"
            "\n"
            "Entity Context:\n"
            "- admin_svc: service account for automated deployments, expected high auth volume\n"
            "- WORKSTATION-04: developer workstation, certutil usage unusual\n"
            "\n"
            "Mutable State:\n"
            "- New accounts: none\n"
            "- Service accounts: admin_svc\n"
            "- Private IPs: 10.0.1.0/24 (same VPC)"
        ))
        logger.info("Shared blocks set up for evaluation")
    except Exception as e:
        logger.warning("Failed to set up blocks for eval: %s", e)


async def run_evals() -> SuiteResult:
    """Run the full supervisor evaluation suite.

    Returns:
        SuiteResult with pass/fail status for all scenarios.
    """
    setup_blocks_for_eval()
    suite = build_supervisor_suite()
    result = await suite.run()
    return result


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    result = asyncio.run(run_evals())
    result.print_report()
    # Save results to JSON
    from pathlib import Path
    from nabla.config import get_settings
    settings = get_settings()
    results_path = Path(settings.data_dir) / "eval_results.json"
    results_path.write_text(result.to_json())
    print(f"\nResults saved to {results_path}")
