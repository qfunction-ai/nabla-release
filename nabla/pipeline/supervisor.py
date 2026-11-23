"""Pipeline supervisor — LLM review of findings with contradiction detection."""

from __future__ import annotations

from letta_client import Letta

from nabla.log import get_logger
from nabla.pipeline.helpers import _extract_assistant_message

logger = get_logger("pipeline.supervisor")


def _build_incident_digest(max_lines: int = 20) -> str:
    """Compact digest of active + recent incidents for the supervisor prompt (UI2b).

    Incidents are the supervisor's cross-run memory: repeat patterns get
    narrated as ongoing campaigns. 7-day window, hard-capped.
    """
    from datetime import datetime, timedelta, timezone

    try:
        from nabla.incidents import list_incidents
    except Exception:
        return ""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    lines: list[str] = []
    try:
        for inc in list_incidents(limit=200):
            if inc.get("status") in ("resolved", "false_positive"):
                continue
            if str(inc.get("updated_at", "")) < cutoff:
                continue
            lines.append(
                f"- [{inc.get('status', '?')}/{inc.get('severity', '?')}] "
                f"{inc.get('entity', '?')} — {str(inc.get('finding_type', '?')).replace('_', ' ')} "
                f"(id {str(inc.get('incident_id', ''))[:8]})"
            )
            if len(lines) >= max_lines:
                break
    except Exception as e:
        logger.warning("Incident digest failed: %s", e)
        return ""
    return "\n".join(lines)


def run_supervisor(
    client: Letta,
    agents: dict[str, str],
    findings_count: int,
    findings_text: str,
    phase: str,
) -> str:
    """Step 4: Supervisor — agent reasoning (reviews pre-correlated findings).

    During baseline with no findings, skips LLM (saves ~60s).
    During baseline WITH findings, calls LLM — signature-based findings
    are high-confidence and deserve review.

    Args:
        client: Letta client instance.
        agents: Dict mapping role → agent_id.
        findings_count: Number of confirmed findings.
        findings_text: Formatted findings text.
        phase: System phase ("baseline" or "detection").

    Returns:
        Supervisor review text.
    """
    if phase == "baseline" and findings_count == 0:
        supervisor_text = (
            "System is in baseline phase — statistical detection methods "
            "are suppressed until sufficient historical data is collected. "
            "Only signature-based methods (LOLBIN, attack scripts, critical "
            "host escalation) are active. No findings to review."
        )
        logger.info("Supervisor: skipped LLM (baseline phase, 0 findings)")
        return supervisor_text

    if findings_count == 0:
        supervisor_text = (
            "No confirmed threats detected. All anomaly detection "
            "methods returned below-threshold results. "
            "Continued monitoring is recommended."
        )
        logger.info("Supervisor: skipped LLM (0 findings)")
        return supervisor_text

    # Recent-incident digest (UI2b): bounded cross-run campaign awareness
    digest_note = ""
    incident_digest = _build_incident_digest()
    if incident_digest:
        digest_note = (
            " \nRecent incidents (last 7 days — reference ongoing campaigns "
            "instead of re-narrating them as new):\n" + incident_digest
        )

    # Build prompt with findings count anchor
    phase_note = ""
    if phase == "baseline":
        phase_note = (
            " NOTE: The system is currently in BASELINE phase. "
            "Only signature-based detection methods are active. "
            "These findings are based on known attack patterns, "
            "not statistical deviation. Read the system_phase "
            "block for details on which methods are active/suppressed."
        )
    # Phase 3 (frontend batch, R-1): ONE call, structured output. FR-2
    # settled the mechanism — the fork does not pass response_format
    # through to Ollama, so this is prompt-only JSON with per-element
    # validation downstream (parse_reports). The free-text path survives
    # only as the parse-failure fallback.
    from nabla.pipeline.structured_report import build_structured_prompt, parse_reports

    prompt = build_structured_prompt(findings_count, phase_note, digest_note)

    # T-1 (round 10): the review call goes to the REVIEWER agent, with
    # its message history reset first — every review sees fresh
    # context, no chat-turn priming, no cross-review drift. Stacks
    # bootstrapped before the split have no reviewer and fall back to
    # the supervisor (with a loud warning — that path carries history).
    reviewer_id = agents.get("reviewer")
    if reviewer_id is None:
        logger.warning(
            "No reviewer agent found — falling back to the supervisor for "
            "review. Re-run bootstrap to create the reviewer (reviews will carry "
            "chat history until then)."
        )
        reviewer_id = agents["supervisor"]
    else:
        try:
            client.agents.messages.reset(agent_id=reviewer_id)
        except Exception as reset_err:
            # Reset failure must not silently degrade into a history-
            # carrying review — the whole point of the split is fresh
            # context. Fail the review loudly; the run records it.
            raise RuntimeError(
                f"Could not reset reviewer agent {reviewer_id}: {reset_err}"
            ) from reset_err

    supervisor_response = client.agents.messages.create(
        agent_id=reviewer_id,
        messages=[{
            "role": "user",
            "content": prompt,
        }],
    )
    supervisor_text = _extract_assistant_message(supervisor_response)

    # Order matters: parse FIRST. The contradiction patterns below match
    # inside JSON summary strings too — prepending the header before the
    # parse would mangle the array. When reports parse, the per-report
    # safeguard (attach_structured_reports) owns contradiction handling
    # and the raw text stays clean. When they don't, this raw-text
    # safeguard guards the fallback the user will actually see.
    _meta = parse_reports(supervisor_text)
    _structured_ok = bool(_meta["reports"])

    # Post-processing: if the supervisor contradicts the findings count,
    # prepend a deterministic summary so the user always sees the truth.
    # Round-6 low: substring matching false-positived on negated uses
    # ("no findings were false positives" IS a findings claim). The
    # patterns anchor to sentence starts.
    import re as _re
    _no_threat_patterns = [
        r"(?<![a-z])no correlated threats", r"(?<![a-z])no threats detected",
        r"(?<![a-z])no threats found", r"(?<![a-z])no findings(?![a-z ]*(were|are) (false|benign))",
        r"clear of", r"(?<![a-z])no acute", r"(?<![a-z])no high-confidence correlated",
    ]
    _lower = supervisor_text.lower()
    _contradicts = (
        not _structured_ok
        and any(_re.search(p, _lower) for p in _no_threat_patterns)
    )
    if _contradicts:
        logger.warning(
            "Supervisor contradicts findings count (%d): "
            "prepending deterministic summary",
            findings_count,
        )
        _header_lines = [
            "**⚠ Supervisor Note:** The LLM response below "
            "contradicts the confirmed findings. The "
            "deterministic pipeline found "
            f"{findings_count} confirmed threat(s):\n"
        ]
        for line in findings_text.split("\n"):
            if line.strip():
                _header_lines.append(line)
        _header_lines.append("\n---\n")
        supervisor_text = "\n".join(_header_lines) + supervisor_text

    return supervisor_text
