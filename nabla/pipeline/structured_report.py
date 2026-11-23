"""Structured supervisor reports — per-incident JSON with per-element
validation and the D-10 evidence resolver (frontend batch Phase 3, R-1).

Design constraints (from the approved plan + FR-1/FR-2/FR-3):

- ONE LLM call (preserves connect-related-findings). FR-2 settled the
  mechanism: the fork does NOT pass response_format through to Ollama
  (live-probed 2026-11-23 — a schema-forced field produced free prose;
  the Ollama request payload builds without a format param). So this is
  PROMPT-ONLY JSON with per-element validation as the safety net.
- PER-ELEMENT validation (FR-1): one malformed report or one truncation
  must not invalidate its neighbors. Each incident gets its own
  review_status. The parser detects an incomplete array and marks the
  affected reports invalid; it NEVER repairs.
- The model can only cite IDs it can SEE (FR-3): the threat_findings
  block carries anomaly_ids; evidence refs resolve against the
  incident's own contributing_anomaly_details (D-10, server-side, in
  the incident-view build — never the LLM's job).
- ATT&CK IDs are checked against the STIX bundle behind the
  attack_mapping block — one list, not a second copy (the L11 lesson).
- The deterministic findings-count safeguard survives, applied to each
  structured summary.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from nabla.log import get_logger

logger = get_logger("pipeline.structured_report")

# ---------------------------------------------------------------------------
# Models — the wire contract for one per-incident report
# ---------------------------------------------------------------------------

VALID_REPORT_SEVERITIES = {"informational", "low", "medium", "high", "critical"}


class Claim(BaseModel):
    """One specific assertion plus the evidence refs that back it."""

    text: str = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)


class IncidentReport(BaseModel):
    """One per-incident structured report from the supervisor."""

    entity: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    severity: str
    entities: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

STRUCTURED_PROMPT_INSTRUCTIONS = """\
The threat_findings block contains {findings_count} confirmed threat(s). \
Read it carefully — every finding line carries an [anomaly_ids: ...] list.

For EACH finding, produce ONE JSON object with EXACTLY these fields:
{{
  "entity": "<the finding's entity name>",
  "summary": "<2-3 sentences: true/false-positive assessment and the attack narrative>",
  "severity": "<informational|low|medium|high|critical>",
  "entities": ["<every entity involved: users, hosts, IPs>"],
  "attack_techniques": ["<ATT&CK technique IDs, e.g. T1059>"],
  "recommended_actions": ["<2-4 concrete containment or investigation actions>"],
  "claims": [
    {{"text": "<one specific claim>", "evidence": ["<anomaly_id copied from the finding's [anomaly_ids: ...] list>"]}}
  ]
}}

Rules:
- Cite ONLY anomaly IDs that appear in the threat_findings block.
- Every claim must carry at least one evidence ref.
- Return ONLY the JSON array of objects — no prose before or after,
  no markdown fences, no commentary. The array must have exactly
  {findings_count} object(s), one per finding.
"""


def build_structured_prompt(findings_count: int, phase_note: str, digest_note: str) -> str:
    """The single supervisor prompt, now requesting the JSON array."""
    return (
        STRUCTURED_PROMPT_INSTRUCTIONS.format(findings_count=findings_count)
        + phase_note
        + digest_note
    )


# ---------------------------------------------------------------------------
# Parsing — per-element, never repairs
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)
_ARRAY_START_RE = re.compile(r"\[")
_HEXBLOB_RE = re.compile(r"^[0-9a-f]{16}$")


def extract_json_array(text: str) -> list[Any] | None:
    """Best-effort array extraction: fences stripped, outermost [] found.

    Returns None when no complete array parses — truncation included.
    Never repairs or synthesizes elements.
    """
    if not text or not text.strip():
        return None
    candidates: list[str] = []
    m = _FENCE_RE.search(text)
    if m:
        candidates.append(m.group(1))
    candidates.append(text)
    # Outermost bracket span: first '[' to last ']'. A truncated array
    # has no closing ']' after the last element, so the span either
    # fails json.loads or loads a PREFIX slice — the per-element
    # validation below is what catches mid-element truncation.
    for cand in candidates:
        start = cand.find("[")
        end = cand.rfind("]")
        if start >= 0 and end > start:
            try:
                parsed = json.loads(cand[start : end + 1])
            except json.JSONDecodeError:
                # silent by design: candidate loop tries the next
                # extraction strategy — failure is reported by the
                # caller when NO candidate parses (2026-11-23)
                continue
            if isinstance(parsed, list):
                return parsed
    return None


def parse_reports(text: str) -> dict[str, Any]:
    """Parse + validate per element. One bad element never poisons neighbors.

    Returns meta:
        raw_len:       length of the LLM output
        reports:       list of VALIDATED report dicts (model_dump)
        invalid:       list of {"index", "error", "raw"} for failed elements
        parse_error:   set when no array extracted at all
        array_len:     elements in the extracted array (None if none)
    """
    meta: dict[str, Any] = {
        "raw_len": len(text or ""),
        "reports": [],
        "invalid": [],
        "parse_error": None,
        "array_len": None,
    }
    arr = extract_json_array(text or "")
    if arr is None:
        meta["parse_error"] = "no complete JSON array in supervisor output"
        return meta
    meta["array_len"] = len(arr)
    for i, el in enumerate(arr):
        if not isinstance(el, dict):
            meta["invalid"].append(
                {"index": i, "error": "element is not an object", "raw": str(el)[:200]}
            )
            continue
        try:
            report = IncidentReport.model_validate(el)
        except ValidationError as e:
            meta["invalid"].append(
                {"index": i, "error": str(e)[:300], "raw": json.dumps(el)[:400]}
            )
            continue
        if report.severity not in VALID_REPORT_SEVERITIES:
            meta["invalid"].append(
                {"index": i, "error": f"severity {report.severity!r} not in "
                f"{sorted(VALID_REPORT_SEVERITIES)}", "raw": json.dumps(el)[:400]}
            )
            continue
        meta["reports"].append(report.model_dump())
    return meta


# ---------------------------------------------------------------------------
# D-10 resolver — evidence + ATT&CK, server-side, per incident
# ---------------------------------------------------------------------------

def _resolve_ref(
    ref: str,
    anomaly_by_id: dict[str, dict],
    event_ids: set[str],
    entity_names: set[str],
) -> dict[str, Any]:
    """Resolve one evidence ref against the incident's own stored data."""
    out: dict[str, Any] = {"ref": ref, "resolved": False, "kind": "unknown"}
    r = (ref or "").strip()
    if not r:
        return out
    if r in anomaly_by_id:
        det = anomaly_by_id[r]
        out.update(
            resolved=True,
            kind="anomaly_id",
            method=det.get("method", ""),
            raw_score=det.get("raw_score"),
            threshold_in_effect=det.get("threshold_in_effect"),
        )
        return out
    if r in event_ids:
        out.update(resolved=True, kind="event_id")
        return out
    if r in entity_names:
        out.update(resolved=True, kind="entity_id")
        return out
    return out


def _attack_technique_ids() -> set[str]:
    """Valid ATT&CK technique IDs from the STIX bundle — one source,
    cached per process. Empty set = bundle unavailable; every ID then
    resolves as unknown (flagged, not trusted, not dropped)."""
    try:
        from nabla.attack import get_attack_technique_ids
        return get_attack_technique_ids()
    except Exception as e:  # pragma: no cover — bundle missing is a degraded state
        logger.warning("ATT&CK ID check unavailable: %s", e)
        return set()


def resolve_report(report: dict[str, Any], incident: dict[str, Any]) -> dict[str, Any]:
    """Resolve one validated report against one incident's stored data.

    - every claim's evidence refs marked resolved/unresolved; resolved
      anomaly refs carry raw_score and threshold_in_effect
    - attack_techniques checked against the bundle; unknown flagged
    - unresolved/unknown are FLAGGED, never silently dropped
    """
    details = incident.get("contributing_anomaly_details") or []
    anomaly_by_id = {d.get("anomaly_id", ""): d for d in details if d.get("anomaly_id")}
    event_ids: set[str] = set()
    for d in details:
        for eid in d.get("event_ids") or []:
            event_ids.add(eid)
    entity_names = {
        str(incident.get("entity", "")),
        *(incident.get("entities") or []),
        *(report.get("entities") or []),
    }
    entity_names.discard("")

    known_ids = _attack_technique_ids()

    resolved_claims = []
    for claim in report.get("claims") or []:
        refs = [_resolve_ref(r, anomaly_by_id, event_ids, entity_names)
                for r in (claim.get("evidence") or [])]
        resolved_claims.append({"text": claim.get("text", ""), "evidence": refs})

    techniques = []
    for t in report.get("attack_techniques") or []:
        tid = str(t).strip().upper()
        techniques.append({"id": tid, "known": (tid in known_ids) if known_ids else False})

    out = dict(report)
    out["claims"] = resolved_claims
    out["attack_techniques"] = techniques
    return out


# ---------------------------------------------------------------------------
# Deterministic safeguard — same patterns as the free-text path
# ---------------------------------------------------------------------------

_NO_THREAT_PATTERNS = [
    r"(?<![a-z])no correlated threats", r"(?<![a-z])no threats detected",
    r"(?<![a-z])no threats found", r"(?<![a-z])no findings(?![a-z ]*(were|are) (false|benign))",
    r"clear of", r"(?<![a-z])no acute", r"(?<![a-z])no high-confidence correlated",
]


def summary_contradicts(summary: str) -> bool:
    lowered = (summary or "").lower()
    return any(re.search(p, lowered) for p in _NO_THREAT_PATTERNS)


# ---------------------------------------------------------------------------
# Attach — match reports to incidents, set review_status per incident
# ---------------------------------------------------------------------------

def attach_structured_reports(
    incidents: list[dict[str, Any]],
    supervisor_text: str,
    findings_count: int,
    findings_text: str = "",
) -> None:
    """Parse the supervisor output and attach per-incident reports IN PLACE.

    review_status per incident:
        ok       — a validated report matched and was resolved onto it
        invalid  — LLM output existed but no valid report matched
        absent   — no LLM output at all

    Matching: anomaly_id overlap first (strongest), entity name as
    fallback. Unmatched valid reports are logged, not forced.
    """
    if not supervisor_text or not supervisor_text.strip():
        for inc in incidents:
            inc["review_status"] = "absent"
            inc.pop("supervisor_report", None)
        return

    meta = parse_reports(supervisor_text)
    reports = meta["reports"]

    # Deterministic safeguard on each structured summary: a report that
    # claims no threats against confirmed findings gets the truth
    # prepended — the pipeline's findings are authoritative.
    for rep in reports:
        if findings_count > 0 and summary_contradicts(rep.get("summary", "")):
            logger.warning(
                "Structured report for %s contradicts findings count (%d): "
                "prepending deterministic summary",
                rep.get("entity"), findings_count,
            )
            header = (
                f"DETERMINISTIC NOTE: the pipeline confirmed {findings_count} "
                "threat(s) — the summary below contradicts them.\n"
            )
            rep["summary"] = header + (rep.get("summary") or "")

    # Index reports for matching.
    def _report_evidence_ids(rep: dict) -> set[str]:
        ids: set[str] = set()
        for claim in rep.get("claims") or []:
            for ev in claim.get("evidence") or []:
                if isinstance(ev, str):
                    ids.add(ev.strip())
        return ids

    unmatched: list[str] = []
    matched: set[int] = set()  # ids of report dicts that matched an incident
    for inc in incidents:
        inc_ids = {a for a in (inc.get("contributing_anomaly_ids") or []) if a}
        entity = str(inc.get("entity", ""))
        best = None
        best_score = -1
        for rep in reports:
            score = len(inc_ids & _report_evidence_ids(rep))
            if score == 0 and str(rep.get("entity", "")) == entity:
                score = 1  # entity fallback
            if score > best_score:
                best_score = score
                best = rep
        if best is not None and best_score > 0:
            resolved = resolve_report(best, inc)
            inc["supervisor_report"] = resolved
            inc["review_status"] = "ok"
            matched.add(id(best))
            inc["supervisor_report_meta"] = {
                "invalid_elements": len(meta["invalid"]),
                "parse_error": meta["parse_error"],
            }
        else:
            inc.pop("supervisor_report", None)
            inc["review_status"] = "invalid"
            inc["supervisor_report_meta"] = {
                "invalid_elements": len(meta["invalid"]),
                "parse_error": meta["parse_error"],
                "reason": "no valid report matched this incident",
            }

    for rep in reports:
        if id(rep) not in matched:
            unmatched.append(str(rep.get("entity", "?")))
    if unmatched:
        logger.info("Structured reports unmatched to any incident: %s", unmatched)
    if meta["invalid"]:
        logger.warning(
            "Structured report: %d invalid element(s), parse_error=%s",
            len(meta["invalid"]), meta["parse_error"],
        )
