"""Incident persistence — durable store for threat findings.

Each finding from a pipeline run becomes an incident with a lifecycle:
  new → investigating → resolved / false_positive

Incidents are persisted to /data/incidents.json and survive across
pipeline runs. Deduplication prevents the same (entity, finding_type)
from creating duplicate active incidents on repeated runs.
"""

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from nabla.log import get_logger
from nabla.persistence import ensure_data_path, load_json_safe

logger = get_logger("incidents")

VALID_STATUSES = {"new", "investigating", "resolved", "false_positive"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}

# Active statuses — incidents with these won't be duplicated
_ACTIVE_STATUSES = {"new", "investigating"}


def _incidents_file() -> str | None:
    """Return the incidents file path, or None if the data dir is not writable.

    Returns:
        Path to incidents.json, or None on error.
    """
    from nabla.config import get_settings
    return ensure_data_path(get_settings().incidents_file)


def _load_incidents(path: str) -> list[dict[str, Any]]:
    """Load all incidents from the JSON file.

    Args:
        path: Path to incidents.json.

    Returns:
        List of incident dicts, or empty list on error.
    """
    return load_json_safe(path, default=[])



def _save_incidents(path: str, incidents: list[dict[str, Any]]) -> None:
    """Write incidents to the JSON file atomically.

    Args:
        path: Path to incidents.json.
        incidents: List of incident dicts.
    """
    from nabla.persistence import atomic_write_json
    try:
        atomic_write_json(path, incidents)
    except OSError:
        logger.warning("Cannot write incidents file %s (read-only data dir)", path)


def _extract_entity_evidence(evidence_text: str, entity: str) -> str:
    """Extract the evidence section for a specific entity.

    The evidence text from explain_findings() is structured per-entity
    with headers like '[user] admin_user:'. This extracts the section
    matching the given entity.

    Args:
        evidence_text: Full evidence text from explain_findings().
        entity: Entity name to extract evidence for.

    Returns:
        Evidence section for the entity, or empty string.
    """
    if not evidence_text:
        return ""
    # Match patterns like '[user] admin_user:' or '[ip] 10.0.1.55:'
    pattern = rf'\[\w+\]\s+{re.escape(entity)}:\s*\n(.*?)(?=\n\s*\[\w+\]\s+\S+:|\Z)'
    match = re.search(pattern, evidence_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return ""


def _build_finding_description(finding: dict[str, Any]) -> str:
    """Deterministic per-finding summary (UI2a item 3).

    The supervisor narrative is run-scoped; each incident gets its own
    one-paragraph 'why this is an incident' anchored in the finding data.
    """
    entity = finding.get("entity", "unknown")
    ftype = finding.get("type", "unknown").replace("_", " ")
    severity = finding.get("severity", "medium").upper()
    parts = [f"{severity}-severity {ftype} finding involving {entity}."]
    if finding.get("tools_detected"):
        parts.append(f"Tools identified: {', '.join(finding['tools_detected'])}.")
    if finding.get("mitre_attack"):
        techs = ", ".join(f"{t.get('id')} ({t.get('name')})" for t in finding["mitre_attack"][:4])
        parts.append(f"ATT&CK: {techs}.")
    parts.append(
        f"Correlation confidence {finding.get('confidence', 0.5):.0%} "
        f"across {', '.join(finding.get('log_types', [])) or 'n/a'} telemetry."
    )
    return " ".join(parts)


def _build_finding_evidence(
    finding: dict[str, Any], run_anomalies: list[dict[str, Any]]
) -> str:
    """Assemble per-finding evidence JSON from persisted run anomalies (UI2a).

    Findings discard anomaly dicts downstream of correlation, but the run
    record persists them (UI-2). Join by entity + finding-type methods.
    """
    import json as _json

    entity = finding.get("entity", "unknown")
    methods = set()
    for t in finding.get("type", "").split(","):
        t = t.strip().replace(" ", "_")
        if t:
            methods.add(t)
    # Also accept the method-name fragments of composite types
    matching = []
    for a in run_anomalies or []:
        if a.get("entity", a.get("user", "")) != entity:
            continue
        m = a.get("detection_method", a.get("type", ""))
        if methods and m not in methods and m.replace("-", "_") not in methods:
            continue
        matching.append(a)
    matching = matching[:25]  # bound

    payload = {
        "anomaly_count": len(matching),
        "anomalies": [
            {
                "anomaly_id": a.get("anomaly_id", ""),
                "method": a.get("detection_method", a.get("type", "")),
                "severity": a.get("severity", "medium"),
                "timestamp": a.get("timestamp", ""),
                "details": a.get("details", ""),
                "mitre": [t if isinstance(t, str) else t.get("id", "") for t in a.get("mitre_attack", [])],
            }
            for a in matching
        ],
        "correlation_score": finding.get("confidence", 0.5),
        "log_types": finding.get("log_types", []),
    }
    return _json.dumps(payload, indent=2)


def _load_run_anomalies(run_id: str) -> list[dict[str, Any]]:
    """Load the persisted anomaly list for a run (empty for old runs)."""
    try:
        from nabla.history import list_runs
        for run in list_runs(limit=50):
            if run.get("run_id", "").startswith(run_id[:8] if run_id else ""):
                return run.get("anomalies", []) or []
    except Exception as e:
        logger.warning("Run anomaly join failed for %s: %s", run_id, e)
    return []


def save_incidents(
    run_id: str,
    findings: list[dict[str, Any]],
    supervisor_text: str = "",
    evidence_text: str = "",
) -> int:
    """Create incidents from pipeline findings.

    Deduplicates against existing active incidents with the same
    (entity, finding_type). Active incidents get their updated_at
    refreshed and MITRE techniques merged instead of creating
    duplicates.

    Args:
        run_id: UUID of the pipeline run.
        findings: List of finding dicts from assess_findings().
        supervisor_text: Supervisor agent's review text.
        evidence_text: Evidence trace text from explain_findings().

    Returns:
        Number of new incidents created (not counting dedup updates).
    """
    from nabla.persistence import file_lock

    path = _incidents_file()
    if path is None:
        return 0

    now = datetime.now(timezone.utc).isoformat()
    new_count = 0
    run_anomalies = _load_run_anomalies(run_id)

    with file_lock(path):
        incidents = _load_incidents(path)

        # Build lookup of active incidents by (entity, finding_type)
        active_keys: dict[tuple[str, str], dict[str, Any]] = {}
        for inc in incidents:
            if inc.get("status") in _ACTIVE_STATUSES:
                key = (inc.get("entity", ""), inc.get("finding_type", ""))
                active_keys[key] = inc

        for finding in findings:
            entity = finding.get("entity", "unknown")
            finding_type = finding.get("type", "unknown")
            key = (entity, finding_type)

            if key in active_keys:
                # Deduplicate: update existing active incident
                existing = active_keys[key]
                existing["updated_at"] = now
                existing["run_id"] = run_id
                # Merge MITRE techniques
                existing_techniques = {
                    t.get("id"): t
                    for t in existing.get("mitre_attack", [])
                }
                for tech in finding.get("mitre_attack", []):
                    existing_techniques.setdefault(tech.get("id"), tech)
                existing["mitre_attack"] = list(existing_techniques.values())
                # Update severity if escalated
                new_sev = finding.get("severity", "medium")
                old_sev = existing.get("severity", "medium")
                if VALID_SEVERITIES.intersection({new_sev, old_sev}):
                    from nabla.utils import SEVERITY_ORDER
                    if SEVERITY_ORDER.get(new_sev, 2) < SEVERITY_ORDER.get(old_sev, 2):
                        existing["severity"] = new_sev
                # Update confidence if higher
                new_conf = finding.get("confidence", 0.5)
                old_conf = existing.get("confidence", 0.5)
                if new_conf > old_conf:
                    existing["confidence"] = new_conf
                # Update supervisor review
                if supervisor_text:
                    existing["supervisor_review"] = supervisor_text
                # Update evidence (explain-layer first, run-anomaly join as fallback)
                entity_evidence = _extract_entity_evidence(evidence_text, entity)
                if entity_evidence:
                    existing["evidence"] = entity_evidence
                else:
                    joined = _build_finding_evidence(finding, run_anomalies)
                    if joined and json.loads(joined)["anomaly_count"] > 0:
                        existing["evidence"] = joined
                if not existing.get("description"):
                    existing["description"] = _build_finding_description(finding)
                continue

            # New incident
            # R8 (round 3): per-FINDING scope — dispositions label only the
            # anomalies this finding rests on (its constituent methods), not
            # everything the entity did that run
            _finding_methods = {
                m.strip()
                for m in str(finding.get("finding_type", "")).split(",")
                if m.strip()
            } | {str(finding.get("finding_type", "")).strip()}
            entity_evidence = _extract_entity_evidence(evidence_text, entity)
            if not entity_evidence:
                joined = _build_finding_evidence(finding, run_anomalies)
                if joined and json.loads(joined)["anomaly_count"] > 0:
                    entity_evidence = joined
            incident = {
                "incident_id": str(uuid.uuid4()),
                "run_id": run_id,
                "created_at": now,
                "updated_at": now,
                "status": "new",
                "severity": finding.get("severity", "medium"),
                "entity": entity,
                "entity_type": finding.get("entity_type", "unknown"),
                "finding_type": finding_type,
                "cross_type": finding.get("cross_type", "single-type"),
                "log_types": finding.get("log_types", []),
                "confidence": finding.get("confidence", 0.5),
                "mitre_attack": finding.get("mitre_attack", []),
                "tools_detected": finding.get("tools_detected"),
                "supervisor_review": supervisor_text,
                "description": _build_finding_description(finding),
                "evidence": entity_evidence,
                # Phase 2/3 (remediation plan): contributing anomaly IDs + the
                # thresholds snapshot in effect at creation — the label
                # pipeline keys dispositions against these.
                "contributing_anomaly_ids": [
                    a.get("anomaly_id", "")
                    for a in (run_anomalies or [])
                    if a.get("entity", a.get("user")) == entity
                    and (a.get("detection_method") in _finding_methods
                         or a.get("type") in _finding_methods)
                ][:20],
                # Phase 3: creation-time snapshot — the label pipeline needs
                # each anomaly's method, raw score, and the threshold that
                # was in effect when it fired (not reconstructable later).
                "contributing_anomaly_details": [
                    {
                        "anomaly_id": a.get("anomaly_id", ""),
                        "method": a.get("detection_method", a.get("type", "")),
                        "raw_score": a.get("raw_score"),
                        "threshold_in_effect": _threshold_in_effect_for(a),
                    }
                    for a in (run_anomalies or [])
                    if a.get("entity", a.get("user")) == entity
                ][:20],
                "operator_notes": "",
            }
            incidents.append(incident)
            active_keys[key] = incident
            new_count += 1

        _save_incidents(path, incidents)

    if new_count > 0:
        logger.info("Saved %d new incidents (%d findings, %d deduped)",
                    new_count, len(findings), len(findings) - new_count)
    return new_count


def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Return incidents, newest first, with optional filtering.

    Args:
        status: Filter by status (new, investigating, resolved, false_positive).
        severity: Filter by severity (low, medium, high, critical).
        limit: Maximum number of incidents to return.

    Returns:
        List of incident dicts, newest first.
    """
    path = _incidents_file()
    if path is None:
        return []
    incidents = _load_incidents(path)
    if status:
        incidents = [i for i in incidents if i.get("status") == status]
    if severity:
        incidents = [i for i in incidents if i.get("severity") == severity]
    return list(reversed(incidents))[:limit]


def get_incident(incident_id: str) -> dict[str, Any] | None:
    """Return a single incident by ID.

    Args:
        incident_id: UUID of the incident.

    Returns:
        Incident dict, or None if not found.
    """
    path = _incidents_file()
    if path is None:
        return None
    for inc in _load_incidents(path):
        if inc.get("incident_id") == incident_id:
            return inc
    return None


def update_incident(
    incident_id: str,
    status: str | None = None,
    notes: str | None = None,
    disposition: str | None = None,
) -> dict[str, Any] | None:
    """Update an incident's status, notes, and/or disposition label.

    Args:
        incident_id: UUID of the incident.
        status: New status (must be in VALID_STATUSES).
        notes: Operator notes to append (newline-separated from existing).
        disposition: Calibration label — true_positive, benign_true_positive,
            or false_positive (Phase 3). Writes feedback records per
            contributing anomaly (keyed anomaly_id, last-wins).

    Returns:
        Updated incident dict, or None if not found.

    Raises:
        ValueError: If status is not valid.
    """
    from nabla.persistence import file_lock

    if status and status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(sorted(VALID_STATUSES))}")
    if disposition and disposition not in VALID_DISPOSITIONS:
        raise ValueError(f"Invalid disposition '{disposition}'. Must be one of: {', '.join(sorted(VALID_DISPOSITIONS))}")

    path = _incidents_file()
    if path is None:
        return None

    with file_lock(path):
        incidents = _load_incidents(path)
        found = None
        for inc in incidents:
            if inc.get("incident_id") == incident_id:
                found = inc
                break

        if found is None:
            return None

        now = datetime.now(timezone.utc).isoformat()
        found["updated_at"] = now
        if status:
            found["status"] = status
            # Compat mapping ONLY where the status string literally names
            # the label (review STRONG 1). resolved sets NO disposition.
            if status == "false_positive" and not found.get("disposition"):
                _apply_disposition(found, "false_positive", now)
        if disposition:
            _apply_disposition(found, disposition, now)
        if notes is not None:
            existing = found.get("operator_notes", "")
            if existing:
                found["operator_notes"] = existing + "\n" + notes
            else:
                found["operator_notes"] = notes

        _save_incidents(path, incidents)
        return found


VALID_DISPOSITIONS = {"true_positive", "benign_true_positive", "false_positive"}


def _threshold_in_effect_for(anomaly: dict) -> float | None:
    """The calibrated value of the anomaly's method's threshold at fire time."""
    try:
        from nabla.rl.calibration import METHOD_TO_THRESHOLD, effective_thresholds
        tname = METHOD_TO_THRESHOLD.get(anomaly.get("detection_method", ""))
        if not tname:
            return None
        return effective_thresholds().get(tname)
    except Exception:
        return None


def _apply_disposition(incident: dict, disposition: str, now: str) -> None:
    """Set the label and emit feedback records per contributing anomaly
    (Phase 3): keyed anomaly_id, creation-time score/threshold snapshot,
    written to the feedback store (last-wins)."""
    incident["disposition"] = disposition
    incident["disposition_at"] = now

    # A10 truth table: FP/BTP release the entity's baseline quarantine;
    # TP holds it (confirmed attack never enters baselines)
    try:
        from nabla.baselines import apply_disposition_to_quarantine, EntityProfileStore
        try:
            from nabla.config import get_settings as _gs
            pstore = EntityProfileStore(_gs().entity_profiles_file)
        except Exception:
            pstore = None
        apply_disposition_to_quarantine(incident.get("entity", ""), disposition,
                                         profile_store=pstore)
    except Exception as e:
        logger.warning("Quarantine disposition failed (non-fatal): %s", e)

    from nabla.rl.calibration import write_labels
    snapshot = incident.get("contributing_anomaly_details") or []
    by_id = {a.get("anomaly_id"): a for a in snapshot if isinstance(a, dict)}
    records = []
    for aid in incident.get("contributing_anomaly_ids", []):
        if not aid:
            continue
        detail = by_id.get(aid, {})
        records.append({
            "anomaly_id": aid,
            "entity": incident.get("entity", ""),
            "detection_method": detail.get("method", ""),
            "raw_score": detail.get("raw_score"),
            "threshold_in_effect": detail.get("threshold_in_effect"),
            "disposition": disposition,
            "disposition_at": now,
            "incident_id": incident.get("incident_id", ""),
            "run_id": incident.get("run_id", ""),
            "supervisor_hint": None,
        })
    if records:
        write_labels(records)


def incident_stats() -> dict[str, Any]:
    """Return counts of incidents by status and severity.

    Returns:
        Dict with 'by_status' and 'by_severity' sub-dicts.
    """
    path = _incidents_file()
    if path is None:
        return {"by_status": {}, "by_severity": {}, "total": 0}
    incidents = _load_incidents(path)

    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for inc in incidents:
        s = inc.get("status", "new")
        by_status[s] = by_status.get(s, 0) + 1
        sev = inc.get("severity", "medium")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "by_status": by_status,
        "by_severity": by_severity,
        "total": len(incidents),
    }
