"""Incidents API — CRUD for threat incident management."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from nabla.auth import require_user
from nabla.log import get_logger

logger = get_logger("api.incidents")

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


class IncidentUpdateRequest(BaseModel):
    """Request body for updating an incident.

    Attributes:
        status: New status — new, investigating, resolved, false_positive.
        notes: Operator notes to append.
    """
    status: Literal["new", "investigating", "resolved", "false_positive"] | None = None
    disposition: Literal["true_positive", "benign_true_positive", "false_positive"] | None = None
    notes: str | None = None


@router.get("")
async def list_incidents(
    status: Literal["new", "investigating", "resolved", "false_positive"] | None = None,
    disposition: Literal["true_positive", "benign_true_positive", "false_positive"] | None = None,
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    entity: str | None = None,
    run_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
    _auth: None = Depends(require_user),
):
    """List incidents with optional filters.

    Args:
        status: Filter by status — new, investigating, resolved, false_positive.
        severity: Filter by severity — low, medium, high, critical.
        entity: Filter by entity name (exact match) — supports process-typed
            incident groupings (UI-3).
        run_id: Filter by originating pipeline run (UI-3/UI-4).
        limit: Max incidents to return.
        offset: Number of incidents to skip.

    Returns:
        Dict with incidents list and total count.
    """
    from nabla.incidents import list_incidents as _list, incident_stats

    # Load enough incidents for pagination — don't load the entire history
    max_load = max(limit + offset, 500)
    incidents = _list(status=status, severity=severity, limit=max_load)
    if entity is not None:
        incidents = [i for i in incidents if i.get("entity") == entity]
    if run_id is not None:
        # Prefix match — consistent with run detail lookups (UI passes 8-char IDs)
        incidents = [i for i in incidents if str(i.get("run_id", "")).startswith(run_id)]
    total = len(incidents)
    page = incidents[offset:offset + limit]

    return {"incidents": page, "total": total, "limit": limit, "offset": offset}


@router.get("/stats")
async def get_incident_stats(_auth: None = Depends(require_user)):
    """Get incident counts by status and severity.

    Returns:
        Dict with by_status and by_severity counts.
    """
    from nabla.incidents import incident_stats
    return incident_stats()


@router.get("/{incident_id}")
async def get_incident(
    incident_id: str,
    _auth: None = Depends(require_user),
):
    """Get a single incident by ID.

    Args:
        incident_id: Incident UUID (supports partial match, first 8 chars).

    Returns:
        Incident dict with evidence, counterfactuals, and timeline.
    """
    from nabla.incidents import get_incident as _get

    incident = _get(incident_id)
    if incident is None:
        # Try partial match — limit to 200 to avoid full-table scan
        from nabla.incidents import list_incidents as _list
        all_incidents = _list(limit=200)
        matches = [i for i in all_incidents
                   if i.get("incident_id", "").startswith(incident_id)]
        if len(matches) == 1:
            incident = matches[0]
        elif len(matches) > 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Partial ID '{incident_id}' matches {len(matches)} incidents",
            )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    return incident


@router.put("/{incident_id}")
async def update_incident(
    incident_id: str,
    request: IncidentUpdateRequest,
    _auth: None = Depends(require_user),
):
    """Update an incident's status and/or append notes.

    Args:
        incident_id: Incident UUID.
        request: Update request with optional status and notes.

    Returns:
        Updated incident dict.
    """
    from nabla.incidents import update_incident as _update

    try:
        result = _update(incident_id, status=request.status, notes=request.notes,
                         disposition=request.disposition)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    return result
