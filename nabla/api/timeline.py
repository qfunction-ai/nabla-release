"""Timeline API — chronological event views for investigation.

Provides a timeline of security events (anomalies, incidents, risk score
changes) for a given entity, ordered by time. Used by the frontend
Timeline component for interactive investigation.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from nabla.auth import require_user
from nabla.config import get_settings
from nabla.log import get_logger

logger = get_logger("api.timeline")

router = APIRouter(prefix="/api/timeline", tags=["timeline"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TimelineEvent(BaseModel):
    """A single event on the timeline."""
    timestamp: str = Field(..., description="ISO timestamp")
    event_type: str = Field(..., description="anomaly, incident, or risk_change")
    severity: str = Field("medium", description="low, medium, high, critical")
    entity: str = Field("", description="Entity ID")
    entity_type: str = Field("user", description="user, host, ip")
    title: str = Field("", description="Short event description")
    details: str = Field("", description="Detailed event description")
    detection_method: str = Field("", description="Detection method for anomalies")
    categories: list[str] = Field(default_factory=list, description="Threat categories")
    risk_score: float = Field(0, description="Entity risk score at time of event")
    source: str = Field("", description="Source: anomaly, incident, risk")
    mitre_attack: list[dict] = Field(default_factory=list, description="MITRE ATT&CK mappings")


class TimelineResponse(BaseModel):
    """Paginated timeline response."""
    events: list[TimelineEvent]
    total: int
    entity: str
    entity_type: str
    earliest: str = ""
    latest: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/{entity_id}", response_model=TimelineResponse)
async def get_entity_timeline(
    entity_id: str,
    limit: int = 100,
    offset: int = 0,
    event_type: Literal["anomaly", "incident", "risk_change", "all"] = "all",
    _auth: Any = Depends(require_user),
) -> TimelineResponse:
    """Get the chronological event timeline for an entity.

    Combines anomalies, incidents, and risk score changes into a single
    timeline view, sorted chronologically.
    """
    settings = get_settings()
    events: list[TimelineEvent] = []

    # 1. Load anomalies from recent pipeline runs
    if event_type in ("anomaly", "all"):
        try:
            from nabla.history import list_runs
            runs = list_runs(limit=10)
            for run in runs:
                run_id = run.get("run_id", "")
                # Anomalies are stored in the run's anomaly list
                anomalies = run.get("anomalies", [])
                for a in anomalies:
                    if a.get("entity", a.get("user", "")) != entity_id:
                        continue
                    events.append(TimelineEvent(
                        timestamp=a.get("timestamp", a.get("detected_at", run.get("started_at", ""))),
                        event_type="anomaly",
                        severity=a.get("severity", "medium"),
                        entity=entity_id,
                        entity_type=a.get("entity_type", "user"),
                        title=f"{a.get('detection_method', a.get('type', 'unknown'))} detected",
                        details=a.get("details", a.get("description", "")),
                        detection_method=a.get("detection_method", a.get("type", "")),
                        categories=a.get("categories", []),
                        source="anomaly",
                        mitre_attack=a.get("mitre_attack", []),
                    ))
        except Exception as e:
            logger.warning("Failed to load anomalies for timeline: %s", e)

    # 2. Load incidents
    if event_type in ("incident", "all"):
        try:
            from nabla.incidents import load_incidents
            incidents = load_incidents(settings.incidents_file)
            for inc in incidents:
                involved = inc.get("entities", [])
                if entity_id not in involved and entity_id != inc.get("primary_entity", ""):
                    continue
                events.append(TimelineEvent(
                    timestamp=inc.get("created_at", inc.get("timestamp", "")),
                    event_type="incident",
                    severity=inc.get("severity", "medium"),
                    entity=entity_id,
                    entity_type=inc.get("entity_type", "user"),
                    title=f"Incident: {inc.get('title', 'Untitled')}",
                    details=inc.get("description", ""),
                    source="incident",
                ))
        except Exception as e:
            logger.warning("Failed to load incidents for timeline: %s", e)

    # 3. Load risk score changes
    if event_type in ("risk_change", "all"):
        try:
            from nabla.risk import EntityRiskStore
            risk_store = EntityRiskStore(settings.entity_risk_scores_file)
            score = risk_store.get(entity_id)
            if score:
                for ts, overall in score.score_history:
                    events.append(TimelineEvent(
                        timestamp=ts,
                        event_type="risk_change",
                        severity="critical" if overall >= 70 else "high" if overall >= 50 else "medium" if overall >= 20 else "low",
                        entity=entity_id,
                        entity_type=score.entity_type,
                        title=f"Risk score: {overall:.0f}",
                        details=f"Overall risk score changed to {overall:.0f}",
                        risk_score=overall,
                        source="risk",
                    ))
        except Exception as e:
            logger.warning("Failed to load risk history for timeline: %s", e)

    # Sort events by timestamp, newest first
    events.sort(key=lambda e: e.timestamp, reverse=True)

    # Apply pagination
    total = len(events)
    paginated = events[offset:offset + limit]

    # Determine entity type
    entity_type = "user"
    try:
        risk_store = EntityRiskStore(settings.entity_risk_scores_file)
        score = risk_store.get(entity_id)
        if score:
            entity_type = score.entity_type
    except Exception as e:
        logger.warning("risk score load failed (non-fatal): %s", e, exc_info=True)

    earliest = events[-1].timestamp if events else ""
    latest = events[0].timestamp if events else ""

    return TimelineResponse(
        events=paginated,
        total=total,
        entity=entity_id,
        entity_type=entity_type,
        earliest=earliest,
        latest=latest,
    )
