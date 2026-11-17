"""Entities API — browse and inspect entity behavioral profiles."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from nabla.auth import require_user
from nabla.log import get_logger

logger = get_logger("api.entities")

router = APIRouter(prefix="/api/entities", tags=["entities"])


def _load_profiles():
    """Load entity profiles from file.

    Returns:
        EntityProfileStore instance.
    """
    from nabla.baselines import EntityProfileStore
    from nabla.config import get_settings
    settings = get_settings()
    return EntityProfileStore(settings.entity_profiles_file)


def _load_env_context() -> dict[str, Any]:
    """Load environment context for entity facts.

    Returns:
        Dict with environment, entities, network_ranges, etc.
    """
    from nabla.config import get_settings
    from nabla.pipeline import _load_environment_context
    settings = get_settings()
    return _load_environment_context(settings.effective_env_context_path)


@router.get("")
async def list_entities(
    type: str | None = None,
    search: str | None = None,
    warm: bool | None = None,
    limit: int = 50,
    offset: int = 0,
    _auth: None = Depends(require_user),
):
    """List all known entities with summary profiles.

    Args:
        type: Filter by entity type — user, host, or ip.
        search: Search entity IDs (case-insensitive substring).
        warm: Filter by warm-up status (true=warm, false=cold).
        limit: Max entities to return.
        offset: Number of entities to skip.

    Returns:
        Dict with entities list and total count.
    """
    try:
        profiles = _load_profiles()
    except Exception:
        return {"entities": [], "total": 0, "limit": limit, "offset": offset}

    min_obs = 3  # Default warm-up threshold
    entities = []

    # Load risk scores for all entities
    risk_map: dict[str, float] = {}
    try:
        from nabla.config import get_settings
        from nabla.risk import EntityRiskStore
        risk_store = EntityRiskStore(get_settings().entity_risk_scores_file)
        for eid, rs in risk_store.scores.items():
            risk_map[eid] = rs.overall
    except Exception:
        logger.warning("Entity list: risk score load failed", exc_info=True)

    # Collect entities — loop over types instead of 3 near-identical blocks
    for etype, profile_dict in [("user", profiles.users), ("host", profiles.hosts), ("ip", profiles.ips)]:
        if type is not None and type != etype:
            continue
        for eid, profile in profile_dict.items():
            if search and search.lower() not in eid.lower():
                continue
            is_warm = profile.observation_count >= min_obs
            if warm is not None and warm != is_warm:
                continue
            entity = {
                "id": eid,
                "type": etype,
                "observation_count": profile.observation_count,
                "first_seen": profile.first_seen,
                "last_seen": profile.last_seen,
                "warm": is_warm,
                "risk_score": risk_map.get(eid, 0),
            }
            # User-specific extra field
            if etype == "user" and hasattr(profile, "account_created_at"):
                entity["account_created_at"] = profile.account_created_at or None
            entities.append(entity)

    total = len(entities)
    page = entities[offset:offset + limit]

    return {"entities": page, "total": total, "limit": limit, "offset": offset}


@router.get("/{entity_id:path}/attribution")
async def get_entity_attribution(
    entity_id: str,
    runs: int = 20,
    _auth: None = Depends(require_user),
):
    """Assemble the 'why this risk score' view for one entity.

    Combines: recent anomalies for this entity (from persisted run
    records — newest `runs` runs), incidents for this entity, and the
    risk-category breakdown from the risk store. One call, one story.
    """
    from nabla.history import list_runs

    # 1. Anomalies from recent runs (bounded scan: newest `runs` runs
    # over the 200-run history cap)
    anomalies = []
    scan_runs = list_runs(limit=max(1, min(runs, 200)))
    for run in scan_runs:
        for a in run.get("anomalies", []) or []:
            if a.get("entity", a.get("user", "")) == entity_id:
                anomalies.append({
                    "run_id": run.get("run_id", ""),
                    "timestamp": a.get("timestamp", run.get("started_at", "")),
                    "detection_method": a.get("detection_method", a.get("type", "")),
                    "severity": a.get("severity", "medium"),
                    "details": a.get("details", ""),
                    "categories": a.get("categories", []),
                    "mitre_attack": a.get("mitre_attack", []),
                })
    anomalies.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    anomalies = anomalies[:100]

    # 2. Incidents involving this entity
    incidents = []
    try:
        from nabla.incidents import list_incidents
        for inc in list_incidents(limit=500):
            if inc.get("entity") == entity_id:
                incidents.append({
                    "incident_id": inc.get("incident_id", ""),
                    "finding_type": inc.get("finding_type", ""),
                    "severity": inc.get("severity", ""),
                    "status": inc.get("status", ""),
                    "updated_at": inc.get("updated_at", ""),
                })
    except Exception as e:
        logger.warning("Attribution: incident load failed: %s", e)

    # 3. Risk category breakdown
    risk = None
    try:
        from nabla.risk import EntityRiskStore
        from nabla.config import get_settings
        store = EntityRiskStore(get_settings().entity_risk_scores_file)
        rs = store.scores.get(entity_id)
        if rs is not None:
            risk = {
                "overall": round(rs.overall, 1),
                "peak": round(rs.peak, 1),
                "trend": round(rs.trend, 3),
                "trend_label": _trend_label(rs.trend),
                "categories": {k: round(v, 1) for k, v in rs.categories.items() if v > 0},
            }
    except Exception as e:
        logger.warning("Attribution: risk load failed: %s", e)

    return {
        "entity_id": entity_id,
        "anomalies": anomalies,
        "incidents": incidents,
        "risk": risk,
        "runs_scanned": len(scan_runs),
    }


def _trend_label(trend: float) -> str:
    if trend > 0.5:
        return "rising"
    if trend < -0.5:
        return "falling"
    return "stable"


@router.put("/{entity_id:path}/context")
async def update_entity_context(
    entity_id: str,
    body: dict,
    _auth: None = Depends(require_user),
):
    """Add, update, or remove facts for a single entity's context.

    Body: {"facts": ["...", "..."]} — replaces the entity's fact list.
    An empty list removes the entity from the context document.
    """
    facts = body.get("facts")
    if not isinstance(facts, list) or any(not isinstance(f, str) or not f.strip() for f in facts):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="facts must be a list of non-empty strings",
        )
    if len(facts) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="too many facts (max 50)",
        )

    from nabla.config import get_settings
    from nabla.persistence import atomic_write_json, load_json_safe

    settings = get_settings()
    path = settings.effective_env_context_path
    doc = load_json_safe(path, default={
        "environment": [], "entities": {}, "network_ranges": [],
        "new_accounts": [], "service_accounts": [], "admin_accounts": [],
        "benign_patterns": [],
    })
    entities = doc.setdefault("entities", {})
    if facts:
        entities[entity_id] = [f.strip() for f in facts]
    else:
        entities.pop(entity_id, None)
    try:
        atomic_write_json(path, doc)
    except OSError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist context: {e}",
        )
    return {"entity_id": entity_id, "facts": entities.get(entity_id, [])}


@router.get("/{entity_id:path}")
async def get_entity(
    entity_id: str,
    _auth: None = Depends(require_user),
):
    """Get full entity profile detail.

    Args:
        entity_id: Entity identifier (username, hostname, or IP).

    Returns:
        Full entity profile with EWMA values, typical behavior,
        and environment context facts.
    """
    try:
        profiles = _load_profiles()
    except Exception:
        raise HTTPException(status_code=503, detail="Entity profiles not available")

    # Try each entity type
    profile = profiles.get_user(entity_id)
    entity_type = "user"
    if profile is None:
        profile = profiles.get_host(entity_id)
        entity_type = "host"
    if profile is None:
        profile = profiles.get_ip(entity_id)
        entity_type = "ip"
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entity '{entity_id}' not found",
        )

    result = profile.to_dict()
    result["type"] = entity_type
    result["warm"] = profile.observation_count >= 3

    # Attach risk score
    try:
        from nabla.risk import EntityRiskStore, get_trend_label
        from nabla.config import get_settings
        risk_store = EntityRiskStore(get_settings().entity_risk_scores_file)
        risk = risk_store.get(entity_id)
        if risk:
            result["risk_score"] = risk.to_dict()
            result["risk_score"]["trend_label"] = get_trend_label(risk.trend)
        else:
            result["risk_score"] = {"overall": 0, "categories": {}, "trend_label": "stable"}
    except Exception:
        result["risk_score"] = {"overall": 0, "categories": {}, "trend_label": "stable"}

    # Attach peer group
    try:
        from nabla.peer_groups import PeerGroupStore
        pg_store = PeerGroupStore(get_settings().entity_risk_scores_file.replace("risk_scores", "peer_groups"))
        pg = pg_store.get_group_for_entity(entity_id)
        if pg:
            result["peer_group"] = {
                "group_id": pg.group_id,
                "label": pg.label,
                "members": pg.members,
                "centroid": pg.centroid,
            }
        else:
            result["peer_group"] = None
    except Exception:
        result["peer_group"] = None

    # Attach environment context facts for this entity
    try:
        env_ctx = _load_env_context()
        entity_facts = env_ctx.get("entities", {})
        result["environment_facts"] = entity_facts.get(entity_id, [])
    except Exception:
        result["environment_facts"] = []

    return result
