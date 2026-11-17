"""Dashboard API — system overview for the web UI."""

import asyncio
from typing import Any

from fastapi import APIRouter, Depends

from nabla.auth import require_user
from nabla.log import get_logger

logger = get_logger("api.dashboard")

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


async def _check_letta_health() -> dict[str, Any]:
    """Check Letta server connectivity.

    Returns:
        Dict with healthy: bool and optional detail.
    """
    try:
        from nabla.client import get_client
        client = get_client()
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(None, client.health)
        if resp.status == "ok":
            return {"healthy": True, "detail": f"v{resp.version}"}
        return {"healthy": False, "detail": f"status={resp.status}"}
    except Exception:
        return {"healthy": False, "detail": "unreachable"}


async def _check_ollama_health() -> dict[str, Any]:
    """Check Ollama connectivity.

    Returns:
        Dict with healthy: bool and optional detail.
    """
    try:
        import httpx
        from nabla.config import get_settings
        settings = get_settings()
        # Ollama is typically at host.docker.internal:11434 inside Docker
        base = settings.embedding_endpoint.replace("/v1", "")
        url = base + "/api/tags"
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
        if resp.status_code == 200:
            return {"healthy": True}
        return {"healthy": False, "detail": f"HTTP {resp.status_code}"}
    except Exception:
        return {"healthy": False, "detail": "unreachable"}


@router.get("")
async def get_dashboard(_auth: None = Depends(require_user)):
    """Get dashboard overview data.

    Returns:
        Dict with system phase, health checks, entity counts,
        incident counts, and recent runs/incidents.
    """
    from nabla.config import get_settings
    from nabla.incidents import incident_stats, list_incidents
    from nabla.history import list_runs
    from nabla.system_state import load_system_state, baseline_days_remaining, warm_up_summary
    from nabla.baselines import EntityProfileStore

    settings = get_settings()

    # System state
    sys_state = load_system_state(settings.system_state_file)
    phase = sys_state.get("phase", "detection")
    days_remaining = baseline_days_remaining(sys_state)

    # Entity profiles
    try:
        profiles = EntityProfileStore(settings.entity_profiles_file)
        entity_counts = {
            "users": len(profiles.users),
            "hosts": len(profiles.hosts),
            "ips": len(profiles.ips),
        }
        warm_up = warm_up_summary(profiles)
    except Exception:
        entity_counts = {"users": 0, "hosts": 0, "ips": 0}
        warm_up = {"users": {"total": 0, "warm": 0, "pct": 0},
                   "hosts": {"total": 0, "warm": 0, "pct": 0},
                   "ips": {"total": 0, "warm": 0, "pct": 0},
                   "min_observations": 3}

    # Health checks — run concurrently to avoid blocking
    letta_health, ollama_health = await asyncio.gather(
        _check_letta_health(), _check_ollama_health(),
    )

    # Incident stats
    stats = incident_stats()

    # Recent runs and incidents
    recent_runs = list_runs(limit=5)
    recent_incidents = list_incidents(limit=5)

    # Top risky entities
    top_risky = []
    try:
        from nabla.risk import EntityRiskStore, get_trend_label
        risk_store = EntityRiskStore(settings.entity_risk_scores_file)
        for rs in risk_store.top_risky(limit=10):
            top_risky.append({
                "entity_id": rs.entity_id,
                "entity_type": rs.entity_type,
                "overall": round(rs.overall, 1),
                "categories": {k: round(v, 1) for k, v in rs.categories.items()},
                "trend": round(rs.trend, 3),
                "trend_label": get_trend_label(rs.trend),
                "peak": round(rs.peak, 1),
            })
    except Exception as e:
        logger.warning("risk score load failed (non-fatal): %s", e, exc_info=True)

    return {
        "phase": phase,
        "days_remaining": days_remaining,
        "warm_up": warm_up,
        "entity_counts": entity_counts,
        "health": {
            "letta": letta_health,
            "ollama": ollama_health,
        },
        "incident_stats": stats,
        "recent_runs": recent_runs,
        "recent_incidents": recent_incidents,
        "top_risky": top_risky,
    }
