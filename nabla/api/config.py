"""Config API — watchlists, environment context, schedule, connectors."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from nabla.auth import require_user
from nabla.log import get_logger

logger = get_logger("api.config")

router = APIRouter(prefix="/api/config", tags=["config"])


# ---------------------------------------------------------------------------
# Watchlists
# ---------------------------------------------------------------------------

@router.get("/watchlists")
async def get_watchlists(_auth: None = Depends(require_user)):
    """Read current watchlist configuration.

    Returns:
        Dict of group_name → entity list.
    """
    from nabla.config import get_settings
    from nabla.watchlist import get_all_entities
    settings = get_settings()
    return get_all_entities(settings.effective_watchlist_path)


class WatchlistUpdate(BaseModel):
    """Full watchlist replacement.

    Attributes:
        groups: Dict of group_name → entity list.
    """
    groups: dict[str, list[str]]


@router.put("/watchlists")
async def update_watchlists(
    request: WatchlistUpdate,
    _auth: None = Depends(require_user),
):
    """Replace watchlist configuration.

    Validates all entity values before saving.
    """
    from nabla.config import get_settings
    from nabla.watchlist import validate_entity, save_watchlist
    settings = get_settings()
    watchlist_path = settings.effective_watchlist_path

    # Validate all entities
    errors = []
    for group, entities in request.groups.items():
        for entity in entities:
            err = validate_entity(entity, group)
            if err:
                errors.append(f"{group}/{entity}: {err}")

    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Validation errors: {'; '.join(errors[:5])}",
        )

    save_watchlist(watchlist_path, request.groups)
    return request.groups


# ---------------------------------------------------------------------------
# Environment Context
# ---------------------------------------------------------------------------

@router.get("/environment")
async def get_environment(_auth: None = Depends(require_user)):
    """Read full environment context.

    Returns the three-section structure:
    - environment: immutable user-declared facts
    - entities: immutable per-entity facts
    - network_ranges, new_accounts, service_accounts, admin_accounts,
      benign_patterns: mutable state (auto-detected + user-declared)
    """
    from nabla.config import get_settings
    from nabla.pipeline import _load_environment_context
    settings = get_settings()
    ctx = _load_environment_context(settings.effective_env_context_path)

    # Convert sets to sorted lists for JSON serialization
    result = {
        "environment": ctx.get("environment", []),
        "entities": ctx.get("entities", {}),
        "network_ranges": ctx.get("network_ranges", []),
        "new_accounts": sorted(ctx.get("new_accounts", set())),
        "service_accounts": sorted(ctx.get("service_accounts", set())),
        "admin_accounts": sorted(ctx.get("admin_accounts", set())),
        "benign_patterns": ctx.get("benign_patterns", []),
    }
    return result


class EnvironmentUpdate(BaseModel):
    """Environment context update.

    Attributes:
        environment: List of free-form environment facts.
        entities: Dict of entity_name → list of facts.
        network_ranges: List of CIDR network ranges.
        new_accounts: List of new account names.
        service_accounts: List of service account names.
        admin_accounts: List of admin account names.
        benign_patterns: List of benign pattern descriptions.
    """
    environment: list[str] = Field(default_factory=list)
    entities: dict[str, list[str]] = Field(default_factory=dict)
    network_ranges: list[str] = Field(default_factory=list)
    new_accounts: list[str] = Field(default_factory=list)
    service_accounts: list[str] = Field(default_factory=list)
    admin_accounts: list[str] = Field(default_factory=list)
    benign_patterns: list[str] = Field(default_factory=list)


@router.put("/environment")
async def update_environment(
    request: EnvironmentUpdate,
    _auth: None = Depends(require_user),
):
    """Update environment context.

    Only writes to the file — mutable state (auto-detected ranges,
    new accounts with timestamps) is re-derived on the next pipeline run.
    """
    from nabla.config import get_settings
    from nabla.watchlist import _DANGEROUS_CHARS

    # Validate entity values for dangerous characters
    for entity_name, facts in request.entities.items():
        dangerous = _DANGEROUS_CHARS.intersection(entity_name)
        if dangerous:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Entity name '{entity_name}' contains dangerous characters",
            )

    settings = get_settings()
    data = {
        "environment": request.environment,
        "entities": request.entities,
        "network_ranges": request.network_ranges,
        "new_accounts": request.new_accounts,
        "service_accounts": request.service_accounts,
        "admin_accounts": request.admin_accounts,
        "benign_patterns": request.benign_patterns,
    }

    path = settings.effective_env_context_path
    from nabla.persistence import atomic_write_json
    try:
        atomic_write_json(path, data)
    except OSError as e:
        from nabla.safe_error import safe_error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=safe_error(e, "Environment context write"),
        )

    return data


# ---------------------------------------------------------------------------
# Schedule
# ---------------------------------------------------------------------------

@router.get("/schedule")
async def get_schedule(_auth: None = Depends(require_user)):
    """Get current scheduler configuration and status.

    Returns:
        Dict with running status, interval, log types, log count,
        next run time.
    """
    from nabla.scheduler import scheduler_status
    from nabla.config import get_settings
    settings = get_settings()

    status_data = scheduler_status()
    return {
        "running": status_data.get("running", False),
        "next_run": status_data.get("next_run"),
        "interval": settings.schedule_interval_minutes,
        "log_types": settings.schedule_log_types,
        "log_count": settings.schedule_log_count,
    }


class ScheduleUpdate(BaseModel):
    """Schedule configuration update.

    Attributes:
        enabled: Start or stop the scheduler.
        interval: Interval in minutes between pipeline runs.
        log_types: Comma-separated log types.
        log_count: Number of log entries per type.
    """
    enabled: bool = True
    interval: int = 5
    log_types: str = "all"
    log_count: int = 50

    @field_validator("interval")
    @classmethod
    def validate_interval(cls, v: int) -> int:
        """Interval must be at least 1 minute."""
        if v < 1:
            raise ValueError("interval must be >= 1 minute")
        if v > 1440:
            raise ValueError("interval must be <= 1440 minutes (24 hours)")
        return v

    @field_validator("log_count")
    @classmethod
    def validate_log_count(cls, v: int) -> int:
        """Log count must be positive."""
        if v < 1:
            raise ValueError("log_count must be >= 1")
        if v > 100_000:
            raise ValueError("log_count must be <= 100000")
        return v


@router.put("/schedule")
async def update_schedule(
    request: ScheduleUpdate,
    _auth: None = Depends(require_user),
):
    """Update scheduler configuration.

    Starts or stops the scheduler and changes parameters.
    """
    from nabla.scheduler import start_scheduler, stop_scheduler
    from nabla.pipeline import _resolve_log_types

    if not request.enabled:
        stop_scheduler()
        return {"running": False, "interval": request.interval,
                "log_types": request.log_types, "log_count": request.log_count}

    log_types = _resolve_log_types(request.log_types)
    start_scheduler(
        interval_minutes=request.interval,
        log_types=log_types,
        log_count=request.log_count,
    )

    return {
        "running": True,
        "interval": request.interval,
        "log_types": request.log_types,
        "log_count": request.log_count,
    }


# ---------------------------------------------------------------------------
# Connectors
# ---------------------------------------------------------------------------

@router.get("/connectors")
async def get_connectors(_auth: None = Depends(require_user)):
    """Get connector status — which SIEM connectors are configured.

    Returns:
        Dict with splunk and sumologic status.
    """
    from nabla.config import get_settings
    settings = get_settings()

    splunk_configured = bool(settings.splunk_host)
    sumologic_configured = bool(settings.sumologic_host)

    # Check last ingestion from ingestion state
    last_ingestion = {}
    try:
        from nabla.ingestion_state import load_state
        state = load_state(settings.effective_ingestion_state_path)
        for source in ["splunk", "sumologic"]:
            for log_type in ["auth", "endpoint"]:
                key = f"{source}_{log_type}"
                ts = state.get(key, {}).get("last_ingested")
                if ts:
                    last_ingestion[key] = ts
    except Exception as e:
        logger.warning("config load failed (non-fatal): %s", e, exc_info=True)

    return {
        "splunk": {
            "configured": splunk_configured,
            "last_ingestion": {k: v for k, v in last_ingestion.items() if k.startswith("splunk")},
        },
        "sumologic": {
            "configured": sumologic_configured,
            "last_ingestion": {k: v for k, v in last_ingestion.items() if k.startswith("sumologic")},
        },
    }
