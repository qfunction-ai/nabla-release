"""Pipeline API — trigger, monitor, and review pipeline runs."""

import asyncio
import json
import threading
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator

from nabla.auth import require_user
from nabla.config import get_settings
from nabla.log import get_logger
from nabla.rate_limit import limiter

logger = get_logger("api.pipeline")

router = APIRouter(prefix="/api/pipeline", tags=["pipeline"])

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class PipelineRunRequest(BaseModel):
    """Request body for triggering a pipeline run.

    Attributes:
        source: Ingestion source — auto, synthetic, splunk, sumologic, file.
        log_type: Log type(s) — auth, network, dns, endpoint, or all.
        log_count: Number of log entries per type (synthetic only).
        file: Path to uploaded log file (when source=file).
        format: File format hint — csv, json, jsonl, xml, text.
        map: Column mapping — canonical=raw_col,canonical2=raw_col2.
        watchlist_groups: Watchlist groups to target.
        update_baseline: Whether file-sourced runs should update baselines.
            Defaults to false — file uploads are ad-hoc analysis and shouldn't
            shift the baseline. Set to true for onboarding a new log source.
    """
    source: str = "auto"
    log_type: str = "all"
    log_count: int = 20
    file: str | None = None
    format: str | None = Field(None, alias="format")
    map: str | None = None
    watchlist_groups: list[str] = Field(default_factory=list)
    update_baseline: bool = False

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        """Validate ingestion source value."""
        allowed = {"auto", "synthetic", "splunk", "sumologic", "file"}
        if v not in allowed:
            raise ValueError(f"source must be one of {sorted(allowed)}, got '{v}'")
        return v

    @field_validator("file")
    @classmethod
    def validate_file(cls, v: str | None) -> str | None:
        """Restrict file paths to the uploads directory.

        Prevents path traversal: users can only reference files that
        were uploaded through /api/upload, not arbitrary paths like
        /app/nabla/config.py or /etc/passwd.
        """
        if v is None:
            return v
        from pathlib import Path
        from nabla.config import get_settings
        settings = get_settings()
        upload_dir = Path(settings.data_dir).joinpath("uploads").resolve()
        resolved = Path(v).resolve()
        if not str(resolved).startswith(str(upload_dir)):
            raise ValueError(
                f"file must be in the uploads directory ({upload_dir}), "
                f"got '{v}'"
            )
        return v

    @field_validator("log_type")
    @classmethod
    def validate_log_type(cls, v: str) -> str:
        """Validate log type value."""
        allowed = {"all", "auth", "network", "dns", "endpoint"}
        if v not in allowed:
            raise ValueError(f"log_type must be one of {sorted(allowed)}, got '{v}'")
        return v

    @field_validator("log_count")
    @classmethod
    def validate_log_count(cls, v: int) -> int:
        """Validate log count is positive."""
        if v < 1:
            raise ValueError("log_count must be >= 1")
        if v > 100_000:
            raise ValueError("log_count must be <= 100000")
        return v


class PipelineRunResponse(BaseModel):
    run_id: str


class PipelineStatus(BaseModel):
    running: bool
    run_id: str | None = None
    started_at: str | None = None
    current_step: str | None = None
    last_run: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Background pipeline state
# ---------------------------------------------------------------------------

_current_run: dict[str, Any] | None = None
_run_lock = threading.Lock()


def _get_last_run() -> dict[str, Any] | None:
    """Get the most recent completed run from history."""
    from nabla.history import list_runs
    runs = list_runs(limit=1)
    if runs:
        return runs[0]
    return None


def _run_pipeline_thread(run_id: str, request: PipelineRunRequest) -> None:
    """Execute the pipeline in a background thread.

    Args:
        run_id: Unique run identifier.
        request: Pipeline run parameters.
    """
    global _current_run

    from nabla.client import get_client
    from nabla.pipeline import run_pipeline

    # Parse column map if provided (format: "canonical=raw,canonical2=raw2")
    column_map = None
    if request.map:
        column_map = {}
        for pair in request.map.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                column_map[k.strip()] = v.strip()

    try:
        client = get_client()
        result = run_pipeline(
            client,
            log_types=request.log_type,
            log_count=request.log_count,
            source=request.source,
            file_path=request.file,
            file_format=request.format,
            column_map=column_map,
            watchlist_groups=request.watchlist_groups or None,
            update_baseline=request.update_baseline,
        )
        with _run_lock:
            if _current_run and _current_run.get("run_id") == run_id:
                _current_run["status"] = "completed"
                _current_run["result"] = "ok"
    except Exception as e:
        logger.error("Pipeline run %s failed: %s", run_id, e)
        with _run_lock:
            if _current_run and _current_run.get("run_id") == run_id:
                _current_run["status"] = "failed"
                _current_run["error"] = "Pipeline run failed — check server logs for details"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/run", response_model=PipelineRunResponse)
@limiter.limit("2/minute")
async def trigger_run(
    request: Request,
    body: PipelineRunRequest,
    _auth: None = Depends(require_user),
):
    """Trigger a pipeline run in the background.

    Returns immediately with a run_id. Check status via GET /api/pipeline/status.
    """
    global _current_run

    with _run_lock:
        if _current_run and _current_run.get("status") == "running":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A pipeline run is already in progress",
            )

        run_id = str(uuid.uuid4())[:8]
        _current_run = {
            "run_id": run_id,
            "status": "running",
            "started_at": time.monotonic(),
            "current_step": "starting",
            "request": body.model_dump(),
        }

    thread = threading.Thread(
        target=_run_pipeline_thread,
        args=(run_id, body),
        daemon=True,
    )
    thread.start()

    return PipelineRunResponse(run_id=run_id)


@router.get("/status", response_model=PipelineStatus)
async def get_status(_auth: None = Depends(require_user)):
    """Get current pipeline status — running or idle."""
    with _run_lock:
        if _current_run and _current_run.get("status") == "running":
            return PipelineStatus(
                running=True,
                run_id=_current_run["run_id"],
                started_at=str(_current_run.get("started_at")),
                current_step=_current_run.get("current_step"),
            )

    last_run = _get_last_run()
    return PipelineStatus(
        running=False,
        last_run=last_run,
    )


@router.get("/history")
async def get_history(
    limit: int = 20,
    offset: int = 0,
    _auth: None = Depends(require_user),
):
    """Get pipeline run history with pagination.

    Args:
        limit: Max runs to return.
        offset: Number of runs to skip.

    Returns:
        Dict with runs list and total count.
    """
    from nabla.history import list_runs
    # Load enough runs for pagination — don't load the entire history
    # into memory. The ceiling of 500 is generous for a single-page UI.
    max_load = max(limit + offset, 500)
    runs = list_runs(limit=max_load)

    total = len(runs)
    page = runs[offset:offset + limit]

    return {"runs": page, "total": total, "limit": limit, "offset": offset}


@router.get("/runs/{run_id}")
async def get_run_detail(
    run_id: str,
    _auth: None = Depends(require_user),
):
    """Get one run record with full detail (UI-4).

    Returns the persisted anomalies, findings summary, supervisor
    narrative, and step durations for the run detail view. Supports
    partial run_id match (first 8 chars), consistent with incidents.
    """
    from nabla.history import list_runs

    runs = list_runs(limit=500)
    run = next((r for r in runs if r.get("run_id", "").startswith(run_id)), None)
    if run is None:
        from fastapi import HTTPException, status as http_status
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail="Run not found",
        )
    return run


@router.post("/stream")
@limiter.limit("5/minute")
async def stream_pipeline(
    request: Request,
    _auth: None = Depends(require_user),
):
    """SSE stream for pipeline progress events.

    Emits step progress events while a pipeline is running.
    If no pipeline is running, emits a single idle event.
    """

    async def event_generator():
        with _run_lock:
            if not _current_run or _current_run.get("status") != "running":
                yield f"data: {json.dumps({'type': 'status', 'status': 'idle'})}\n\n"
                return

            run_id = _current_run["run_id"]

        yield f"data: {json.dumps({'type': 'status', 'status': 'running', 'run_id': run_id})}\n\n"

        # Poll for completion
        while True:
            await asyncio.sleep(1)
            with _run_lock:
                if _current_run and _current_run.get("run_id") == run_id:
                    run_status = _current_run.get("status")
                    current_step = _current_run.get("current_step", "")
                    if run_status == "running":
                        yield f"data: {json.dumps({'type': 'progress', 'step': current_step})}\n\n"
                    elif run_status == "completed":
                        yield f"data: {json.dumps({'type': 'status', 'status': 'completed', 'run_id': run_id})}\n\n"
                        break
                    elif run_status == "failed":
                        error = _current_run.get("error", "Unknown error")
                        yield f"data: {json.dumps({'type': 'error', 'error': error})}\n\n"
                        break
                    else:
                        break
                else:
                    break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
