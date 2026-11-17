"""System API — bootstrap, teardown, health, RL, export/import."""

import json
import os
import tempfile

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse

from nabla.auth import require_user
from nabla.log import get_logger
from nabla.rate_limit import limiter

logger = get_logger("api.system")

router = APIRouter(prefix="/api/system", tags=["system"])


# ---------------------------------------------------------------------------
# Bootstrap / Teardown
# ---------------------------------------------------------------------------

@router.post("/bootstrap")
@limiter.limit("1/minute")
async def bootstrap(request: Request, _auth: None = Depends(require_user)):
    """Bootstrap the Nabla agent system.

    Creates supervisor agent, shared blocks, and tools.
    Idempotent — safe to call if already bootstrapped.
    """
    from nabla.client import get_client
    from nabla.agents.bootstrap import bootstrap

    client = get_client()
    try:
        result = bootstrap(client)
        return {"status": "ok", "agents": result}
    except Exception as e:
        from nabla.safe_error import safe_error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=safe_error(e, "Bootstrap"),
        )


@router.post("/teardown")
@limiter.limit("1/minute")
async def teardown(request: Request, _auth: None = Depends(require_user)):
    """Teardown the Nabla agent system.

    Removes all Nabla agents and shared blocks.
    """
    from nabla.client import get_client
    from nabla.agents.bootstrap import teardown

    client = get_client()
    try:
        teardown(client)
        return {"status": "ok"}
    except Exception as e:
        from nabla.safe_error import safe_error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=safe_error(e, "Teardown"),
        )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@router.get("/health")
async def health_check(_auth: None = Depends(require_user)):
    """Check system health — Letta, Ollama, data directory.

    Returns:
        Dict with health status for each component.
    """
    result = {}

    # Letta
    try:
        from nabla.client import get_client
        client = get_client()
        resp = client.health()
        result["letta"] = {"healthy": resp.status == "ok", "detail": f"v{resp.version}"}
    except Exception as e:
        result["letta"] = {"healthy": False, "detail": "unreachable"}

    # Ollama
    try:
        import httpx
        from nabla.config import get_settings
        settings = get_settings()
        base = settings.embedding_endpoint.replace("/v1", "")
        url = base + "/api/tags"
        resp = httpx.get(url, timeout=5.0)
        result["ollama"] = {"healthy": resp.status_code == 200}
    except Exception as e:
        result["ollama"] = {"healthy": False, "detail": "unreachable"}

    # Data directory
    from nabla.config import get_settings
    settings = get_settings()
    data_dir = settings.data_dir
    result["data_dir"] = {
        "path": data_dir,
        "writable": os.access(data_dir, os.W_OK) if os.path.exists(data_dir) else False,
        "exists": os.path.exists(data_dir),
    }

    return result


# ---------------------------------------------------------------------------
# RL State
# ---------------------------------------------------------------------------

@router.get("/rl")
async def get_rl_state(_auth: None = Depends(require_user)):
    """Get RL adaptive threshold state and detection method effectiveness.

    Returns:
        Dict with current thresholds, update counts, and bandit effectiveness.
    """
    from nabla.config import get_settings
    from nabla.rl.thresholds import ThresholdAgent, THRESHOLDS
    from nabla.rl.bandit import DetectionMethodBandit

    settings = get_settings()

    agent = ThresholdAgent.load(settings.rl_state_file)
    bandit = DetectionMethodBandit.load(settings.rl_state_file)

    # Current threshold values with defaults
    thresholds = {}
    for name, (lo, hi, step, default) in THRESHOLDS.items():
        current = agent.current_values.get(name, default)
        thresholds[name] = {
            "current": current,
            "default": default,
            "changed": current != default,
            "updates": agent.update_counts.get(name, 0),
        }

    # Bandit effectiveness
    means = bandit.get_means()
    effectiveness = {}
    for method in sorted(means, key=means.get, reverse=True):
        effectiveness[method] = {
            "mean": round(means[method], 3),
            "alpha": bandit.alpha.get(method, 1.0),
            "beta": bandit.beta.get(method, 1.0),
            "observations": bandit.update_counts.get(method, 0),
        }

    return {
        "thresholds": thresholds,
        "effectiveness": effectiveness,
        "total_threshold_updates": sum(agent.update_counts.values()),
        "total_bandit_observations": sum(bandit.update_counts.values()),
    }


# ---------------------------------------------------------------------------
# Export / Import
# ---------------------------------------------------------------------------

@router.post("/export")
@limiter.limit("2/minute")
async def export_state(request: Request, _auth: None = Depends(require_user)):
    """Export all Nabla learned state as a JSON download.

    Returns:
        JSON file with all state files bundled.
    """
    from nabla.config import get_settings
    from nabla.export import export_state as _export

    settings = get_settings()

    # Write to temp file, then read and return
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        output_path = f.name

    try:
        _export(settings.data_dir, output_path)
        with open(output_path, "r") as f:
            data = json.load(f)
        return JSONResponse(content=data)
    except Exception as e:
        from nabla.safe_error import safe_error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=safe_error(e, "Export"),
        )
    finally:
        if os.path.exists(output_path):
            os.unlink(output_path)


@router.post("/import")
@limiter.limit("2/minute")
async def import_state(
    request: Request,
    file: UploadFile,
    merge: bool = False,
    _auth: None = Depends(require_user),
):
    """Import Nabla state from a JSON file.

    Args:
        file: Uploaded JSON file.
        merge: If true, merge with existing state. If false, overwrite.

    Returns:
        Dict with import status.
    """
    from nabla.config import get_settings
    from nabla.export import import_state as _import

    settings = get_settings()

    # Save uploaded file to temp location
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        content = await file.read()
        f.write(content)
        input_path = f.name

    try:
        _import(input_path, settings.data_dir, merge=merge)
        return {"status": "ok", "merge": merge}
    except Exception as e:
        from nabla.safe_error import safe_error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=safe_error(e, "Import"),
        )
    finally:
        if os.path.exists(input_path):
            os.unlink(input_path)
