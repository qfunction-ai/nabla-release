"""System API — bootstrap, teardown, health, RL, export/import."""

import json
import os
import tempfile

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

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
    except Exception:
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
    except Exception:
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

# ---------------------------------------------------------------------------
# Response models (R-4 — the response model IS the contract)
# ---------------------------------------------------------------------------

class ThresholdState(BaseModel):
    """One threshold with its honest calibration state (L6, mockup 03).

    state:
      calibratable    — a method with a comparable raw_score feeds it and
                        label evidence has reached min_labels
      held            — calibratable, but labels are still below
                        min_labels; accumulating
      not_calibratable — no method emits a score in this knob's units;
                        tuning it would be theater
    """

    name: str
    current: float
    default: float
    changed: bool = False
    pinned: bool = False
    state: str = "not_calibratable"
    evidence: str | None = None
    label_count: int = 0
    tp_count: int = 0
    fp_count: int = 0
    min_labels: int = 30
    methods: list[str] = []
    reason: str | None = None


class BanditState(BaseModel):
    mean: float
    alpha: float = 1.0
    beta: float = 1.0


class RLStateResponse(BaseModel):
    thresholds: dict[str, ThresholdState]
    effectiveness: dict[str, BanditState]
    feedback_labels: int = 0
    min_labels: int = 30


class MethodReference(BaseModel):
    """One detection method, served from the backend's own tables (L11).

    The frontend's detectionMethods.ts was a stale third copy — 15
    emitted methods had no entry, one row was a slash-triple. This
    endpoint is the ground truth: every EMITTED method (not just the
    27 bandit arms — attack_script, cusum, ewma, renamed_tool emit
    without an arm), the anomaly type strings it actually emits, its
    tunable knob (name + default) and its calibratable state. Authored
    teaching prose stays in the frontend and joins by `method` key.
    """

    method: str
    types: list[str] = []
    threshold: str | None = None
    default: float | None = None
    calibratable: bool = False
    state: str  # calibratable | not_calibratable | static
    bandit_arm: bool = False


class MethodsResponse(BaseModel):
    methods: list[MethodReference]


def _emitted_method_types() -> dict[str, list[str]]:
    """method key -> the anomaly `type` strings its constructors emit.

    Extracted from source at request time (cached per process) — the
    same grep the R7 coverage gate uses, extended to pair each
    detection_method with the `type` in the same dict literal. If a
    detector renames its type string, this endpoint follows without a
    manual copy.
    """
    import re
    from pathlib import Path
    from nabla import __file__ as _pkg

    cached = getattr(_emitted_method_types, "_cache", None)
    if cached is not None:
        return cached

    pairs: dict[str, set[str]] = {}
    pkg = Path(_pkg).parent
    for py in pkg.rglob("*.py"):
        if "__pycache__" in str(py):
            continue
        lines = py.read_text().splitlines()
        # track the most recent "type" literal; pair it with the next
        # detection_method within the same dict literal. The wide window
        # (25 lines) covers long literals — enumeration_behavior's
        # type and detection_method sit 21 lines apart. The endpoint
        # witness pins known pairs, so a mis-pairing fails loudly.
        recent_type: str | None = None
        recent_line: int = -100
        for i, line in enumerate(lines):
            m = re.search(r'"type":\s*"([a-z_]+)"', line)
            if m:
                recent_type, recent_line = m.group(1), i
                continue
            m = re.search(r'"detection_method":\s*"([a-z_]+)"', line)
            if m and recent_type and i - recent_line <= 25:
                pairs.setdefault(m.group(1), set()).add(recent_type)
    out = {k: sorted(v) for k, v in pairs.items()}
    _emitted_method_types._cache = out
    return out


@router.get("/methods", response_model=MethodsResponse)
async def get_methods(_auth: None = Depends(require_user)):
    """The method reference, generated from the backend's own tables
    (L11): every emitted method + THRESHOLDS + the R7
    classification. Kills the frontend's stale third copy — the
    Methods page joins this list with its authored prose by method
    key, and methods without prose render flagged, not silently
    missing.
    """
    from nabla.rl.bandit import DETECTION_METHODS
    from nabla.rl.calibration import (
        THRESHOLDS,
        METHOD_TO_THRESHOLD,
        NOT_CALIBRATABLE_METHODS,
        STATIC_DETECTORS,
    )

    types_by_method = _emitted_method_types()
    # Every emitted method: the extraction pairs (pre_flagged's type is
    # a passthrough, so it joins from the bandit list), plus any
    # bandit arm the extraction missed.
    all_methods = sorted(
        set(types_by_method) | set(DETECTION_METHODS)
    )
    methods = []
    for method in all_methods:
        tname = METHOD_TO_THRESHOLD.get(method)
        if tname:
            state = "calibratable"
            default = THRESHOLDS[tname][3]
        elif method in NOT_CALIBRATABLE_METHODS:
            state = "not_calibratable"
            default = None
        elif method in STATIC_DETECTORS:
            state = "static"
            default = None
        else:
            state = "unknown"
            default = None
        methods.append({
            "method": method,
            "types": types_by_method.get(method, []),
            "threshold": tname,
            "default": default,
            "calibratable": state == "calibratable",
            "state": state,
            "bandit_arm": method in DETECTION_METHODS,
        })
    return {"methods": methods}


@router.get("/rl", response_model=RLStateResponse)
async def get_rl_state(_auth: None = Depends(require_user)):
    """Get threshold calibration state and detection method effectiveness.

    Phase 3: thresholds come from the calibration store (label-driven);
    the bandit survives unchanged. Frontend batch Phase 4 (L6): every
    threshold carries its honest state (calibratable / held /
    not_calibratable) and its live label evidence (counts + FP/TP
    breakdown) — the held state and the not_calibratable tier knobs
    were previously absent, so the Config page could not show what the
    calibration loop was actually doing.
    """
    from nabla.config import get_settings
    from nabla.rl.calibration import (
        load_calibration,
        THRESHOLDS,
        current_labels,
        METHOD_TO_THRESHOLD,
        MIN_LABELS,
    )
    from nabla.rl.bandit import DetectionMethodBandit

    settings = get_settings()

    store = load_calibration()
    bandit = DetectionMethodBandit.load(settings.rl_state_file)
    labels = current_labels()

    # Per-threshold label evidence (L6): which methods feed this knob and
    # what the labeled alerts say. TP = true_positive + benign_true_positive.
    methods_by_threshold: dict[str, list[str]] = {}
    for method, tname in METHOD_TO_THRESHOLD.items():
        methods_by_threshold.setdefault(tname, []).append(method)

    label_counts: dict[str, dict[str, int]] = {}
    for rec in labels:
        tname = METHOD_TO_THRESHOLD.get(rec.get("detection_method", ""))
        if not tname or rec.get("raw_score") is None:
            continue
        c = label_counts.setdefault(tname, {"labels": 0, "tp": 0, "fp": 0})
        c["labels"] += 1
        if rec.get("disposition") in ("true_positive", "benign_true_positive"):
            c["tp"] += 1
        elif rec.get("disposition") == "false_positive":
            c["fp"] += 1

    thresholds = {}
    for name, (lo, hi, step, default) in THRESHOLDS.items():
        entry = store.get(name, {})
        methods = methods_by_threshold.get(name, [])
        counts = label_counts.get(name, {"labels": 0, "tp": 0, "fp": 0})
        if not methods:
            state = "not_calibratable"
            reason = "no calibratable method feeds this threshold"
        elif bool(entry.get("pinned")):
            state = "calibratable"  # pinned is the operator guardrail, not a state
            reason = None
        elif counts["labels"] < MIN_LABELS:
            state = "held"
            reason = f"below min_labels ({counts['labels']}/{MIN_LABELS}); accumulating"
        else:
            state = "calibratable"
            reason = None
        thresholds[name] = {
            "name": name,
            "current": entry.get("current", default),
            "default": default,
            "changed": entry.get("current", default) != default,
            "pinned": bool(entry.get("pinned")),
            "state": state,
            "evidence": entry.get("evidence"),
            "label_count": counts["labels"],
            "tp_count": counts["tp"],
            "fp_count": counts["fp"],
            "min_labels": MIN_LABELS,
            "methods": sorted(methods),
            "reason": reason,
        }

    means = bandit.get_means()
    effectiveness = {}
    for method in sorted(means, key=means.get, reverse=True):
        effectiveness[method] = {
            "mean": round(means[method], 3),
            "alpha": bandit.alpha.get(method, 1.0),
            "beta": bandit.beta.get(method, 1.0),
        }

    return {
        "thresholds": thresholds,
        "effectiveness": effectiveness,
        "feedback_labels": len(labels),
        "min_labels": MIN_LABELS,
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

    # Round-6 low: cap uploads (the whole file was read into memory with
    # no limit) — 64MB is orders beyond any legitimate state export
    MAX_IMPORT_BYTES = 64 * 1024 * 1024
    content = await file.read(MAX_IMPORT_BYTES + 1)
    if len(content) > MAX_IMPORT_BYTES:
        raise HTTPException(status_code=413,
                            detail="import file exceeds 64MB cap")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
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
