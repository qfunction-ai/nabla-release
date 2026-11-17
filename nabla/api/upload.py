"""Upload API — log file upload for ad-hoc analysis."""

import os
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, status

from nabla.auth import require_user
from nabla.log import get_logger
from nabla.rate_limit import limiter

logger = get_logger("api.upload")

router = APIRouter(prefix="/api/upload", tags=["upload"])

# Max upload size: 100MB
MAX_UPLOAD_SIZE = 100 * 1024 * 1024


def _sanitize_filename(name: str) -> str:
    """Sanitize an uploaded filename to prevent path traversal.

    Strips directory components, replaces path separators and
    special characters with underscores, and rejects empty/dot-only
    names after sanitization.

    Args:
        name: Raw filename from the upload request.

    Returns:
        Safe filename with no directory components or special chars.
    """
    # Strip directory components (handles both / and \ separators)
    # os.path.basename only handles the OS-native separator, so split
    # on both forward and backslash, then take the last component.
    name = name.replace("\\", "/").split("/")[-1]
    # Replace any remaining path separators and dangerous characters
    name = re.sub(r'[^\w.\-]', '_', name)
    # Reject empty or dot-only names
    if not name or name.strip('._-') == '':
        name = "upload"
    return name


@router.post("")
@limiter.limit("5/minute")
async def upload_file(
    request: Request,
    file: UploadFile,
    log_type: str = "auth",
    format: str | None = None,
    _auth: None = Depends(require_user),
):
    """Upload a log file for ad-hoc analysis.

    The file is saved to /data/uploads/ and can be referenced
    in a pipeline run with source=file.

    Args:
        file: Uploaded log file.
        log_type: Log type hint — auth, network, dns, endpoint.
        format: File format hint — csv, json, jsonl, xml, text.

    Returns:
        Dict with file_id and path for pipeline use.
    """
    from nabla.config import get_settings
    settings = get_settings()

    # Ensure upload directory exists
    upload_dir = os.path.join(settings.data_dir, "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    # Check size and read in chunks to avoid loading entire file into memory
    chunks: list[bytes] = []
    total_size = 0
    while True:
        chunk = await file.read(1024 * 1024)  # 1MB chunks
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > MAX_UPLOAD_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large (exceeded {MAX_UPLOAD_SIZE} bytes)",
            )
        chunks.append(chunk)
    content = b"".join(chunks)

    # Save with sanitized unique name
    file_id = str(uuid.uuid4())[:8]
    original_name = file.filename or "upload"
    safe_name = _sanitize_filename(original_name)
    safe_name = f"{file_id}_{safe_name}"
    file_path = os.path.join(upload_dir, safe_name)

    with open(file_path, "wb") as f:
        f.write(content)

    logger.info("Uploaded file %s (%d bytes) → %s", original_name, len(content), file_path)

    return {
        "file_id": file_id,
        "path": file_path,
        "original_name": original_name,
        "size": len(content),
        "log_type": log_type,
        "format": format,
    }
