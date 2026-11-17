"""API authentication — user accounts with httpOnly cookie sessions.

Model (per docs/plans/2026-09-01-nabla-login.md, transferring Delta's
proven architecture): bcrypt-verified users in a file store; JWT
sessions in httpOnly cookies (JS-invisible, XSS-resistant); auth state
hydrated via GET /api/auth/me. The raw token is never handled by the
frontend. NABLA_DEV_MODE remains a documented open-access bypass.

Three modes:
1. Users exist → require a valid session cookie
2. Dev mode → open access (logged once as warning)
3. No users + no dev mode → reject with needs_setup guidance (the
   frontend shows the registration form)
"""

import datetime as _dt

import jwt
from fastapi import HTTPException, Request, status

from nabla.config import get_settings

COOKIE_NAME = "nabla_session"

# Track whether we've logged the open-access warning
_open_access_warned = False


def _jwt_secret() -> str:
    from nabla.users import load_jwt_secret

    settings = get_settings()
    return load_jwt_secret(settings.jwt_secret_file)


def create_access_token(username: str, role: str) -> str:
    """Mint an HS256 session JWT for the user."""
    settings = get_settings()
    now = _dt.datetime.now(_dt.timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + _dt.timedelta(minutes=settings.jwt_expire_minutes)).timestamp()),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def verify_access_token(token: str) -> dict:
    """Verify a session JWT. Returns the payload or raises 401."""
    try:
        return jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session",
        )


def _cookie_max_age() -> int:
    return get_settings().jwt_expire_minutes * 60


def set_auth_cookie(response, token: str) -> None:
    """Set the session cookie with the hardened attribute set.

    httponly: JS-invisible (XSS token theft prevention)
    samesite=strict: CSRF defense
    secure: HTTPS-only outside dev mode (local HTTP dev would drop it)
    max_age: derived from the JWT expiry so they never drift
    """
    settings = get_settings()
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=_cookie_max_age(),
        httponly=True,
        samesite="strict",
        secure=not settings.dev_mode,
        path="/",
    )


def clear_auth_cookie(response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/",
        secure=not settings.dev_mode,
        httponly=True,
        samesite="strict",
    )


async def require_user(request: Request) -> dict:
    """Validate the session cookie. Returns the JWT payload.

    Raises:
        HTTPException: 401 if no valid session and not in dev mode.
    """
    global _open_access_warned

    settings = get_settings()

    # Dev mode — open access bypass (documented; single-user local dev)
    if settings.dev_mode:
        if not _open_access_warned:
            from nabla.log import get_logger

            logger = get_logger("auth")
            logger.warning(
                "API is open (NABLA_DEV_MODE=true). All endpoints are "
                "unauthenticated. Disable dev mode for production use."
            )
            _open_access_warned = True
        return {"sub": "dev", "role": "admin"}

    token = request.cookies.get(COOKIE_NAME)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return verify_access_token(token)
