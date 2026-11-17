"""Auth API — user registration, login, logout, session hydration."""

import hmac

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from nabla.auth import (
    clear_auth_cookie,
    create_access_token,
    require_user,
    set_auth_cookie,
)
from nabla.config import get_settings
from nabla.rate_limit import limiter
from nabla.users import UserStore, validate_username

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _store() -> UserStore:
    settings = get_settings()
    return UserStore(settings.users_file)


@router.get("/setup-status")
async def setup_status():
    """Report first-run state.

    Anti-reconnaissance shape: requires_setup_token is ONLY revealed
    when zero users exist (the registration form needs it). Once a user
    exists, the flag disappears — attackers cannot learn the
    registration shape from a configured deployment.
    """
    store = _store()
    needs_setup = store.count() == 0
    out: dict = {"needs_setup": needs_setup}
    if needs_setup:
        out["requires_setup_token"] = bool(get_settings().setup_token)
    return out


@router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
async def register(request: Request, body: dict):
    """Register the first user (becomes admin). Rejected once users exist.

    If NABLA_SETUP_TOKEN is configured, the request must carry it.
    """
    settings = get_settings()
    store = _store()

    if store.count() > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration is closed — a user already exists",
        )

    if settings.setup_token:
        supplied = body.get("setup_token", "")
        if not supplied or not hmac.compare_digest(str(supplied), settings.setup_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid setup token",
            )

    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))

    if err := validate_username(username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters",
        )

    try:
        user = store.create(username, password, role="admin")
    except FileExistsError:
        # Lost the first-registration race
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration is closed — a user already exists",
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    response = JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"username": user["username"], "role": user["role"]},
    )
    set_auth_cookie(response, create_access_token(user["username"], user["role"]))
    return response


@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, body: dict):
    """Log in: verify credentials, set the session cookie.

    Generic failure shape by design: the same 401 "Invalid username or
    password" whether the user is missing or the password is wrong —
    no user enumeration.
    """
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))

    store = _store()
    if not username or not password or not store.verify_password(username, password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    user = store.get(username)
    response = JSONResponse(content={"username": user["username"], "role": user["role"]})
    set_auth_cookie(response, create_access_token(user["username"], user["role"]))
    return response


@router.post("/logout")
@limiter.limit("3/minute")
async def logout(request: Request):
    """Clear the session cookie."""
    response = JSONResponse(content={"ok": True})
    clear_auth_cookie(response)
    return response


@router.get("/me")
async def me(user: dict = Depends(require_user)):
    """Hydrate auth state from the session cookie."""
    return {"username": user["sub"], "role": user["role"]}
