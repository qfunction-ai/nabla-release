"""User accounts for Nabla — file-based store with bcrypt password hashes.

Single-admin posture: the first registered user becomes admin; the role
field is reserved for future RBAC without a management UI. The store is
a JSON file written via the atomic-persistence house pattern with a
POSIX file lock for read-modify-write sequences.

The first-registration race guard (O_EXCL on the initial file) is
atomic cross-process on one host and matches the single-worker
deployment. TRIPWIRE: if uvicorn workers are ever configured, this
guard needs revisiting (see docs/plans/2026-09-01-nabla-login.md, Risk 8).
"""

import json
import os
from datetime import datetime, timezone

import bcrypt

from nabla.log import get_logger
from nabla.persistence import atomic_write_json, file_lock

logger = get_logger("users")

MAX_USERNAME_LEN = 50
MIN_USERNAME_LEN = 3


def validate_username(username: str) -> str | None:
    """Return an error string if the username is invalid, else None."""
    if not (MIN_USERNAME_LEN <= len(username) <= MAX_USERNAME_LEN):
        return f"Username must be {MIN_USERNAME_LEN}-{MAX_USERNAME_LEN} characters"
    import re

    if not re.fullmatch(r"[a-zA-Z0-9_]+", username):
        return "Username may only contain letters, digits, and underscores"
    return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class UserStore:
    """JSON-file-backed user store."""

    def __init__(self, path: str):
        self.path = path

    def _load(self) -> dict:
        try:
            with open(self.path) as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, OSError) as e:
            # R6-9 (round 6): FAIL CLOSED. The old behavior (return {})
            # made count() == 0, which REOPENED first-registration and let
            # create() overwrite the file — wiping the real admin with the
            # first visitor. A present-but-unreadable file is an incident,
            # not an empty store.
            raise RuntimeError(
                f"users file exists but cannot be read ({self.path}: {e}) — "
                f"failing closed; refusing to treat as empty (R6-9)") from e

    def count(self) -> int:
        return len(self._load())

    def get(self, username: str) -> dict | None:
        return self._load().get(username)

    def verify_password(self, username: str, password: str) -> bool:
        user = self.get(username)
        if user is None:
            # Constant-ish time: hash a dummy so a missing user costs the same
            bcrypt.checkpw(password.encode(), b"$2b$12$C6UzMDM.H6dfI/f/IKcEeO7ZBpUvHzGE9zSlx0rdxW8e9x8/0LmeK")
            return False
        return bcrypt.checkpw(password.encode(), user["password_hash"].encode())

    def create(self, username: str, password: str, role: str = "admin") -> dict:
        """Create a user. First user becomes admin (enforced by the caller).

        The initial file is created with O_EXCL so two concurrent
        first-registrations cannot both win.

        Raises:
            FileExistsError: if this store raced another first-registration.
            ValueError: on invalid username or short password.
        """
        if err := validate_username(username):
            raise ValueError(err)
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")

        user = {
            "username": username,
            "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            "role": role,
            "created_at": _now_iso(),
        }

        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)

        # Race guard: exclusive create of the initial file.
        if not os.path.exists(self.path):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "w") as f:
                    json.dump({username: user}, f, indent=2)
                logger.info("Created users store with first user %s (admin)", username)
                return user
            except FileExistsError:
                # Another process won the first-registration race; fall
                # through to the locked path, where the users-exist check
                # in the route layer will reject the late registration.
                pass  # silent by design: O_EXCL race loser (2026-09 sweep)

        with file_lock(self.path):
            users = self._load()
            if username in users:
                raise ValueError("Username already exists")
            # R6-10 (round 6): the O_EXCL loser falls through to here, and
            # the route's users-exist check has already passed. Re-check:
            # if the store is no longer empty, this is a race loser trying
            # to become a SECOND admin — reject.
            if len(users) > 0 and user.get("role") == "admin":
                raise PermissionError(
                    "first registration already won — refusing to create "
                    "a second admin (R6-10)")
            users[username] = user
            atomic_write_json(self.path, users)

        return user


def load_jwt_secret(path: str) -> str:
    """Load or create the JWT signing secret (32 random bytes, 0600).

    Created on first boot; persisted for the volume's lifetime so
    sessions survive restarts. If the volume dies, all sessions die
    with it — correct semantics for this deployment.
    """
    try:
        with open(path) as f:
            secret = f.read().strip()
            if secret:
                return secret
    except FileNotFoundError:
        pass  # silent by design: absent jwt_secret falls through to generation (2026-09 sweep)

    import secrets

    secret = secrets.token_urlsafe(32)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    # Round-6 low: the O_EXCL sat OUTSIDE the try — a first-boot race
    # raised an uncaught FileExistsError. Inside, the loser reads the
    # winner's file (and an empty winner file — crash mid-write —
    # regenerates instead of failing every login with a 500).
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secret)
    except FileExistsError:
        with open(path) as f:
            winner = f.read().strip()
        if winner:
            return winner
        # Empty (crashed mid-write): regenerate non-exclusively
        with open(path, "w") as f:
            f.write(secret)
    logger.info("Generated JWT signing secret at %s", path)
    return secret
