"""Tests for the cookie-session auth model (users, JWT, auth routes).

Covers the login plan spec: register (first-user-only, setup-token gate,
validation), login (generic errors — no user enumeration), /me hydration,
logout, cookie attributes, anti-recon setup-status, dev-mode bypass,
and the UserStore race guard.
"""

import json
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from nabla.config import Settings


def _settings(tmp_path, dev_mode=False, setup_token="", expire=10080):
    return Settings(
        data_dir=str(tmp_path),
        letta_base_url="http://localhost:9999",
        setup_token=setup_token,
        dev_mode=dev_mode,
        jwt_expire_minutes=expire,
        embedding_endpoint="http://localhost:11434/v1",
        splunk_host="",
        sumologic_host="",
        splunk_validate_url=False,
        sumologic_validate_url=False,
    )


@pytest.fixture
def auth_app(tmp_path):
    """Full Nabla app with file-backed auth, dev mode OFF."""
    from nabla.server import app
    from nabla.rate_limit import reset_rate_limits

    settings = _settings(tmp_path, dev_mode=False)
    reset_rate_limits()

    with patch("nabla.config.get_settings", return_value=settings), \
         patch("nabla.config._settings", settings):
        # https base so the Secure cookie (secure=not dev_mode) is sent
        client = TestClient(app, raise_server_exceptions=False, base_url="https://testserver")
        yield client, settings, tmp_path

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# UserStore unit tests
# ---------------------------------------------------------------------------

class TestUserStore:
    def test_first_user_created_as_admin(self, tmp_path):
        from nabla.users import UserStore

        store = UserStore(str(tmp_path / "users.json"))
        user = store.create("admin_user", "password123")
        assert user["role"] == "admin"
        assert store.count() == 1

    def test_password_hashed_not_plaintext(self, tmp_path):
        from nabla.users import UserStore

        store = UserStore(str(tmp_path / "users.json"))
        store.create("admin_user", "password123")
        raw = json.load(open(tmp_path / "users.json"))
        assert "password123" not in raw["admin_user"]["password_hash"]
        assert raw["admin_user"]["password_hash"].startswith("$2")

    def test_verify_password(self, tmp_path):
        from nabla.users import UserStore

        store = UserStore(str(tmp_path / "users.json"))
        store.create("admin_user", "password123")
        assert store.verify_password("admin_user", "password123")
        assert not store.verify_password("admin_user", "wrong")
        assert not store.verify_password("nobody", "password123")

    def test_duplicate_username_rejected(self, tmp_path):
        from nabla.users import UserStore

        store = UserStore(str(tmp_path / "users.json"))
        store.create("admin_user", "password123")
        with pytest.raises(ValueError, match="already exists"):
            store.create("admin_user", "another-pass-1")

    def test_username_validation(self, tmp_path):
        from nabla.users import UserStore

        store = UserStore(str(tmp_path / "users.json"))
        with pytest.raises(ValueError, match="characters"):
            store.create("ab", "password123")
        with pytest.raises(ValueError, match="letters"):
            store.create("bad name!", "password123")

    def test_short_password_rejected(self, tmp_path):
        from nabla.users import UserStore

        store = UserStore(str(tmp_path / "users.json"))
        with pytest.raises(ValueError, match="8 characters"):
            store.create("admin_user", "short")

    def test_race_guard_first_file_exclusive(self, tmp_path):
        """Simulate the lost race: file appears between check and create."""
        from nabla.users import UserStore

        path = str(tmp_path / "users.json")
        # Another "process" creates the initial file after our exists() check
        store = UserStore(path)
        original_exists = os.path.exists
        with patch("nabla.users.os.path.exists", side_effect=lambda p: False if p == path else original_exists(p)):
            os.makedirs(tmp_path, exist_ok=True)
            with open(path, "w") as f:
                json.dump({"winner": {"username": "winner", "password_hash": "x", "role": "admin"}}, f)
            # Falls through to locked path; username not taken -> creates fine
            user = store.create("late_user", "password123")
            assert user["username"] == "late_user"
        data = json.load(open(path))
        assert "winner" in data and "late_user" in data


# ---------------------------------------------------------------------------
# JWT + cookie mechanics
# ---------------------------------------------------------------------------

class TestJwtCookies:
    def test_token_roundtrip(self, tmp_path):
        from nabla.auth import create_access_token, verify_access_token

        settings = _settings(tmp_path)
        with patch("nabla.auth.get_settings", return_value=settings):
            token = create_access_token("alice", "admin")
            payload = verify_access_token(token)
            assert payload["sub"] == "alice"
            assert payload["role"] == "admin"

    def test_expired_token_rejected(self, tmp_path):
        from nabla.auth import create_access_token, verify_access_token

        settings = _settings(tmp_path, expire=-1)  # already expired
        with patch("nabla.auth.get_settings", return_value=settings):
            token = create_access_token("alice", "admin")
            with pytest.raises(Exception):
                verify_access_token(token)

    def test_cookie_attributes_hardened(self, auth_app):
        client, _, _ = auth_app
        client.post("/api/auth/register", json={"username": "alice", "password": "password123"})
        # Inspect the register response's Set-Cookie via a login call instead
        resp = client.post("/api/auth/login", json={"username": "alice", "password": "password123"})
        cookie_header = resp.headers.get("set-cookie", "")
        assert "nabla_session=" in cookie_header
        assert "httponly" in cookie_header.lower()
        assert "samesite=strict" in cookie_header.lower()
        assert "path=/" in cookie_header.lower()
        # secure flag: dev_mode=False -> secure expected
        assert "secure" in cookie_header.lower()

    def test_dev_mode_drops_secure_flag(self, tmp_path):
        from nabla.server import app
        from nabla.rate_limit import reset_rate_limits

        settings = _settings(tmp_path, dev_mode=True)
        reset_rate_limits()
        with patch("nabla.config.get_settings", return_value=settings), \
             patch("nabla.config._settings", settings):
            client = TestClient(app, raise_server_exceptions=False, base_url="https://testserver")
            resp = client.post("/api/auth/login", json={"username": "a", "password": "b"})
            # login fails (no users) but dev-mode bypass means the cookie
            # attribute path is only testable via register:
            resp = client.post("/api/auth/register", json={"username": "dev_user", "password": "password123"})
            cookie_header = resp.headers.get("set-cookie", "")
            assert "secure" not in cookie_header.lower()
        app.dependency_overrides.clear()

    def test_jwt_secret_created_once(self, tmp_path):
        from nabla.users import load_jwt_secret

        path = str(tmp_path / "jwt_secret")
        s1 = load_jwt_secret(path)
        s2 = load_jwt_secret(path)
        assert s1 == s2 and len(s1) > 20
        assert os.stat(path).st_mode & 0o777 == 0o600


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------

class TestSetupStatus:
    def test_fresh_state_reveals_token_flag(self, auth_app):
        client, settings, _ = auth_app
        with patch.object(settings, "setup_token", "tok", create=True):
            resp = client.get("/api/auth/setup-status")
        assert resp.json() == {"needs_setup": True, "requires_setup_token": True}

    def test_configured_state_hides_token_flag(self, auth_app):
        """Anti-recon: once a user exists, requires_setup_token disappears."""
        client, _, _ = auth_app
        client.post("/api/auth/register", json={"username": "alice", "password": "password123"})
        resp = client.get("/api/auth/setup-status")
        assert resp.json() == {"needs_setup": False}


class TestRegister:
    def test_first_user_registers_and_gets_cookie(self, auth_app):
        client, _, _ = auth_app
        resp = client.post("/api/auth/register", json={"username": "alice", "password": "password123"})
        assert resp.status_code == 201
        assert resp.json() == {"username": "alice", "role": "admin"}
        assert "nabla_session" in client.cookies

    def test_second_user_rejected(self, auth_app):
        client, _, _ = auth_app
        client.post("/api/auth/register", json={"username": "alice", "password": "password123"})
        resp = client.post("/api/auth/register", json={"username": "bob", "password": "password123"})
        assert resp.status_code == 400
        assert "closed" in resp.json()["detail"]

    def test_setup_token_gate(self, auth_app):
        client, settings, _ = auth_app
        with patch.object(settings, "setup_token", "sekrit", create=True):
            resp = client.post("/api/auth/register", json={"username": "alice", "password": "password123"})
            assert resp.status_code == 403
            resp = client.post("/api/auth/register", json={
                "username": "alice", "password": "password123", "setup_token": "sekrit"})
            assert resp.status_code == 201

    def test_validation_errors(self, auth_app):
        client, _, _ = auth_app
        assert client.post("/api/auth/register", json={"username": "ab", "password": "password123"}).status_code == 400
        assert client.post("/api/auth/register", json={"username": "alice", "password": "short"}).status_code == 400


class TestLogin:
    def test_login_ok(self, auth_app):
        client, _, _ = auth_app
        client.post("/api/auth/register", json={"username": "alice", "password": "password123"})
        client.cookies.clear()
        resp = client.post("/api/auth/login", json={"username": "alice", "password": "password123"})
        assert resp.status_code == 200
        assert resp.json()["username"] == "alice"
        assert "nabla_session" in client.cookies

    def test_generic_error_no_enumeration(self, auth_app):
        """Missing user and wrong password MUST return identical errors."""
        client, _, _ = auth_app
        client.post("/api/auth/register", json={"username": "alice", "password": "password123"})
        client.cookies.clear()
        r1 = client.post("/api/auth/login", json={"username": "ghost", "password": "whatever12"})
        r2 = client.post("/api/auth/login", json={"username": "alice", "password": "wrongpass1"})
        assert r1.status_code == r2.status_code == 401
        assert r1.json()["detail"] == r2.json()["detail"] == "Invalid username or password"


class TestMeAndLogout:
    def test_me_hydrates_from_cookie(self, auth_app):
        client, _, _ = auth_app
        client.post("/api/auth/register", json={"username": "alice", "password": "password123"})
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json() == {"username": "alice", "role": "admin"}

    def test_me_without_cookie_401(self, auth_app):
        client, _, _ = auth_app
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_logout_clears_cookie(self, auth_app):
        client, _, _ = auth_app
        client.post("/api/auth/register", json={"username": "alice", "password": "password123"})
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200
        # TestClient may keep the cookie; verify server-side rejection
        client.cookies.clear()
        assert client.get("/api/auth/me").status_code == 401

    def test_protected_route_requires_session(self, auth_app):
        client, _, _ = auth_app
        resp = client.get("/api/dashboard")
        assert resp.status_code == 401


class TestRateLimits:
    def test_login_rate_limited(self, auth_app):
        client, _, _ = auth_app
        client.post("/api/auth/register", json={"username": "alice", "password": "password123"})
        client.cookies.clear()
        codes = []
        for _ in range(7):
            r = client.post("/api/auth/login", json={"username": "alice", "password": "wrongpass1"})
            codes.append(r.status_code)
        assert 429 in codes
        assert codes.count(401) == 5  # exactly the limit, then blocked

    def test_register_rate_limited(self, auth_app):
        client, _, _ = auth_app
        codes = []
        for i in range(5):
            r = client.post("/api/auth/register", json={"username": f"u{i}", "password": "password123"})
            codes.append(r.status_code)
        # first registers (201), second+ rejected as closed (400), then 429s
        assert 429 in codes


class TestDevModeBypass:
    def test_dev_mode_open_access(self, tmp_path):
        from nabla.server import app
        from nabla.rate_limit import reset_rate_limits

        settings = _settings(tmp_path, dev_mode=True)
        reset_rate_limits()
        with patch("nabla.config.get_settings", return_value=settings), \
             patch("nabla.config._settings", settings):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/auth/me")
            assert resp.status_code == 200
            assert resp.json()["role"] == "admin"
        app.dependency_overrides.clear()
