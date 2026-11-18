"""D10: server.py coverage — the app factory and routes via TestClient."""
from fastapi.testclient import TestClient

from nabla.server import app


def test_app_builds_with_routes():
    """The FastAPI app assembles and exposes the expected route families."""
    client = TestClient(app, raise_server_exceptions=False)
    paths = {r.path for r in app.routes}
    assert "/health" in paths
    assert any(p.startswith("/api/entities") for p in paths)
    assert any(p.startswith("/api/incidents") for p in paths)


def test_health_endpoint():
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/health")
    assert r.status_code == 200


def test_middleware_stack():
    """Auth middleware is present (cookie sessions)."""
    from nabla.auth import require_user
    # R16: the can't-fail 'or True' removed — the 401 below is the real check
    r = TestClient(app).get("/api/entities")
    assert r.status_code in (401, 403), f"unauthenticated access should be rejected: {r.status_code}"
