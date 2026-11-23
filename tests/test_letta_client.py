"""Migration witnesses (M-1, M-2, MR-2, MR-3) — the v0.16.38 auth path.

Every assertion runs against the REAL letta-client 1.10.3 surface (the
production pin): real constructor, real serialization, real request
build through a recording transport. No mocked client of our own
making — the token= bug survived a whole release precisely because the
suite mocked the client.

Witnesses:
  W1  get_client() constructs with a key set (M-1: the kwarg exists)
  W2  the api_key lands on the wire as "Authorization: Bearer" (MR-3)
  W3  env.py's two patches route through the SDK with auth (MR-2)
  W4  unpassed update fields are OMITTED, not sent (no agent wipe)
  W5  a Letta 401 raises the actionable auth message
"""

import httpx
import pytest
from letta_client import Letta

import nabla.client as client_mod


def _recording_client(handler, api_key="test-key-123"):
    """A real Letta client whose transport records requests."""
    return Letta(
        base_url="http://letta-test:8283",
        api_key=api_key,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_w1_get_client_with_key_constructs(monkeypatch):
    """M-1: with a key set, get_client() must construct against the real
    Letta class. RED on the token= kwarg (TypeError) — the branch never
    executed while the key defaulted empty."""
    class _Settings:
        letta_api_key = "test-key-123"
        letta_base_url = "http://letta-test:8283"

    monkeypatch.setattr(client_mod, "get_settings", lambda: _Settings())
    client_mod.reset_client()
    try:
        c = client_mod.get_client()
        assert c is not None
    finally:
        client_mod.reset_client()


def test_w2_api_key_sends_bearer_header_on_the_wire():
    """MR-3: 'the SDK's api_key produces the Bearer header' is shown by
    test, not assumed — the same claim class as token=."""
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["path"] = request.url.path
        return httpx.Response(200, json={"status": "ok", "version": "0.16.38"})

    c = _recording_client(handler)
    c.health()
    assert seen["auth"] == "Bearer test-key-123"


def test_w3_w4_env_patches_route_through_sdk_with_auth(monkeypatch):
    """MR-2: the two bootstrap patches go through the SDK client (one
    authenticated path), carrying exactly the payloads the raw calls
    sent, with the auth header. W4: Fern's omit semantics — unpassed
    fields must NOT appear on the wire (an update that sent name/system
    would wipe the agent)."""
    import json as _json

    recorded = []

    def handler(request):
        recorded.append({
            "method": request.method,
            "path": request.url.path,
            "auth": request.headers.get("authorization"),
            "body": _json.loads(request.content) if request.content else None,
        })
        return httpx.Response(200, json={})

    c = _recording_client(handler)
    monkeypatch.setattr("nabla.agents.env.get_client", lambda: c)

    from nabla.agents.env import fix_embedding_model_prefix, set_agent_compaction_model

    set_agent_compaction_model("agent-abc", "gemma4:26b")
    fix_embedding_model_prefix("agent-abc", "embeddinggemma:latest")

    assert len(recorded) == 2
    for r in recorded:
        assert r["method"] == "PATCH"
        assert r["path"] == "/v1/agents/agent-abc"
        assert r["auth"] == "Bearer test-key-123"
        # W4: partial update only — anything else here would wipe the agent
        assert "name" not in r["body"]
        assert "system" not in r["body"]
        assert "llm_config" not in r["body"]
        assert "block_ids" not in r["body"]
    assert recorded[0]["body"] == {"compaction_settings": {"model": "gemma4:26b"}}
    assert recorded[1]["body"] == {
        "embedding_config": {
            "embedding_model": "embeddinggemma:latest",
            "embedding_endpoint": "http://host.docker.internal:11434/v1",
            "embedding_endpoint_type": "ollama",
            "embedding_dim": 4096,
        }
    }


def test_w5_letta_401_raises_actionable_auth_error():
    """A bare 401 from a secure-mode server wastes a debugging cycle —
    the diagnosis transport rewrites the 401 body so the SDK's
    APIStatusError carries the actionable message verbatim (the SDK
    wraps transport exceptions in APIConnectionError, so the message
    must travel in the response body)."""
    from letta_client import APIStatusError

    from nabla.client import _AuthDiagnosisTransport

    inner = httpx.MockTransport(
        lambda request: httpx.Response(401, json={"detail": "Not authenticated"})
    )
    c = Letta(
        base_url="http://letta-test:8283",
        api_key="empty-or-wrong",
        http_client=httpx.Client(transport=_AuthDiagnosisTransport(inner)),
    )
    with pytest.raises(APIStatusError, match="NABLA_LETTA_API_KEY") as excinfo:
        c.agents.retrieve(agent_id="agent-abc")
    assert excinfo.value.status_code == 401
    assert "LETTA_SERVER_PASSWORD" in str(excinfo.value)
