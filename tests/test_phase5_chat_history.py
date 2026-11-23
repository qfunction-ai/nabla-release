"""Phase 5 (B1/R-3): the per-user chat transcript store.

The Chat page is useState-only today — refresh wipes the conversation.
The Letta server holds history but exposing it would leak every user's
chats PLUS the pipeline's review prompts (one shared supervisor
agent). These witnesses verify the Nabla-owned store: identity
scoping, cursor pagination, and that chat_stream persists a turn only
on clean completion.
"""
import json
import pytest


@pytest.fixture
def chat_env(tmp_path, monkeypatch):
    import importlib
    import nabla.config
    monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))
    nabla.config._settings = None
    importlib.reload(nabla.config)
    import nabla.chat_history as ch
    importlib.reload(ch)
    return ch


class TestStore:
    def test_roundtrip_and_scoping(self, chat_env):
        ch = chat_env
        ch.append_turn(user="alice", message="q1", answer="a1")
        ch.append_turn(user="bob", message="q2", answer="a2")
        ch.append_turn(user="alice", message="q3", answer="a3")

        alice = ch.load_history(user="alice")
        assert [t["message"] for t in alice] == ["q3", "q1"]  # newest first
        bob = ch.load_history(user="bob")
        assert [t["message"] for t in bob] == ["q2"]

    def test_cursor_pagination(self, chat_env):
        ch = chat_env
        for i in range(5):
            ch.append_turn(user="u", message=f"m{i}", answer=f"a{i}",
                           ts=f"2026-11-23T00:0{i}:00+00:00")
        page1 = ch.load_history(user="u", limit=2)
        assert [t["message"] for t in page1] == ["m4", "m3"]
        page2 = ch.load_history(user="u", limit=2, before_ts=page1[-1]["ts"])
        assert [t["message"] for t in page2] == ["m2", "m1"]

    def test_reasoning_stored_only_when_requested(self, chat_env):
        ch = chat_env
        ch.append_turn(user="u", message="q", answer="a", reasoning="think")
        assert ch.load_history(user="u")[0]["reasoning"] == "think"


class TestEndpoint:
    def test_history_scoped_to_identity(self, chat_env, monkeypatch):
        from fastapi.testclient import TestClient
        from nabla.server import app
        from nabla.auth import require_user

        chat_env.append_turn(user="alice", message="q1", answer="a1")
        chat_env.append_turn(user="bob", message="q2", answer="a2")

        monkeypatch.setitem(app.dependency_overrides, require_user,
                            lambda: {"sub": "alice"})
        client = TestClient(app)
        data = client.get("/api/chat/history").json()
        assert [t["message"] for t in data["turns"]] == ["q1"]
        # response model drops the internal user field — identity never
        # echoes back as data
        assert "user" not in data["turns"][0]

    def test_limit_validation(self, chat_env, monkeypatch):
        from fastapi.testclient import TestClient
        from nabla.server import app
        from nabla.auth import require_user

        monkeypatch.setitem(app.dependency_overrides, require_user,
                            lambda: {"sub": "alice"})
        client = TestClient(app)
        assert client.get("/api/chat/history?limit=0").status_code == 422
        assert client.get("/api/chat/history?limit=501").status_code == 422

    def test_stream_persists_on_completion(self, chat_env, monkeypatch):
        """chat_stream accumulates assistant text and writes the turn
        ONLY on clean end-of-stream."""
        from fastapi.testclient import TestClient
        from nabla.server import app
        from nabla.auth import require_user

        class FakeChunk:
            def __init__(self, message_type, content=None, reasoning=None):
                self.message_type = message_type
                self.content = content
                self.reasoning = reasoning

        class FakeMessages:
            def create(self, **kwargs):
                assert kwargs["messages"][0]["content"] == "hello supervisor"
                yield FakeChunk("reasoning_message", reasoning="pondering")
                yield FakeChunk("assistant_message", content="the answer")

        class FakeAgent:
            id = "agent-x"

        class FakeClient:
            agents = type("A", (), {"messages": FakeMessages()})()

        import nabla.client as client_mod
        import nabla.agents.registry as registry

        monkeypatch.setattr(client_mod, "get_client", lambda: FakeClient())
        monkeypatch.setattr(registry, "find_agent", lambda c, name: FakeAgent())
        monkeypatch.setitem(app.dependency_overrides, require_user,
                            lambda: {"sub": "alice"})

        client = TestClient(app)
        resp = client.post("/api/chat/stream",
                           json={"message": "hello supervisor"})
        assert resp.status_code == 200
        assert "done" in resp.text

        turns = chat_env.load_history(user="alice")
        assert len(turns) == 1
        assert turns[0]["message"] == "hello supervisor"
        assert turns[0]["answer"] == "the answer"
        # include_reasoning=False: reasoning streamed but NOT persisted
        assert turns[0]["reasoning"] is None

    def test_stream_error_writes_nothing(self, chat_env, monkeypatch):
        """An errored stream must not persist a partial turn."""
        from fastapi.testclient import TestClient
        from nabla.server import app
        from nabla.auth import require_user

        class FakeMessages:
            def create(self, **kwargs):
                yield FakeChunk("assistant_message", content="partial")
                raise RuntimeError("boom")

        class FakeChunk:
            def __init__(self, message_type, content=None):
                self.message_type = message_type
                self.content = content

        class FakeAgent:
            id = "agent-x"

        class FakeClient:
            agents = type("A", (), {"messages": FakeMessages()})()

        import nabla.client as client_mod
        import nabla.agents.registry as registry

        monkeypatch.setattr(client_mod, "get_client", lambda: FakeClient())
        monkeypatch.setattr(registry, "find_agent", lambda c, name: FakeAgent())
        monkeypatch.setitem(app.dependency_overrides, require_user,
                            lambda: {"sub": "alice"})

        client = TestClient(app)
        resp = client.post("/api/chat/stream", json={"message": "q"})
        assert resp.status_code == 200  # SSE: error arrives as an event
        assert "error" in resp.text
        assert chat_env.load_history(user="alice") == []
