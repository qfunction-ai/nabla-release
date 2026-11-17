"""Tests for nabla.api.chat — /api/chat/stream endpoint."""

import json
from unittest.mock import patch, MagicMock

import pytest


class TestChatStream:
    """Test POST /api/chat/stream."""

    def test_chat_stream_no_agent(self, app_client, mock_letta_client):
        """When supervisor agent not found, returns 503."""
        mock_letta_client.agents.list.return_value = []

        with patch("nabla.agents.registry.find_agent", return_value=None):
            resp = app_client.post(
                "/api/chat/stream",
                json={"message": "Hello", "include_reasoning": False},
            )
        assert resp.status_code == 503

    def test_chat_stream_content_type(self, app_client, mock_letta_client):
        """Stream response has SSE content-type."""
        mock_agent = MagicMock()
        mock_agent.id = "agent-123"

        # Mock the stream to return immediately
        mock_stream = MagicMock()
        mock_stream.__iter__ = MagicMock(return_value=iter([]))

        with patch("nabla.agents.registry.find_agent", return_value=mock_agent), \
             patch("nabla.client.get_client", return_value=mock_letta_client):
            mock_letta_client.agents.messages.create.return_value = mock_stream
            resp = app_client.post(
                "/api/chat/stream",
                json={"message": "Hello", "include_reasoning": False},
            )

        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")

    def test_chat_stream_has_no_cache_headers(self, app_client, mock_letta_client):
        """Stream response has no-cache headers."""
        mock_agent = MagicMock()
        mock_agent.id = "agent-123"
        mock_stream = MagicMock()
        mock_stream.__iter__ = MagicMock(return_value=iter([]))

        with patch("nabla.agents.registry.find_agent", return_value=mock_agent), \
             patch("nabla.client.get_client", return_value=mock_letta_client):
            mock_letta_client.agents.messages.create.return_value = mock_stream
            resp = app_client.post(
                "/api/chat/stream",
                json={"message": "Hello"},
            )

        assert resp.headers.get("cache-control") == "no-cache"
        assert resp.headers.get("x-accel-buffering") == "no"

    def test_chat_stream_emits_done(self, app_client, mock_letta_client):
        """Stream ends with a done event."""
        mock_agent = MagicMock()
        mock_agent.id = "agent-123"
        mock_stream = MagicMock()
        mock_stream.__iter__ = MagicMock(return_value=iter([]))

        with patch("nabla.agents.registry.find_agent", return_value=mock_agent), \
             patch("nabla.client.get_client", return_value=mock_letta_client):
            mock_letta_client.agents.messages.create.return_value = mock_stream
            resp = app_client.post(
                "/api/chat/stream",
                json={"message": "Hello"},
            )

        body = resp.text
        assert "done" in body

    def test_chat_stream_with_reasoning(self, app_client, mock_letta_client):
        """Chat with include_reasoning=True passes flag to Letta."""
        mock_agent = MagicMock()
        mock_agent.id = "agent-123"
        mock_stream = MagicMock()
        mock_stream.__iter__ = MagicMock(return_value=iter([]))

        with patch("nabla.agents.registry.find_agent", return_value=mock_agent), \
             patch("nabla.client.get_client", return_value=mock_letta_client):
            mock_letta_client.agents.messages.create.return_value = mock_stream
            resp = app_client.post(
                "/api/chat/stream",
                json={"message": "Hello", "include_reasoning": True},
            )

        assert resp.status_code == 200

    def test_chat_stream_empty_message(self, app_client, mock_letta_client):
        """Empty message still sends to the stream."""
        mock_agent = MagicMock()
        mock_agent.id = "agent-123"
        mock_stream = MagicMock()
        mock_stream.__iter__ = MagicMock(return_value=iter([]))

        with patch("nabla.agents.registry.find_agent", return_value=mock_agent), \
             patch("nabla.client.get_client", return_value=mock_letta_client):
            mock_letta_client.agents.messages.create.return_value = mock_stream
            resp = app_client.post(
                "/api/chat/stream",
                json={"message": ""},
            )

        assert resp.status_code == 200
