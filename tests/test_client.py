"""Tests for the Letta client factory."""

from unittest.mock import MagicMock, patch

import pytest

from nabla.client import get_client, reset_client


class TestGetClient:
    """Tests for get_client singleton factory."""

    def setup_method(self):
        """Reset the singleton before each test."""
        reset_client()

    def teardown_method(self):
        """Reset the singleton after each test."""
        reset_client()

    @patch("nabla.client.Letta")
    @patch("nabla.client.get_settings")
    def test_creates_client_on_first_call(self, mock_settings, mock_letta_cls):
        """First call creates a new Letta client."""
        mock_settings_obj = MagicMock()
        mock_settings_obj.letta_base_url = "http://localhost:8283"
        mock_settings_obj.letta_api_key = None
        mock_settings.return_value = mock_settings_obj

        mock_instance = MagicMock()
        mock_letta_cls.return_value = mock_instance

        client = get_client()
        assert client is mock_instance
        mock_letta_cls.assert_called_once()

    @patch("nabla.client.Letta")
    @patch("nabla.client.get_settings")
    def test_returns_same_instance_on_second_call(self, mock_settings, mock_letta_cls):
        """Second call returns the cached singleton without re-creating."""
        mock_settings_obj = MagicMock()
        mock_settings_obj.letta_base_url = "http://localhost:8283"
        mock_settings_obj.letta_api_key = None
        mock_settings.return_value = mock_settings_obj

        mock_instance = MagicMock()
        mock_letta_cls.return_value = mock_instance

        client1 = get_client()
        client2 = get_client()
        assert client1 is client2
        assert mock_letta_cls.call_count == 1

    @patch("nabla.client.Letta")
    @patch("nabla.client.get_settings")
    def test_client_with_api_key(self, mock_settings, mock_letta_cls):
        """Client passes API key when configured."""
        mock_settings_obj = MagicMock()
        mock_settings_obj.letta_base_url = "http://localhost:8283"
        mock_settings_obj.letta_api_key = "test-key-123"
        mock_settings.return_value = mock_settings_obj

        mock_instance = MagicMock()
        mock_letta_cls.return_value = mock_instance

        get_client()
        call_kwargs = mock_letta_cls.call_args.kwargs
        assert call_kwargs.get("token") == "test-key-123"

    @patch("nabla.client.Letta")
    @patch("nabla.client.get_settings")
    def test_client_without_api_key(self, mock_settings, mock_letta_cls):
        """Client omits token when no API key configured."""
        mock_settings_obj = MagicMock()
        mock_settings_obj.letta_base_url = "http://localhost:8283"
        mock_settings_obj.letta_api_key = None
        mock_settings.return_value = mock_settings_obj

        mock_instance = MagicMock()
        mock_letta_cls.return_value = mock_instance

        get_client()
        call_kwargs = mock_letta_cls.call_args.kwargs
        assert "token" not in call_kwargs


class TestResetClient:
    """Tests for reset_client."""

    @patch("nabla.client.Letta")
    @patch("nabla.client.get_settings")
    def test_reset_allows_new_client(self, mock_settings, mock_letta_cls):
        """After reset, next call creates a new client."""
        mock_settings_obj = MagicMock()
        mock_settings_obj.letta_base_url = "http://localhost:8283"
        mock_settings_obj.letta_api_key = None
        mock_settings.return_value = mock_settings_obj

        mock_letta_cls.return_value = MagicMock()

        client1 = get_client()
        reset_client()
        client2 = get_client()
        assert mock_letta_cls.call_count == 2
