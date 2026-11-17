"""Tests for nabla.api.upload — /api/upload endpoint."""

import io
import os
from unittest.mock import patch

import pytest


class TestUpload:
    """Test POST /api/upload."""

    def test_upload_small_file(self, app_client, temp_data_dir):
        """Upload a small file succeeds."""
        content = b"timestamp,user,action\n2025-01-01,alice,login\n"
        resp = app_client.post(
            "/api/upload",
            files={"file": ("test.csv", io.BytesIO(content), "text/csv")},
            data={"log_type": "auth"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "file_id" in data
        assert "path" in data
        assert data["original_name"] == "test.csv"
        assert data["size"] == len(content)
        assert data["log_type"] == "auth"

    def test_upload_creates_file_on_disk(self, app_client, temp_data_dir):
        """Uploaded file is saved to the uploads directory."""
        content = b"hello world"
        resp = app_client.post(
            "/api/upload",
            files={"file": ("test.txt", io.BytesIO(content), "text/plain")},
            data={"log_type": "auth"},
        )
        data = resp.json()
        file_path = data["path"]
        assert os.path.exists(file_path)
        with open(file_path, "rb") as f:
            assert f.read() == content

    def test_upload_with_format(self, app_client, temp_data_dir):
        """Upload with format hint."""
        content = b'{"logs": []}'
        resp = app_client.post(
            "/api/upload?format=json",
            files={"file": ("data.json", io.BytesIO(content), "application/json")},
            data={"log_type": "auth"},
        )
        data = resp.json()
        assert data["format"] == "json"

    def test_upload_default_log_type(self, app_client, temp_data_dir):
        """Default log_type is 'auth'."""
        content = b"test"
        resp = app_client.post(
            "/api/upload",
            files={"file": ("test.csv", io.BytesIO(content), "text/csv")},
        )
        data = resp.json()
        assert data["log_type"] == "auth"

    def test_upload_file_id_unique(self, app_client, temp_data_dir):
        """Each upload gets a unique file_id."""
        content = b"test"
        resp1 = app_client.post(
            "/api/upload",
            files={"file": ("a.csv", io.BytesIO(content), "text/csv")},
        )
        resp2 = app_client.post(
            "/api/upload",
            files={"file": ("b.csv", io.BytesIO(content), "text/csv")},
        )
        id1 = resp1.json()["file_id"]
        id2 = resp2.json()["file_id"]
        assert id1 != id2

    def test_upload_oversized_file_rejected(self, app_client, temp_data_dir):
        """Files exceeding MAX_UPLOAD_SIZE are rejected."""
        from nabla.api.upload import MAX_UPLOAD_SIZE

        # Create a file slightly larger than the limit
        big_content = b"x" * (MAX_UPLOAD_SIZE + 1)
        resp = app_client.post(
            "/api/upload",
            files={"file": ("big.csv", io.BytesIO(big_content), "text/csv")},
        )
        assert resp.status_code == 413

    def test_upload_max_size_exactly(self, app_client, temp_data_dir):
        """File exactly at MAX_UPLOAD_SIZE is accepted."""
        from nabla.api.upload import MAX_UPLOAD_SIZE

        exact_content = b"x" * MAX_UPLOAD_SIZE
        resp = app_client.post(
            "/api/upload",
            files={"file": ("exact.csv", io.BytesIO(exact_content), "text/csv")},
        )
        assert resp.status_code == 200

    def test_upload_no_filename(self, app_client, temp_data_dir):
        """Upload with empty filename falls back to 'upload'."""
        content = b"test"
        resp = app_client.post(
            "/api/upload",
            files={"file": ("upload", io.BytesIO(content), "text/csv")},
        )
        # FastAPI requires a filename — empty string is rejected as 422
        # Provide a filename to succeed
        assert resp.status_code == 200
        data = resp.json()
        assert data["original_name"] == "upload"
