"""Tests for ingestion state tracking."""

import os
import tempfile

from nabla.ingestion_state import (
    get_last_ingestion,
    load_state,
    reset_state,
    save_state,
    update_last_ingestion,
)


def _tmp_state():
    d = tempfile.mkdtemp()
    return os.path.join(d, "ingestion_state.json")


def test_load_state_missing():
    path = _tmp_state()
    data = load_state(path)
    assert data == {}


def test_save_and_load():
    path = _tmp_state()
    save_state(path, {"splunk": {"last_ingestion": "2026-04-28T08:00:00Z"}})
    data = load_state(path)
    assert data["splunk"]["last_ingestion"] == "2026-04-28T08:00:00Z"


def test_get_last_ingestion():
    path = _tmp_state()
    save_state(path, {"splunk": {"last_ingestion": "2026-04-28T08:00:00Z"}})
    result = get_last_ingestion(path, "splunk")
    assert result == "2026-04-28T08:00:00Z"


def test_get_last_ingestion_missing():
    path = _tmp_state()
    result = get_last_ingestion(path, "splunk")
    assert result is None


def test_update_last_ingestion():
    path = _tmp_state()
    update_last_ingestion(path, "splunk", total_ingested=100)
    data = load_state(path)
    assert "splunk" in data
    assert data["splunk"]["last_ingestion"] is not None
    assert data["splunk"]["total_ingested"] == 100


def test_update_accumulates_total():
    path = _tmp_state()
    update_last_ingestion(path, "splunk", total_ingested=100)
    update_last_ingestion(path, "splunk", total_ingested=50)
    data = load_state(path)
    assert data["splunk"]["total_ingested"] == 150


def test_reset_specific_connector():
    path = _tmp_state()
    update_last_ingestion(path, "splunk", total_ingested=100)
    update_last_ingestion(path, "elastic", total_ingested=200)
    reset_state(path, "splunk")
    data = load_state(path)
    assert "splunk" not in data
    assert "elastic" in data


def test_reset_all():
    path = _tmp_state()
    update_last_ingestion(path, "splunk", total_ingested=100)
    reset_state(path)
    assert not os.path.exists(path)


# --- Error path tests ---


def test_load_state_corrupted_json():
    """load_state returns empty dict for corrupted JSON file."""
    path = _tmp_state()
    with open(path, "w") as f:
        f.write("not valid json{{{")

    data = load_state(path)
    assert data == {}


def test_load_state_oserror(tmp_path):
    """load_state returns empty dict on OSError."""
    path = str(tmp_path / "ingestion_state.json")
    with open(path, "w") as f:
        f.write("{}")

    import builtins
    _real_open = builtins.open

    def _raising_open(*args, **kwargs):
        raise OSError("permission denied")

    original = builtins.open
    builtins.open = _raising_open
    try:
        data = load_state(path)
        assert data == {}
    finally:
        builtins.open = original


def test_save_state_relative_path(tmp_path, monkeypatch):
    """save_state with relative path uses '.' as dirname fallback."""
    monkeypatch.chdir(tmp_path)
    path = "ingestion_state.json"  # relative path — dirname is ""
    save_state(path, {"test": True})
    data = load_state(os.path.join(str(tmp_path), path))
    assert data == {"test": True}


def test_update_last_ingestion_new_connector():
    """update_last_ingestion with a new connector creates a new entry."""
    path = _tmp_state()
    # Start with an existing connector
    save_state(path, {"splunk": {"last_ingestion": "2026-04-28T08:00:00Z", "total_ingested": 100}})
    # Add a new connector
    update_last_ingestion(path, "elastic", total_ingested=50)
    data = load_state(path)
    assert "splunk" in data
    assert "elastic" in data
    assert data["elastic"]["total_ingested"] == 50


def test_reset_state_file_not_exists():
    """reset_state with no file doesn't crash."""
    path = _tmp_state()
    # File doesn't exist yet — reset all should not crash
    reset_state(path)


def test_reset_state_os_remove_fails(tmp_path, monkeypatch):
    """reset_state doesn't crash when os.remove raises."""
    path = str(tmp_path / "ingestion_state.json")
    with open(path, "w") as f:
        f.write("{}")

    monkeypatch.setattr(os, "remove", lambda p: (_ for _ in ()).throw(FileNotFoundError("gone")))
    # Should not raise
    reset_state(path)
