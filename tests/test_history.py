"""Tests for pipeline run history."""

import importlib

import nabla.config
import nabla.history as h
from nabla.history import new_run, complete_run, save_run, list_runs


def test_new_run():
    """new_run creates a record with ID and start time."""
    run = new_run(log_types=["auth", "dns"], log_count=50)
    assert run["run_id"]
    assert run["started_at"]
    assert run["log_types"] == ["auth", "dns"]
    assert run["log_count"] == 50
    assert run["success"] is False
    assert run["finished_at"] is None


def test_complete_run_success():
    """complete_run marks a run as successful with counts."""
    run = new_run(log_types=["auth"], log_count=20)
    complete_run(run, anomaly_count=5, findings_count=3)
    assert run["success"] is True
    assert run["anomaly_count"] == 5
    assert run["findings_count"] == 3
    assert run["finished_at"] is not None
    assert run["error"] is None


def test_complete_run_with_step_durations():
    """complete_run stores step durations rounded to 2 decimal places."""
    run = new_run(log_types=["auth"], log_count=20)
    complete_run(
        run,
        anomaly_count=5,
        findings_count=3,
        step_durations={"ingestion": 1.234, "anomaly": 10.567, "correlation": 5.0, "supervisor": 8.999},
    )
    assert run["step_durations"] == {
        "ingestion": 1.23,
        "anomaly": 10.57,
        "correlation": 5.0,
        "supervisor": 9.0,
    }


def test_new_run_step_durations_default():
    """new_run should have step_durations as None."""
    run = new_run(log_types=["auth"], log_count=10)
    assert run["step_durations"] is None


def test_complete_run_failure():
    """complete_run marks a run as failed with error."""
    run = new_run(log_types=["dns"], log_count=10)
    complete_run(run, error="Connection refused")
    assert run["success"] is False
    assert run["error"] == "Connection refused"


def test_save_and_list_runs(tmp_path, monkeypatch):
    """save_run persists to file, list_runs returns recent runs."""
    runs_file = str(tmp_path / "runs.json")
    monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))

    # Re-import to pick up new env
    import importlib
    import nabla.config
    importlib.reload(nabla.config)
    import nabla.history as h
    importlib.reload(h)

    run1 = new_run(log_types=["auth"], log_count=10)
    complete_run(run1, anomaly_count=2)
    h.save_run(run1)

    run2 = new_run(log_types=["dns"], log_count=20)
    complete_run(run2, anomaly_count=7)
    h.save_run(run2)

    runs = h.list_runs(limit=10)
    assert len(runs) == 2
    # Newest first
    assert runs[0]["run_id"] == run2["run_id"]
    assert runs[1]["run_id"] == run1["run_id"]


def test_list_runs_limit(tmp_path, monkeypatch):
    """list_runs respects the limit parameter."""
    monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))

    import importlib
    import nabla.config
    importlib.reload(nabla.config)
    import nabla.history as h
    importlib.reload(h)

    for i in range(5):
        run = new_run(log_types=["auth"], log_count=10)
        complete_run(run, anomaly_count=i)
        h.save_run(run)

    runs = h.list_runs(limit=3)
    assert len(runs) == 3


# --- Error path tests ---


def _reload_history(monkeypatch, data_dir):
    """Helper: set NABLA_DATA_DIR and reload modules so history picks it up."""
    monkeypatch.setenv("NABLA_DATA_DIR", str(data_dir))
    importlib.reload(nabla.config)
    importlib.reload(h)


def test_runs_file_unwritable_dir(tmp_path, monkeypatch):
    """_runs_file returns None when data dir is not writable."""
    _reload_history(monkeypatch, "/nonexistent_dir")
    assert h._runs_file() is None


def test_load_runs_corrupted_json(tmp_path, monkeypatch):
    """_load_runs returns empty list for corrupted JSON file."""
    _reload_history(monkeypatch, tmp_path)

    runs_file = str(tmp_path / "runs.json")
    with open(runs_file, "w") as f:
        f.write("not valid json{{{")

    assert h._load_runs(runs_file) == []


def test_load_runs_oserror(tmp_path, monkeypatch):
    """_load_runs returns empty list on OSError."""
    _reload_history(monkeypatch, tmp_path)

    runs_file = str(tmp_path / "runs.json")
    # Create the file so os.path.exists returns True
    with open(runs_file, "w") as f:
        f.write("[]")

    import builtins
    _real_open = builtins.open

    def _raising_open(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(builtins, "open", _raising_open)
    assert h._load_runs(runs_file) == []


def test_save_runs_oserror(tmp_path, monkeypatch):
    """_save_runs logs warning but doesn't crash on OSError."""
    _reload_history(monkeypatch, tmp_path)

    import nabla.persistence

    def _raising_atomic_write(*args, **kwargs):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(nabla.persistence, "atomic_write_json", _raising_atomic_write)

    # Should not raise
    h._save_runs(str(tmp_path / "runs.json"), [{"test": True}])


def test_new_run_with_operator():
    """new_run sets operator field when provided."""
    run = new_run(log_types=["auth"], log_count=10, operator="alice")
    assert run["operator"] == "alice"


def test_new_run_operator_env_fallback(monkeypatch):
    """new_run uses NABLA_OPERATOR env var as fallback."""
    monkeypatch.setenv("NABLA_OPERATOR", "bob")
    run = new_run(log_types=["auth"], log_count=10)
    assert run["operator"] == "bob"


def test_complete_run_no_step_durations():
    """complete_run with step_durations=None doesn't set step_durations."""
    run = new_run(log_types=["auth"], log_count=10)
    complete_run(run, anomaly_count=5, step_durations=None)
    assert run["step_durations"] is None


def test_save_run_no_runs_file(tmp_path, monkeypatch):
    """save_run returns early when _runs_file returns None."""
    _reload_history(monkeypatch, "/nonexistent_dir")

    run = new_run(log_types=["auth"], log_count=10)
    # Should not raise
    h.save_run(run)


def test_list_runs_no_runs_file(tmp_path, monkeypatch):
    """list_runs returns empty list when _runs_file returns None."""
    _reload_history(monkeypatch, "/nonexistent_dir")
    assert h.list_runs() == []
