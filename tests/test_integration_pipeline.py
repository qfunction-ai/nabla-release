"""Integration tests for the pipeline execution."""

import os

import pytest


@pytest.mark.integration
def test_pipeline_single_type(bootstrap_system, tmp_path, monkeypatch):
    """Pipeline with a single log type should return all step results."""
    from nabla.pipeline import run_pipeline

    # Redirect data dir to tmp_path so state files are writable on the host
    monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))
    import nabla.config as cfg
    cfg._settings = None  # force re-read of settings

    results = run_pipeline(
        client=None,  # will create its own
        log_types="auth",
        log_count=10,
    )

    assert "ingestion" in results
    assert "anomaly" in results
    assert "correlation" in results
    assert "supervisor" in results
    assert "auth" in results["ingestion"]


@pytest.mark.integration
def test_pipeline_multi_type(bootstrap_system, tmp_path, monkeypatch):
    """Pipeline with 'all' log types should ingest all 4 types."""
    from nabla.pipeline import run_pipeline

    # Redirect data dir to tmp_path so state files are writable on the host
    monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))
    import nabla.config as cfg
    cfg._settings = None  # force re-read of settings

    results = run_pipeline(
        log_types="all",
        log_count=10,
    )

    assert "ingestion" in results
    # Should mention all 4 types
    for t in ["auth", "network", "dns", "endpoint"]:
        assert t in results["ingestion"]


@pytest.mark.integration
def test_pipeline_run_history(bootstrap_system, tmp_path, monkeypatch):
    """After a pipeline run, the run should appear in history."""
    from nabla.pipeline import run_pipeline
    from nabla.history import list_runs

    # Redirect data dir to tmp_path so run history is writable on the host
    monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))
    import nabla.config as cfg
    cfg._settings = None  # force re-read of settings

    results = run_pipeline(log_types="auth", log_count=10)

    runs = list_runs(limit=5)
    assert len(runs) >= 1
    latest = runs[0]
    assert latest["success"] is True
    assert latest["anomaly_count"] is not None


@pytest.mark.integration
def test_pipeline_step_durations(bootstrap_system, tmp_path, monkeypatch):
    """Pipeline run should record step durations."""
    from nabla.pipeline import run_pipeline
    from nabla.history import list_runs

    # Redirect data dir to tmp_path so run history is writable on the host
    monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))
    import nabla.config as cfg
    cfg._settings = None  # force re-read of settings

    results = run_pipeline(log_types="auth", log_count=10)

    runs = list_runs(limit=1)
    latest = runs[0]
    assert latest["step_durations"] is not None
    assert "ingestion" in latest["step_durations"]
    assert "anomaly" in latest["step_durations"]
    assert "correlation" in latest["step_durations"]
    assert "supervisor" in latest["step_durations"]
    # All durations should be non-negative (supervisor can be 0.0 if skipped in baseline)
    for step, duration in latest["step_durations"].items():
        assert duration >= 0, f"Step {step} has negative duration {duration}"


@pytest.mark.integration
def test_pipeline_baseline_snapshot(bootstrap_system):
    """After a pipeline run, the baseline snapshots JSONL file should have entries."""
    from letta_client import Letta
    from nabla.pipeline import run_pipeline
    from nabla.config import get_settings

    results = run_pipeline(log_types="auth", log_count=10)

    # Check baseline snapshots JSONL file
    import json
    settings = get_settings()
    path = settings.baseline_snapshots_file
    assert os.path.exists(path), f"Baseline snapshots file not found: {path}"

    baseline_found = False
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, dict) and data.get("snapshot_type") == "baseline":
                    baseline_found = True
                    break
            except json.JSONDecodeError:
                pass
    assert baseline_found, "No baseline snapshot found in JSONL file"


@pytest.mark.integration
def test_pipeline_error_without_bootstrap(letta_client):
    """Running pipeline without bootstrap should raise RuntimeError."""
    from nabla.pipeline import run_pipeline
    from nabla.agents.bootstrap import teardown

    # Ensure no nabla agents exist
    teardown(letta_client)

    with pytest.raises(RuntimeError, match="Expected 1 Nabla agent"):
        run_pipeline(log_types="auth", log_count=10)
