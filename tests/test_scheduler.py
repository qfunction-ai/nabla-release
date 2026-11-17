"""Tests for scheduler module."""

import signal
import threading
import time
from unittest.mock import MagicMock, patch

import nabla.scheduler
import pytest
from nabla.scheduler import (
    _pipeline_job,
    run_scheduler_loop,
    scheduler_status,
    start_scheduler,
    stop_scheduler,
)


@pytest.fixture(autouse=True)
def _reset_global_scheduler():
    """Reset the global _scheduler and _lock between every test to avoid state leakage."""
    yield
    # Ensure any running scheduler is shut down, then nuke the global
    if nabla.scheduler._scheduler and nabla.scheduler._scheduler.running:
        nabla.scheduler._scheduler.shutdown(wait=False)
    nabla.scheduler._scheduler = None


# ---------------------------------------------------------------------------
# _pipeline_job
# ---------------------------------------------------------------------------

@patch("nabla.scheduler.logger")
@patch("nabla.pipeline.run_pipeline")
@patch("nabla.client.get_client")
def test_pipeline_job_calls_run_pipeline_with_correct_args(mock_get_client, mock_run_pipeline, mock_logger):
    """_pipeline_job fetches a client and delegates to run_pipeline with the given kwargs."""
    mock_client = MagicMock()
    mock_get_client.return_value = mock_client

    _pipeline_job(
        log_types=["auth", "dns"],
        log_count=100,
        source="manual",
        watchlist_groups=["group_a"],
    )

    mock_get_client.assert_called_once()
    mock_run_pipeline.assert_called_once_with(
        mock_client,
        log_types=["auth", "dns"],
        log_count=100,
        source="manual",
        watchlist_groups=["group_a"],
    )


@patch("nabla.scheduler.logger")
@patch("nabla.pipeline.run_pipeline", side_effect=RuntimeError("boom"))
@patch("nabla.client.get_client")
def test_pipeline_job_logs_error_on_exception(mock_get_client, mock_run_pipeline, mock_logger):
    """When run_pipeline raises, _pipeline_job logs the error and does not crash."""
    mock_get_client.return_value = MagicMock()

    # Should not raise
    _pipeline_job(log_types=["auth"], log_count=10)

    mock_logger.error.assert_called_once()
    call_args = mock_logger.error.call_args
    assert "Pipeline run failed" in call_args[0][0]


@patch("nabla.scheduler.logger")
@patch("nabla.pipeline.run_pipeline")
@patch("nabla.client.get_client")
def test_pipeline_job_default_kwargs(mock_get_client, mock_run_pipeline, mock_logger):
    """_pipeline_job uses 'auto' source and None watchlist_groups by default."""
    mock_get_client.return_value = MagicMock()

    _pipeline_job(log_types=["network"], log_count=25)

    mock_run_pipeline.assert_called_once_with(
        mock_get_client.return_value,
        log_types=["network"],
        log_count=25,
        source="auto",
        watchlist_groups=None,
    )


# ---------------------------------------------------------------------------
# start_scheduler
# ---------------------------------------------------------------------------

@patch("nabla.scheduler.logger")
def test_start_scheduler_happy_path(mock_logger):
    """start_scheduler creates a running scheduler with the right job config."""
    start_scheduler(
        interval_minutes=10,
        log_types=["auth"],
        log_count=20,
        source="manual",
        watchlist_groups=["grp"],
    )

    status = scheduler_status()
    assert status["running"] is True
    assert status["next_run"] is not None

    # Verify the job was added with correct id
    sched = nabla.scheduler._scheduler
    jobs = sched.get_jobs()
    assert len(jobs) == 1
    assert jobs[0].id == "nabla_pipeline"

    stop_scheduler()


@patch("nabla.scheduler.logger")
def test_start_scheduler_already_running(mock_logger):
    """Calling start_scheduler twice is a no-op the second time (early return)."""
    start_scheduler(interval_minutes=5, log_types=["dns"])

    # Second call should return early — logger.info("Already running.")
    start_scheduler(interval_minutes=5, log_types=["dns"])

    # The "Already running." message should have been logged
    assert any("Already running" in str(call) for call in mock_logger.info.call_args_list)

    stop_scheduler()


@patch("nabla.pipeline._resolve_log_types", return_value=["auth", "network", "dns", "endpoint"])
@patch("nabla.scheduler.logger")
def test_start_scheduler_resolves_log_types_when_none(mock_logger, mock_resolve):
    """When log_types is None, start_scheduler resolves them via _resolve_log_types('all')."""
    start_scheduler(interval_minutes=5, log_types=None, log_count=50)

    mock_resolve.assert_called_once_with("all")

    # The job kwargs should contain the resolved types
    sched = nabla.scheduler._scheduler
    jobs = sched.get_jobs()
    assert len(jobs) == 1
    assert jobs[0].kwargs["log_types"] == ["auth", "network", "dns", "endpoint"]

    stop_scheduler()


# ---------------------------------------------------------------------------
# stop_scheduler
# ---------------------------------------------------------------------------

@patch("nabla.scheduler.logger")
def test_stop_scheduler_running(mock_logger):
    """stop_scheduler shuts down a running scheduler."""
    start_scheduler(interval_minutes=5, log_types=["auth"])
    assert scheduler_status()["running"] is True

    stop_scheduler()

    # After stopping, the global scheduler object still exists but is no longer running
    assert nabla.scheduler._scheduler is not None
    assert nabla.scheduler._scheduler.running is False
    mock_logger.info.assert_any_call("Stopped.")


@patch("nabla.scheduler.logger")
def test_stop_scheduler_not_running(mock_logger):
    """stop_scheduler on a non-running scheduler logs 'Not running.' and does not crash."""
    # _scheduler is None from the autouse fixture
    stop_scheduler()

    mock_logger.info.assert_any_call("Not running.")


# ---------------------------------------------------------------------------
# scheduler_status
# ---------------------------------------------------------------------------

def test_scheduler_status_not_running():
    """Scheduler status reports not running when not started."""
    status = scheduler_status()
    assert status["running"] is False
    assert status["next_run"] is None


@patch("nabla.scheduler.logger")
def test_scheduler_status_running(mock_logger):
    """Scheduler status reports running with a next_run time after start."""
    start_scheduler(interval_minutes=5, log_types=["dns"])

    status = scheduler_status()
    assert status["running"] is True
    assert status["next_run"] is not None

    stop_scheduler()


# ---------------------------------------------------------------------------
# run_scheduler_loop
# ---------------------------------------------------------------------------

@patch("nabla.scheduler._pipeline_job")
@patch("nabla.scheduler.start_scheduler")
@patch("nabla.scheduler.stop_scheduler")
@patch("nabla.scheduler.logger")
def test_run_scheduler_loop_calls_start_and_initial_job(mock_logger, mock_stop, mock_start, mock_pipeline_job):
    """run_scheduler_loop starts the scheduler and runs an initial pipeline job."""
    captured_handlers = {}

    def fake_signal(signum, handler):
        captured_handlers[signum] = handler
        # Don't call the real signal.signal — it only works in the main thread
        return None

    with patch("signal.signal", side_effect=fake_signal):
        # Run run_scheduler_loop in a background thread
        loop_thread = threading.Thread(
            target=run_scheduler_loop,
            kwargs={"interval_minutes": 5, "log_types": ["auth"], "log_count": 10},
            daemon=True,
        )
        loop_thread.start()

        # Give it a moment to register signal handlers
        time.sleep(0.2)

        # Simulate SIGTERM by calling the captured handler
        assert signal.SIGTERM in captured_handlers, "SIGTERM handler not registered"
        captured_handlers[signal.SIGTERM](signal.SIGTERM, None)

        loop_thread.join(timeout=3)

    mock_start.assert_called_once_with(5, ["auth"], 10, "auto", None)
    mock_pipeline_job.assert_called_once_with(["auth"], 10, "auto", None)
    mock_stop.assert_called_once()


@patch("nabla.scheduler._pipeline_job")
@patch("nabla.scheduler.start_scheduler")
@patch("nabla.scheduler.stop_scheduler")
@patch("nabla.scheduler.logger")
def test_run_scheduler_loop_uses_default_log_types_when_none(mock_logger, mock_stop, mock_start, mock_pipeline_job):
    """When log_types is None, run_scheduler_loop passes default types to _pipeline_job."""
    captured_handlers = {}

    def fake_signal(signum, handler):
        captured_handlers[signum] = handler
        return None  # Don't call real signal.signal

    with patch("signal.signal", side_effect=fake_signal):
        loop_thread = threading.Thread(
            target=run_scheduler_loop,
            kwargs={"interval_minutes": 5, "log_types": None, "log_count": 50},
            daemon=True,
        )
        loop_thread.start()
        time.sleep(0.2)

        captured_handlers[signal.SIGTERM](signal.SIGTERM, None)
        loop_thread.join(timeout=3)

    # _pipeline_job should be called with the fallback default types
    mock_pipeline_job.assert_called_once_with(
        ["auth", "network", "dns", "endpoint"], 50, "auto", None,
    )


@patch("nabla.scheduler._pipeline_job")
@patch("nabla.scheduler.start_scheduler")
@patch("nabla.scheduler.stop_scheduler")
@patch("nabla.scheduler.logger")
def test_run_scheduler_loop_registers_sigint_handler(mock_logger, mock_stop, mock_start, mock_pipeline_job):
    """run_scheduler_loop registers handlers for both SIGTERM and SIGINT."""
    captured_handlers = {}

    def fake_signal(signum, handler):
        captured_handlers[signum] = handler
        return None  # Don't call real signal.signal

    with patch("signal.signal", side_effect=fake_signal):
        loop_thread = threading.Thread(
            target=run_scheduler_loop,
            kwargs={"interval_minutes": 5, "log_types": ["dns"], "log_count": 10},
            daemon=True,
        )
        loop_thread.start()
        time.sleep(0.2)

        assert signal.SIGTERM in captured_handlers
        assert signal.SIGINT in captured_handlers

        # Trigger shutdown
        captured_handlers[signal.SIGTERM](signal.SIGTERM, None)
        loop_thread.join(timeout=3)
