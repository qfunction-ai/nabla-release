"""Integration tests for the scheduler."""

import pytest


@pytest.mark.integration
def test_scheduler_start_stop():
    """Scheduler should start, report running, and stop cleanly."""
    from nabla.scheduler import start_scheduler, stop_scheduler, scheduler_status

    try:
        start_scheduler(interval_minutes=5, log_count=10)
        status = scheduler_status()
        assert status["running"] is True
        assert status["next_run"] is not None
    finally:
        stop_scheduler()

    status = scheduler_status()
    assert status["running"] is False


@pytest.mark.integration
def test_scheduler_status_when_not_running():
    """Scheduler status should report not running when idle."""
    from nabla.scheduler import scheduler_status

    status = scheduler_status()
    assert status["running"] is False
    assert status["next_run"] is None


@pytest.mark.integration
def test_scheduler_double_start():
    """Starting the scheduler twice should not error."""
    from nabla.scheduler import start_scheduler, stop_scheduler

    try:
        start_scheduler(interval_minutes=5, log_count=10)
        start_scheduler(interval_minutes=5, log_count=10)  # should not raise
    finally:
        stop_scheduler()
