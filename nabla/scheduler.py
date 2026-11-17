"""Scheduled pipeline execution using APScheduler."""

import threading
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from nabla.log import get_logger

_scheduler: BackgroundScheduler | None = None
_lock = threading.Lock()
logger = get_logger("scheduler")


def _pipeline_job(
    log_types: list[str], log_count: int, source: str = "auto",
    watchlist_groups: list[str] | None = None,
) -> None:
    """Job function executed by the scheduler."""
    from nabla.client import get_client
    from nabla.pipeline import run_pipeline

    client = get_client()
    try:
        run_pipeline(client, log_types=log_types, log_count=log_count, source=source, watchlist_groups=watchlist_groups)
    except Exception as e:
        logger.error("Pipeline run failed: %s", e)


def start_scheduler(
    interval_minutes: int = 5,
    log_types: list[str] | None = None,
    log_count: int = 50,
    source: str = "auto",
    watchlist_groups: list[str] | None = None,
) -> None:
    """Start the background scheduler for periodic pipeline runs."""
    global _scheduler

    with _lock:
        if _scheduler and _scheduler.running:
            logger.info("Already running.")
            return

        if log_types is None:
            from nabla.pipeline import _resolve_log_types
            log_types = _resolve_log_types("all")

        _scheduler = BackgroundScheduler()
        _scheduler.add_job(
            _pipeline_job,
            trigger=IntervalTrigger(minutes=interval_minutes),
            kwargs={
                "log_types": log_types, "log_count": log_count,
                "source": source, "watchlist_groups": watchlist_groups,
            },
            id="nabla_pipeline",
            max_instances=1,
            replace_existing=True,
        )
        _scheduler.start()
        logger.info(
            "Started — running every %d min, types=%s, count=%d, source=%s",
            interval_minutes, log_types, log_count, source,
        )


def stop_scheduler() -> None:
    """Stop the background scheduler."""
    global _scheduler

    with _lock:
        if _scheduler and _scheduler.running:
            _scheduler.shutdown(wait=False)
            logger.info("Stopped.")
        else:
            logger.info("Not running.")


def scheduler_status() -> dict:
    """Return current scheduler state."""
    global _scheduler

    if _scheduler and _scheduler.running:
        jobs = _scheduler.get_jobs()
        next_run = None
        for job in jobs:
            if job.next_run_time:
                next_run = job.next_run_time.isoformat()
                break
        return {"running": True, "next_run": next_run}
    return {"running": False, "next_run": None}


def run_scheduler_loop(
    interval_minutes: int = 5,
    log_types: list[str] | None = None,
    log_count: int = 50,
    source: str = "auto",
    watchlist_groups: list[str] | None = None,
) -> None:
    """Start the scheduler and block until interrupted.

    This is the main entry point for the Docker container's scheduler mode.
    """
    import signal

    start_scheduler(interval_minutes, log_types, log_count, source, watchlist_groups)

    # Run an initial pipeline immediately
    _pipeline_job(log_types or ["auth", "network", "dns", "endpoint"], log_count, source, watchlist_groups)

    # Block until SIGTERM/SIGINT
    stop_event = threading.Event()

    def _signal_handler(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    logger.info("Running. Press Ctrl+C or send SIGTERM to stop.")
    stop_event.wait()

    stop_scheduler()
