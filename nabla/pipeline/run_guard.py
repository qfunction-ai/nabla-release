"""R6-8 (round 6): the cross-run pipeline guard.

One pipeline run at a time, process-wide and cross-process. Acquired
NON-BLOCKING (D8): a second run fails fast with a clear error instead
of queueing behind minutes of LLM work. flock semantics mean the lock
releases automatically if the process dies — there is no stale-lock
recovery path because there is no stale-lock state.

Operational note (found live in Phase 11): a SIGKILLed wrapper (say,
a killed witness script) can leave an orphaned child mid-run holding
the flock. `pkill -f "nabla (ingest|run)"` inside the container clears
it. The error message could say this; kept terse for now.
"""

from __future__ import annotations

import atexit
import fcntl
import logging
from pathlib import Path

logger = logging.getLogger("nabla.pipeline.run_guard")

_LOCK_PATH = Path("/tmp/nabla_pipeline.lock")

_active: list = []  # at most one guard per process


class RunGuard:
    """Holds the exclusive flock for the process lifetime."""

    def __init__(self, fd):
        self._fd = fd
        _active.append(self)

    def release(self) -> None:
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            self._fd.close()
            self._fd = None
            if self in _active:
                _active.remove(self)


def acquire_run_guard(path: str | None = None) -> RunGuard:
    """Acquire the run guard or raise RuntimeError (never blocks).

    Tests pass a per-tmp path to avoid cross-test interference; the
    default is the fixed /tmp path shared by scheduler and API.
    """
    p = Path(path) if path else _LOCK_PATH
    fd = open(p, "w")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fd.close()
        raise RuntimeError(
            "another pipeline run is active — retry when it completes "
            "(R6-8 non-blocking exclusion)")
    guard = RunGuard(fd)
    # Belt-and-suspenders: run_pipeline releases per-call; atexit covers
    # any path that forgets (and clear-releases on hard interpreter exit)
    atexit.register(guard.release)
    return guard
