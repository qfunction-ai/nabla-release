"""R6-2 (round 6): the SSE stream must not hold the run lock across yields.

The concurrency test reproduces the freeze shape: a suspended generator
holding _run_lock while another handler tries to acquire it. Under the
old code the second acquire blocks the event loop; under copy-then-yield
it completes immediately.
"""

import asyncio
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient


def _sse_lines(response):
    for line in response.iter_lines():
        if line.startswith("data: "):
            yield json.loads(line[len("data: "):])


class TestSSELockDiscipline:
    def test_stream_does_not_hold_lock_across_yields(self):
        from nabla.api.pipeline import _run_lock, _current_run
        import nabla.api.pipeline as _pipe
        # Simulate a running pipeline (_current_run is module-global,
        # None until a run starts)
        _prev = _pipe._current_run
        _pipe._current_run = {"run_id": "r1", "status": "running",
                              "current_step": "detecting"}

        from nabla.server import app
        with TestClient(app) as client:
            # Start the SSE stream in a thread; read the first event
            received = []
            def read_stream():
                with client.stream("POST", "/api/pipeline/stream") as resp:
                    for ev in _sse_lines(resp):
                        received.append(ev)
                        break  # first event only; generator suspends
            t = threading.Thread(target=read_stream)
            t.start()
            time.sleep(0.3)  # let the generator suspend inside its loop

            # The probe: acquire the lock from another thread WITH a
            # timeout. Old code: the suspended generator holds it ->
            # timeout -> the freeze shape. New code: instant.
            acquired = _run_lock.acquire(timeout=2.0)
            assert acquired, (
                "R6-2: the SSE generator holds _run_lock while suspended "
                "at yield — other handlers freeze")
            if acquired:
                _run_lock.release()
            t.join(timeout=5)
        _pipe._current_run = _prev

    def test_lock_reacquired_between_sse_polls(self):
        """The realistic victim, without the auth scaffolding: the status
        handler's lock acquisition is exactly this probe. A second
        acquire-while-suspended must succeed within the poll interval."""
        import nabla.api.pipeline as _pipe
        from nabla.api.pipeline import _run_lock
        _prev = _pipe._current_run
        _pipe._current_run = {"run_id": "r2", "status": "running",
                              "current_step": "supervisor"}
        try:
            from nabla.server import app
            with TestClient(app) as client:
                def read_stream():
                    with client.stream("POST", "/api/pipeline/stream") as resp:
                        for _ in _sse_lines(resp):
                            break
                t = threading.Thread(target=read_stream)
                t.start()
                time.sleep(0.3)
                t0 = time.monotonic()
                acquired = _run_lock.acquire(timeout=2.0)
                elapsed = time.monotonic() - t0
                assert acquired and elapsed < 1.5, (
                    f"R6-2: lock acquisition took {elapsed:.1f}s while a "
                    f"stream was suspended — the freeze shape")
                if acquired:
                    _run_lock.release()
                t.join(timeout=5)
        finally:
            _pipe._current_run = _prev
