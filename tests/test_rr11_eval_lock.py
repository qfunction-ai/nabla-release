"""Round-11 eval-lock witnesses: `nabla eval supervisor` takes the run guard.

The eval resets the reviewer agent (T-1, round 10); a pipeline run holds
the same reviewer. Run concurrently, they reset each other mid-review.
The review's ruling: make the fix, not an operator-discipline rule —
run_evals acquires the same run guard the pipeline uses.
"""
import asyncio
from pathlib import Path

import pytest

from nabla.pipeline.run_guard import acquire_run_guard


@pytest.fixture
def guard_dir(tmp_path, monkeypatch):
    """Point the cached settings at tmp so the guard path is test-local."""
    from nabla.config import Settings
    s = Settings(data_dir=str(tmp_path), letta_base_url="http://localhost:9999",
                 setup_token="", dev_mode=True, embedding_endpoint="http://localhost:11434/v1",
                 splunk_host="", sumologic_host="", splunk_validate_url=False,
                 sumologic_validate_url=False)
    monkeypatch.setattr("nabla.config._settings", s)
    return tmp_path


def test_eval_refuses_while_a_run_holds_the_guard(guard_dir, monkeypatch):
    """A pipeline run in flight → the eval must refuse, not race it."""
    from nabla.evals.supervisor_evals import run_evals
    import nabla.client as client_mod

    def _no_client(*a, **kw):
        raise AssertionError("run_evals must refuse BEFORE building a client")

    monkeypatch.setattr(client_mod, "get_client", _no_client)

    guard = acquire_run_guard()  # a pipeline run holds it
    try:
        with pytest.raises(RuntimeError, match="[Rr]un"):
            asyncio.run(run_evals())
    finally:
        guard.release()


def test_eval_holds_the_guard_during_its_body(guard_dir, monkeypatch):
    """While the eval runs, a pipeline run must refuse in the other
    direction — the eval acquires the same guard for its duration."""
    from nabla.evals import supervisor_evals

    def _probe():
        # Inside run_evals: the guard must already be held. Acquiring it
        # here must REFUSE. If it succeeds, run_evals never took it.
        try:
            g = acquire_run_guard()
        except RuntimeError:
            return  # correct: the eval holds it
        g.release()
        raise AssertionError("run_evals did NOT hold the run guard during its body")

    async def _fake_suite_run():
        _probe()
        raise _Stop()  # probe passed; stop before real eval machinery

    class _Stop(Exception):
        pass

    class _FakeSuite:
        async def run(self):
            return await _fake_suite_run()

    monkeypatch.setattr(supervisor_evals, "setup_blocks_for_eval", lambda: None)
    monkeypatch.setattr(supervisor_evals, "build_supervisor_suite", _FakeSuite)
    with pytest.raises(_Stop):
        asyncio.run(supervisor_evals.run_evals())
