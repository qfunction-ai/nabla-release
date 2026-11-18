"""F3: non-fatal degradation reporting from anywhere inside a run.

The run record's `degradations` list is built in orchestration, but the
failures it needs to record happen deep inside detectors that have no
reference to it. Before this, a detector could fail on every single run —
as `exfil_volume` did for a whole round — and the run still reported clean,
because the only trace was a `logger.warning` nobody reads.

The sink is context-local rather than a module global so concurrent runs
(the scheduler's and an ad-hoc file upload's) cannot attribute each other's
failures. Outside a collecting run, `report_degradation` is a no-op, so
detectors stay callable from tests and scripts.
"""

from __future__ import annotations

import contextlib
from contextvars import ContextVar
from typing import Iterator

_sink: ContextVar[list[str] | None] = ContextVar("nabla_degradations", default=None)


@contextlib.contextmanager
def collect_degradations(sink: list[str]) -> Iterator[list[str]]:
    """Route `report_degradation` calls into `sink` for the duration."""
    token = _sink.set(sink)
    try:
        yield sink
    finally:
        _sink.reset(token)


def report_degradation(name: str) -> None:
    """Record a non-fatal failure. No-op when no run is collecting."""
    sink = _sink.get()
    if sink is not None and name not in sink:
        sink.append(name)
