"""F3: detector failures must reach the run record, not just the log.

Detectors catch their own exceptions so one bad detector cannot kill a run.
That is the right call, but the only trace used to be a `logger.warning`.
`exfil_volume` raised on every run for an entire round and every run still
reported clean, because nothing connected the swallowed exception to the
run record's `degradations` list.
"""

from __future__ import annotations

import threading

import pytest

from nabla.degradations import collect_degradations, report_degradation


class TestSink:
    def test_no_op_outside_a_collecting_run(self):
        """Detectors must stay callable from tests and scripts."""
        report_degradation("whatever")  # must not raise

    def test_captures_inside_a_collecting_run(self):
        sink: list[str] = []
        with collect_degradations(sink):
            report_degradation("exfil_volume")
        assert sink == ["exfil_volume"]

    def test_deduplicates(self):
        """A detector failing every batch of a run is one degradation."""
        sink: list[str] = []
        with collect_degradations(sink):
            for _ in range(50):
                report_degradation("exfil_volume")
        assert sink == ["exfil_volume"]

    def test_stops_collecting_after_the_block(self):
        sink: list[str] = []
        with collect_degradations(sink):
            report_degradation("inside")
        report_degradation("outside")
        assert sink == ["inside"]

    def test_restores_the_outer_sink_on_exit(self):
        outer: list[str] = []
        with collect_degradations(outer):
            inner: list[str] = []
            with collect_degradations(inner):
                report_degradation("inner_only")
            report_degradation("outer_only")
        assert inner == ["inner_only"]
        assert outer == ["outer_only"]

    def test_restores_the_outer_sink_even_on_exception(self):
        outer: list[str] = []
        with collect_degradations(outer):
            with pytest.raises(RuntimeError):
                with collect_degradations([]):
                    raise RuntimeError("boom")
            report_degradation("after_boom")
        assert outer == ["after_boom"]

    def test_sinks_are_isolated_between_threads(self):
        """Concurrent runs must not attribute each other's failures."""
        a: list[str] = []
        b: list[str] = []
        started = threading.Barrier(2)

        def worker(sink, name):
            with collect_degradations(sink):
                started.wait(timeout=5)
                report_degradation(name)

        threads = [
            threading.Thread(target=worker, args=(a, "from_a")),
            threading.Thread(target=worker, args=(b, "from_b")),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert a == ["from_a"]
        assert b == ["from_b"]


class TestDetectorFailuresReachTheSink:
    """WITNESS: a real detector exception, not a synthetic report call."""

    @pytest.fixture(autouse=True)
    def _data_dir(self, tmp_path, monkeypatch):
        """detect_exfiltration resolves settings, which creates the data dir."""
        monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))
        import nabla.config as cfg
        monkeypatch.setattr(cfg, "_settings", None, raising=False)

    def test_exfil_volume_failure_is_reported(self, monkeypatch):
        from nabla import exfiltration

        def boom(*a, **kw):
            raise RuntimeError("F1-shaped failure")

        monkeypatch.setattr(exfiltration, "_detect_volume_anomaly", boom)
        sink: list[str] = []
        with collect_degradations(sink):
            exfiltration.detect_exfiltration([], entity_profiles=None)
        assert "exfil_volume" in sink

    def test_every_exfil_subdetector_reports(self, monkeypatch):
        from nabla import exfiltration

        def boom(*a, **kw):
            raise RuntimeError("boom")

        for name in ("_detect_volume_anomaly", "_detect_destination_anomaly",
                     "_detect_dns_tunneling", "_detect_staging_pattern"):
            monkeypatch.setattr(exfiltration, name, boom)
        sink: list[str] = []
        with collect_degradations(sink):
            exfiltration.detect_exfiltration([], entity_profiles=None)
        assert set(sink) == {
            "exfil_volume", "exfil_destination", "exfil_dns_tunneling",
            "exfil_staging",
        }

    def test_detect_exfiltration_still_returns_on_failure(self, monkeypatch):
        """Swallowing is deliberate — one bad detector must not kill the run."""
        from nabla import exfiltration

        def boom(*a, **kw):
            raise RuntimeError("boom")

        monkeypatch.setattr(exfiltration, "_detect_volume_anomaly", boom)
        sink: list[str] = []
        with collect_degradations(sink):
            out = exfiltration.detect_exfiltration([], entity_profiles=None)
        assert out == []
        assert sink == ["exfil_volume"]


class TestOrchestrationWiring:
    """The collector must actually be installed around the detection call.

    A sink that nothing fills is the same bug F3 describes, one layer up.
    """

    def test_run_pipeline_installs_the_collector(self):
        import inspect

        from nabla.pipeline import orchestration

        src = inspect.getsource(orchestration._run_pipeline_body)
        assert "collect_degradations(degradations)" in src, (
            "run_pipeline does not wrap run_detection in collect_degradations — "
            "detector failures will not reach the run record"
        )

    def test_run_record_writes_the_degradations_list(self):
        import inspect

        from nabla.pipeline import orchestration

        src = inspect.getsource(orchestration._run_pipeline_body)
        assert 'run_record["degradations"] = degradations' in src
