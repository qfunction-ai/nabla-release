"""SumoLogic import: nabla ingest semantics, resumability, span-clock provenance, verify."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from nabla.config import Settings


def _settings(tmp_path):
    return Settings(
        data_dir=str(tmp_path), letta_base_url="http://localhost:9999",
        embedding_endpoint="http://localhost:11434/v1", splunk_host="",
        sumologic_host="", splunk_validate_url=False, sumologic_validate_url=False,
    )


def _make_dataset(tmp_path, days=3, events_per_day=10):
    """Build a mini baseline dataset with realistic timestamps."""
    import random
    random.seed(7)
    users = ["analyst1", "admin", "svc_backup"]
    d = tmp_path / "baseline"
    d.mkdir(exist_ok=True)
    base = datetime(2026, 8, 10, tzinfo=timezone.utc)
    for day in range(days):
        lines = []
        for i in range(events_per_day):
            t = base + timedelta(days=day, seconds=i * 500)
            lines.append(json.dumps({
                "timestamp": t.isoformat(),
                "user": random.choice(users),
                "action": "login_success",
                "source_ip": f"10.0.1.{random.randint(2,50)}",
                "host": "EC2AMAZ-OCPNFK9",
                "log_type": "auth",
            }))
        (d / f"2026-08-{10+day:02d}.jsonl").write_text("\n".join(lines) + "\n")
    return d


@pytest.fixture
def mock_env(tmp_path):
    """Patch the pipeline so ingest's run_pipeline calls are no-ops."""
    s = _settings(tmp_path)
    with patch("nabla.cli.get_settings", return_value=s), \
         patch("nabla.config.get_settings", return_value=s), \
         patch("nabla.config._settings", s), \
         patch("nabla.cli.get_client"), \
         patch("nabla.pipeline.run_pipeline") as rp:
        rp.return_value = {"ingestion": "ok"}
        yield s, rp


class TestIngestResumability:
    def test_chunk_hash_keyed_on_content(self, tmp_path, mock_env):
        s, rp = mock_env
        from nabla.cli import _chunk_hash
        f1 = tmp_path / "a.jsonl"
        f1.write_text('{"x": 1}\n')
        h1 = _chunk_hash(str(f1))
        f1.write_text('{"x": 2}\n')  # changed content
        h2 = _chunk_hash(str(f1))
        assert h1 != h2, "content change must change the resumability key (review N2)"

    def test_reingest_skips_landed_identical_chunks(self, tmp_path, mock_env):
        s, rp = mock_env
        d = _make_dataset(tmp_path, days=2)
        from nabla.cli import app
        runner = CliRunner()
        with patch("nabla.cli._landed_chunks", return_value=set()), \
             patch("nabla.history.list_runs", return_value=[]):
            r1 = runner.invoke(app, ["ingest", str(d), "--siem-data"])
        assert r1.exit_code == 0, r1.output
        assert rp.call_count == 2  # one per file

        # Simulate the chunks being recorded as landed
        from nabla.cli import _chunk_hash
        import os
        landed = set()
        for f in sorted(d.glob("*.jsonl")):
            landed.add(f"{f.name}:{_chunk_hash(str(f))}")

        rp.reset_mock()
        with patch("nabla.cli._landed_chunks", return_value=landed):
            r2 = runner.invoke(app, ["ingest", str(d), "--siem_data".replace("_", "-")])
        assert r2.exit_code == 0
        assert rp.call_count == 0, "identical chunks must be skipped"
        assert "already landed" in r2.output


class TestIngestSemantics:
    def test_frozen_baseline_passes_update_false(self, tmp_path, mock_env):
        s, rp = mock_env
        d = _make_dataset(tmp_path, days=1)
        from nabla.cli import app
        runner = CliRunner()
        with patch("nabla.cli._landed_chunks", return_value=set()):
            runner.invoke(app, ["ingest", str(d), "--frozen-baseline"])
        assert rp.call_args.kwargs.get("update_baseline") is False

    def test_default_updates_baseline(self, tmp_path, mock_env):
        s, rp = mock_env
        d = _make_dataset(tmp_path, days=1)
        from nabla.cli import app
        runner = CliRunner()
        with patch("nabla.cli._landed_chunks", return_value=set()):
            runner.invoke(app, ["ingest", str(d)])
        assert rp.call_args.kwargs.get("update_baseline") is True

    def test_graph_off_by_default_on_by_flag(self, tmp_path, mock_env):
        s, rp = mock_env
        d = _make_dataset(tmp_path, days=1)
        from nabla.cli import app
        runner = CliRunner()
        with patch("nabla.cli._landed_chunks", return_value=set()):
            runner.invoke(app, ["ingest", str(d)])
            assert rp.call_args.kwargs.get("skip_graph") is True  # Gate 0 default
            runner.invoke(app, ["ingest", str(d), "--graph"])
            assert rp.call_args.kwargs.get("skip_graph") is False


class TestSkipGraph:
    def test_detection_respects_skip_graph(self, tmp_path):
        """run_detection with skip_graph=True never touches the graph layers."""
        from unittest.mock import MagicMock
        from nabla.pipeline.detection import run_detection
        import nabla.pipeline.detection as det_mod

        client = MagicMock()
        agents = {"supervisor": "agent-x"}
        entries = [{"user": "u", "action": "login_success",
                    "timestamp": "2026-08-15T10:00:00Z", "log_type": "auth"} for _ in range(5)]

        called = {"gcn": False, "prov": False, "temp": False}
        import types

        fake_gcn = types.ModuleType("nabla.gcn_lof")
        def _gcn_detect(*a, **k):
            called["gcn"] = True
            return []
        fake_gcn.GCNLOFDetector = types.SimpleNamespace(load=lambda p: types.SimpleNamespace(detect=_gcn_detect, alpha=0.5))
        fake_prov = types.ModuleType("nabla.provenance")
        def _prov(*a, **k):
            called["prov"] = True
            return [], None, None
        fake_prov.detect_provenance_anomalies_with_context = _prov

        with patch.dict("sys.modules", {"nabla.gcn_lof": fake_gcn, "nabla.provenance": fake_prov}):
            s = _settings(tmp_path)
            with patch("nabla.config.get_settings", return_value=s):
                result = run_detection(
                    client, agents, s, entries, MagicMock(),
                    siem_entries_ingested=0, effective_source="file",
                    skip_graph=True,
                )
        assert not called["gcn"] and not called["prov"], "skip_graph must bypass graph layers"


class TestVerify:
    def test_verify_matches_and_misses(self, tmp_path, mock_env):
        s, _ = mock_env
        # Seed incidents
        incs = [
            {"incident_id": "i1", "entity": "analyst1", "finding_type": "brute_force",
             "severity": "high", "status": "new", "updated_at": "2026-09-01T00:00:00Z"},
            {"incident_id": "i2", "entity": "ghost_user", "finding_type": "lolbin",
             "severity": "low", "status": "new", "updated_at": "2026-09-01T00:00:00Z"},
        ]
        (tmp_path / "incidents.json").write_text(json.dumps(incs))
        scenario = {
            "expected_findings": [
                {"entity": "analyst1", "expected_detectors": ["brute_force"], "expected_severity": "high"},
                {"entity": "admin", "expected_detectors": ["entity_new_ip"], "expected_severity": "medium"},
            ]
        }
        sp = tmp_path / "scenario.json"
        sp.write_text(json.dumps(scenario))

        from nabla.cli import _verify_scenario
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _verify_scenario(str(sp))
        out = buf.getvalue()
        assert "✓ analyst1" in out          # matched
        assert "✗ admin" in out             # missed
        assert "+ unexpected: ghost_user" in out  # extra
        assert "1 matched, 1 missed" in out
