"""Phase mechanics: data-span clock, reset scopes, phase override."""

import json
import os
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


# ---------------------------------------------------------------------------
# Data-span clock
# ---------------------------------------------------------------------------

class TestDataSpanClock:
    def test_record_ingestion_tracks_span(self):
        from nabla.system_state import record_ingestion

        state = {}
        state = record_ingestion(state, "sumologic", entry_timestamps=[
            "2026-08-01T10:00:00Z", "2026-08-15T10:00:00Z", "2026-08-05T10:00:00Z",
        ])
        assert state["data_oldest_ts"].startswith("2026-08-01")
        assert state["data_newest_ts"].startswith("2026-08-15")

        # Second ingestion extends both ends
        state = record_ingestion(state, "sumologic", entry_timestamps=[
            "2026-07-20T10:00:00Z", "2026-09-01T10:00:00Z",
        ])
        assert state["data_oldest_ts"].startswith("2026-07-20")
        assert state["data_newest_ts"].startswith("2026-09-01")

    def test_synthetic_never_advances(self):
        from nabla.system_state import record_ingestion

        state = {}
        state = record_ingestion(state, "synthetic", entry_timestamps=["2020-01-01T00:00:00Z"])
        assert "first_ingestion_at" not in state
        assert "data_oldest_ts" not in state

    def test_transition_fires_on_span(self):
        from nabla.system_state import should_transition

        old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
        recent = datetime.now(timezone.utc).isoformat()
        state = {
            "phase": "baseline", "first_ingestion_at": old,
            "data_oldest_ts": old, "data_newest_ts": recent,
        }
        assert should_transition(state, warm_user_count=5) is True

    def test_no_transition_on_short_span(self):
        from nabla.system_state import should_transition

        old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
        recent = datetime.now(timezone.utc).isoformat()
        state = {
            "phase": "baseline", "first_ingestion_at": old,  # wall clock LONG ago
            "data_oldest_ts": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
            "data_newest_ts": recent,
        }
        # Span is 5 days despite 40 wall-clock days — no transition (span wins)
        assert should_transition(state, warm_user_count=5) is False

    def test_wallclock_fallback_when_span_absent(self):
        from nabla.system_state import should_transition

        # Pre-upgrade state: no span fields, first_ingestion 30 days ago
        state = {
            "phase": "baseline",
            "first_ingestion_at": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
        }
        assert should_transition(state, warm_user_count=5) is True

    def test_days_remaining_uses_span(self):
        from nabla.system_state import baseline_days_remaining

        state = {
            "phase": "baseline",
            "data_oldest_ts": (datetime.now(timezone.utc) - timedelta(days=12)).isoformat(),
            "data_newest_ts": datetime.now(timezone.utc).isoformat(),
        }
        remaining = baseline_days_remaining(state)
        assert remaining in (8, 9)  # int() of 9-minus-microsecond-drift


# ---------------------------------------------------------------------------
# CLI: phase override + reset
# ---------------------------------------------------------------------------

@pytest.fixture
def runner():
    return CliRunner()


class TestPhaseOverride:
    def test_force_requires_confirm(self, runner, tmp_path):
        from nabla.cli import app
        s = _settings(tmp_path)
        with patch("nabla.cli.get_settings", return_value=s), \
             patch("nabla.config.get_settings", return_value=s):
            r = runner.invoke(app, ["phase", "force-detection"])
        assert r.exit_code == 1
        assert "--confirm" in r.output

    def test_force_and_revert_roundtrip(self, runner, tmp_path):
        from nabla.cli import app
        from nabla.system_state import load_system_state
        s = _settings(tmp_path)
        with patch("nabla.cli.get_settings", return_value=s), \
             patch("nabla.config.get_settings", return_value=s):
            r = runner.invoke(app, ["phase", "force-detection", "--confirm"])
            assert r.exit_code == 0
            state = load_system_state(s.system_state_file)
            assert state["phase"] == "detection"

            r = runner.invoke(app, ["phase", "set-baseline", "--confirm"])
            assert r.exit_code == 0
            state = load_system_state(s.system_state_file)
            assert state["phase"] == "baseline"


class TestReset:
    def _seed(self, tmp_path):
        for name in ["entity_profiles.json", "entity_risk_scores.json", "rl_state.json",
                     "incidents.json", "runs.json", "environment_context.json",
                     "system_state.json", "entity_peer_groups.json"]:
            (tmp_path / name).write_text("{}")

    def test_learned_scope_files(self, tmp_path):
        from nabla.cli import _reset_files
        files = _reset_files("learned", tmp_path)
        names = [os.path.basename(f) for f in files]
        assert "entity_peer_groups.json" in names  # derived path included (review N1)
        assert "incidents.json" not in names  # learned keeps incidents

    def test_reset_learned(self, runner, tmp_path):
        from nabla.cli import app
        self._seed(tmp_path)
        s = _settings(tmp_path)
        with patch("nabla.cli.get_settings", return_value=s), \
             patch("nabla.config.get_settings", return_value=s):
            r = runner.invoke(app, ["reset", "--scope", "learned", "--yes"])
        assert r.exit_code == 0
        assert not (tmp_path / "entity_profiles.json").exists()
        assert not (tmp_path / "entity_peer_groups.json").exists()
        assert (tmp_path / "incidents.json").exists()  # survives learned
        assert (tmp_path / "users.json").exists() is False  # never seeded

    def test_reset_all(self, runner, tmp_path):
        from nabla.cli import app
        self._seed(tmp_path)
        (tmp_path / "users.json").write_text('{"opsuser": {}}')
        s = _settings(tmp_path)
        with patch("nabla.cli.get_settings", return_value=s), \
             patch("nabla.config.get_settings", return_value=s):
            r = runner.invoke(app, ["reset", "--scope", "all", "--yes"])
        assert r.exit_code == 0
        assert not (tmp_path / "incidents.json").exists()
        assert not (tmp_path / "runs.json").exists()
        assert (tmp_path / "users.json").exists()  # ALWAYS survives

    def test_confirmation_gate(self, runner, tmp_path):
        from nabla.cli import app
        self._seed(tmp_path)
        s = _settings(tmp_path)
        with patch("nabla.cli.get_settings", return_value=s), \
             patch("nabla.config.get_settings", return_value=s):
            r = runner.invoke(app, ["reset", "--scope", "learned"], input="n\n")
        assert r.exit_code != 0 or "Aborted" in r.output
        assert (tmp_path / "entity_profiles.json").exists()  # nothing deleted


class TestResetScopesCoverCalibration:
    def test_feedback_dir_in_learned_scope(self, tmp_path):
        """Stage-4 find #5: calibration/feedback are learned state — resets clear them."""
        import os
        from nabla.cli import _reset_files
        (tmp_path / "feedback").mkdir()
        (tmp_path / "feedback" / "labels.jsonl").write_text("x")
        (tmp_path / "feedback" / "calibration.json").write_text("{}")
        files = _reset_files("learned", tmp_path)
        assert any("feedback" in f for f in files), "feedback store must reset with learned scope"
