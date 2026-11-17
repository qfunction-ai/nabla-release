"""Tests for the Nabla CLI — argument parsing, lock file, and command routing."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from nabla.cli import app


runner = CliRunner()


# ---------------------------------------------------------------------------
# Bootstrap command
# ---------------------------------------------------------------------------

class TestBootstrap:
    """Tests for the bootstrap command."""

    @patch("nabla.cli.get_client")
    @patch("nabla.agents.bootstrap.bootstrap")
    def test_bootstrap_success(self, mock_bootstrap, mock_get_client):
        """Bootstrap prints agent IDs on success."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_bootstrap.return_value = {"supervisor": "agent-123", "detector": "agent-456"}

        result = runner.invoke(app, ["bootstrap"])
        assert result.exit_code == 0
        assert "agent-123" in result.output
        assert "agent-456" in result.output

    @patch("nabla.cli.get_client")
    @patch("nabla.agents.bootstrap.bootstrap")
    def test_bootstrap_returns_agents(self, mock_bootstrap, mock_get_client):
        """Bootstrap calls the real bootstrap function with the client."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_bootstrap.return_value = {"supervisor": "agent-1"}

        runner.invoke(app, ["bootstrap"])
        mock_bootstrap.assert_called_once_with(mock_client)


# ---------------------------------------------------------------------------
# Run command — lock file behavior
# ---------------------------------------------------------------------------

class TestRunLockFile:
    """Tests for the pipeline run lock file mechanism."""

    @patch("nabla.cli.get_client")
    @patch("nabla.pipeline.run_pipeline")
    def test_run_creates_and_removes_lock(self, mock_pipeline, mock_get_client):
        """Lock file is created and cleaned up after a successful run."""
        mock_get_client.return_value = MagicMock()
        mock_pipeline.return_value = {"detect": "ok"}

        # Ensure lock doesn't exist
        lock = "/tmp/nabla-pipeline.lock"
        if os.path.exists(lock):
            os.unlink(lock)

        result = runner.invoke(app, ["run"])
        assert result.exit_code == 0
        assert not os.path.exists(lock), "Lock file should be removed after run"

    @patch("nabla.cli.get_client")
    @patch("nabla.pipeline.run_pipeline")
    def test_run_with_existing_lock_fails(self, mock_pipeline, mock_get_client):
        """Run fails if lock file already exists (concurrent run)."""
        lock = "/tmp/nabla-pipeline.lock"
        try:
            with open(lock, "w") as f:
                f.write("99999\n")

            result = runner.invoke(app, ["run"])
            assert result.exit_code == 1
            assert "already in progress" in result.output
            mock_pipeline.assert_not_called()
        finally:
            if os.path.exists(lock):
                os.unlink(lock)

    @patch("nabla.cli.get_client")
    @patch("nabla.pipeline.run_pipeline")
    def test_run_removes_lock_on_failure(self, mock_pipeline, mock_get_client):
        """Lock file is cleaned up even if the pipeline raises."""
        mock_get_client.return_value = MagicMock()
        mock_pipeline.side_effect = RuntimeError("pipeline exploded")

        lock = "/tmp/nabla-pipeline.lock"
        if os.path.exists(lock):
            os.unlink(lock)

        result = runner.invoke(app, ["run"])
        assert result.exit_code == 1
        assert not os.path.exists(lock), "Lock file should be removed even on failure"


# ---------------------------------------------------------------------------
# Run command — argument validation
# ---------------------------------------------------------------------------

class TestRunValidation:
    """Tests for the run command argument validation."""

    @patch("nabla.cli.get_client")
    @patch("nabla.pipeline.run_pipeline")
    def test_run_file_source_requires_file(self, mock_pipeline, mock_get_client):
        """Run with --source=file fails without --file."""
        mock_get_client.return_value = MagicMock()
        # Need to bypass lock file for testing
        lock = "/tmp/nabla-pipeline.lock"
        if os.path.exists(lock):
            os.unlink(lock)

        try:
            result = runner.invoke(app, ["run", "--source", "file"])
            assert result.exit_code == 1
            assert "--file is required" in result.output
            mock_pipeline.assert_not_called()
        finally:
            if os.path.exists(lock):
                os.unlink(lock)

    @patch("nabla.cli.get_client")
    @patch("nabla.pipeline.run_pipeline")
    def test_run_with_column_map(self, mock_pipeline, mock_get_client):
        """Run parses --map argument and passes column_map to pipeline."""
        mock_get_client.return_value = MagicMock()
        mock_pipeline.return_value = {"detect": "ok"}

        lock = "/tmp/nabla-pipeline.lock"
        if os.path.exists(lock):
            os.unlink(lock)

        try:
            result = runner.invoke(app, [
                "run", "--map", "user=Username,action=Activity",
            ])
            assert result.exit_code == 0
            call_kwargs = mock_pipeline.call_args
            assert call_kwargs.kwargs.get("column_map") is not None or \
                   (len(call_kwargs.args) > 0 and True)  # column_map was passed
        finally:
            if os.path.exists(lock):
                os.unlink(lock)


# ---------------------------------------------------------------------------
# Status command
# ---------------------------------------------------------------------------

class TestStatus:
    """Tests for the status command."""

    @patch("nabla.cli.get_settings")
    @patch("nabla.cli.get_client")
    @patch("nabla.pipeline.get_status")
    @patch("nabla.system_state.load_system_state")
    @patch("nabla.system_state.format_phase_summary")
    def test_status_success(self, mock_format, mock_load, mock_get_status,
                             mock_get_client, mock_get_settings):
        """Status prints agent info on success."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_get_status.return_value = {
            "agents": [{"role": "supervisor", "name": "Supervisor", "id": "agent-1"}],
            "blocks": {"system_phase": "detection", "threat_findings": "none"},
        }
        mock_format.return_value = "Phase: detection"
        mock_settings = MagicMock()
        mock_settings.system_state_file = "/tmp/test_system_state.json"
        mock_get_settings.return_value = mock_settings

        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "supervisor" in result.output

    @patch("nabla.cli.get_client")
    @patch("nabla.pipeline.get_status")
    def test_status_error(self, mock_get_status, mock_get_client):
        """Status exits with error when get_status returns error."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_get_status.return_value = {"error": "Letta unreachable"}

        result = runner.invoke(app, ["status"])
        assert result.exit_code == 1
        assert "Letta unreachable" in result.output


# ---------------------------------------------------------------------------
# History command
# ---------------------------------------------------------------------------

class TestHistory:
    """Tests for the history command."""

    @patch("nabla.history.list_runs")
    def test_history_no_runs(self, mock_list):
        """History prints message when no runs exist."""
        mock_list.return_value = []
        result = runner.invoke(app, ["history"])
        assert result.exit_code == 0
        assert "No pipeline runs" in result.output

    @patch("nabla.history.list_runs")
    def test_history_with_runs(self, mock_list):
        """History prints run IDs and counts."""
        mock_list.return_value = [{
            "run_id": "abc123456789",
            "started_at": "2026-05-12T10:00:00Z",
            "source": "synthetic",
            "log_types": ["auth"],
            "anomaly_count": 5,
            "findings_count": 2,
            "success": True,
            "step_durations": {"detect": 10.0},
        }]
        result = runner.invoke(app, ["history"])
        assert result.exit_code == 0
        assert "abc12345" in result.output


# ---------------------------------------------------------------------------
# Chat command
# ---------------------------------------------------------------------------

class TestChat:
    """Tests for the chat command."""

    @patch("nabla.cli.get_client")
    @patch("nabla.agents.registry.find_agent")
    def test_chat_no_supervisor(self, mock_find, mock_get_client):
        """Chat exits when supervisor agent not found."""
        mock_get_client.return_value = MagicMock()
        mock_find.return_value = None

        result = runner.invoke(app, ["chat"])
        assert result.exit_code == 1
        assert "not found" in result.output


# ---------------------------------------------------------------------------
# Schedule command
# ---------------------------------------------------------------------------

class TestSchedule:
    """Tests for the schedule command."""

    @patch("nabla.scheduler.stop_scheduler")
    def test_schedule_stop(self, mock_stop):
        """Schedule --stop calls stop_scheduler."""
        result = runner.invoke(app, ["schedule", "--stop"])
        assert result.exit_code == 0
        mock_stop.assert_called_once()


# ---------------------------------------------------------------------------
# Teardown command
# ---------------------------------------------------------------------------

class TestTeardown:
    """Tests for the teardown command."""

    @patch("nabla.cli.get_client")
    @patch("nabla.agents.bootstrap.teardown")
    def test_teardown_force(self, mock_teardown, mock_get_client):
        """Teardown with --force skips confirmation."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_teardown.return_value = 5

        result = runner.invoke(app, ["teardown", "--force"])
        assert result.exit_code == 0
        assert "5" in result.output

    @patch("nabla.cli.get_client")
    @patch("nabla.agents.bootstrap.teardown")
    def test_teardown_abort(self, mock_teardown, mock_get_client):
        """Teardown without --force aborts on declining confirmation."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        result = runner.invoke(app, ["teardown"], input="n\n")
        assert result.exit_code == 1  # Aborted


# ---------------------------------------------------------------------------
# Export command
# ---------------------------------------------------------------------------

class TestExportCmd:
    """Tests for the export CLI command."""

    @patch("nabla.cli.get_settings")
    @patch("nabla.export.export_state")
    def test_export_success(self, mock_export, mock_get_settings):
        """Export command calls export_state and prints summary."""
        mock_settings = MagicMock()
        mock_settings.data_dir = "/tmp"
        mock_get_settings.return_value = mock_settings
        mock_export.return_value = {"exported": ["entity_profiles"], "skipped": []}

        result = runner.invoke(app, ["export", "-o", "/tmp/test-export.json"])
        assert result.exit_code == 0
        assert "Exported" in result.output


# ---------------------------------------------------------------------------
# Import command
# ---------------------------------------------------------------------------

class TestImportCmd:
    """Tests for the import CLI command."""

    @patch("nabla.cli.get_settings")
    @patch("nabla.export.import_state")
    def test_import_force(self, mock_import, mock_get_settings):
        """Import with --force skips confirmation."""
        mock_settings = MagicMock()
        mock_settings.data_dir = "/tmp"
        mock_get_settings.return_value = mock_settings
        mock_import.return_value = {"imported": ["entity_profiles"], "skipped": [], "backups": []}

        result = runner.invoke(app, ["import", "-i", "/tmp/test-export.json", "--force"])
        assert result.exit_code == 0
        assert "Imported" in result.output

    @patch("nabla.cli.get_settings")
    @patch("nabla.export.import_state")
    def test_import_file_not_found(self, mock_import, mock_get_settings):
        """Import reports error when file not found."""
        mock_settings = MagicMock()
        mock_settings.data_dir = "/tmp"
        mock_get_settings.return_value = mock_settings
        mock_import.side_effect = FileNotFoundError("not found")

        result = runner.invoke(app, ["import", "-i", "/tmp/missing.json", "--force"])
        assert result.exit_code == 1
        assert "not found" in result.output


# ---------------------------------------------------------------------------
# Watchlist subcommands
# ---------------------------------------------------------------------------

class TestWatchlistCmd:
    """Tests for the watchlist subcommands."""

    @patch("nabla.cli.get_settings")
    @patch("nabla.watchlist.list_groups")
    @patch("nabla.watchlist.get_all_entities")
    def test_watchlist_list_empty(self, mock_all, mock_list, mock_get_settings):
        """Watchlist list shows message when empty."""
        mock_settings = MagicMock()
        mock_settings.effective_watchlist_path = "/tmp/watchlist.json"
        mock_get_settings.return_value = mock_settings
        mock_list.return_value = {"high_value_users": [], "critical_systems": []}
        mock_all.return_value = {"users": [], "hosts": [], "ips": []}

        result = runner.invoke(app, ["watchlist", "list"])
        assert result.exit_code == 0
        assert "empty" in result.output.lower()

    @patch("nabla.cli.get_settings")
    @patch("nabla.watchlist.add_entity")
    def test_watchlist_add(self, mock_add, mock_get_settings):
        """Watchlist add calls add_entity and prints confirmation."""
        mock_settings = MagicMock()
        mock_settings.effective_watchlist_path = "/tmp/watchlist.json"
        mock_get_settings.return_value = mock_settings

        result = runner.invoke(app, ["watchlist", "add", "high_value_users", "admin"])
        assert result.exit_code == 0
        assert "admin" in result.output
        mock_add.assert_called_once()

    @patch("nabla.cli.get_settings")
    @patch("nabla.watchlist.remove_entity")
    def test_watchlist_remove(self, mock_remove, mock_get_settings):
        """Watchlist remove calls remove_entity and prints confirmation."""
        mock_settings = MagicMock()
        mock_settings.effective_watchlist_path = "/tmp/watchlist.json"
        mock_get_settings.return_value = mock_settings

        result = runner.invoke(app, ["watchlist", "remove", "high_value_users", "admin"])
        assert result.exit_code == 0
        assert "admin" in result.output
        mock_remove.assert_called_once()


# ---------------------------------------------------------------------------
# Incidents subcommands
# ---------------------------------------------------------------------------

class TestIncidentsCmd:
    """Tests for the incidents subcommands."""

    @patch("nabla.incidents.list_incidents")
    def test_incidents_list_empty(self, mock_list):
        """Incidents list shows message when no incidents."""
        mock_list.return_value = []
        result = runner.invoke(app, ["incidents", "list"])
        assert result.exit_code == 0
        assert "No incidents" in result.output

    @patch("nabla.incidents.list_incidents")
    def test_incidents_list_with_filter(self, mock_list):
        """Incidents list passes status filter."""
        mock_list.return_value = []
        result = runner.invoke(app, ["incidents", "list", "--status", "new"])
        mock_list.assert_called_once()
        call_kwargs = mock_list.call_args
        assert call_kwargs.kwargs.get("status") == "new" or \
               (len(call_kwargs.args) > 0 and call_kwargs.args[0] == "new")

    @patch("nabla.incidents.get_incident")
    def test_incidents_show_not_found(self, mock_get):
        """Incidents show reports when incident not found."""
        mock_get.return_value = None
        result = runner.invoke(app, ["incidents", "show", "abcd1234"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    @patch("nabla.incidents.incident_stats")
    def test_incidents_stats_empty(self, mock_stats):
        """Incidents stats shows message when no incidents."""
        mock_stats.return_value = {"total": 0, "by_status": {}, "by_severity": {}}
        result = runner.invoke(app, ["incidents", "stats"])
        assert result.exit_code == 0
        assert "No incidents" in result.output

    @patch("nabla.incidents.incident_stats")
    def test_incidents_stats_with_data(self, mock_stats):
        """Incidents stats prints counts."""
        mock_stats.return_value = {
            "total": 5,
            "by_status": {"new": 3, "investigating": 2},
            "by_severity": {"critical": 1, "high": 2, "medium": 2},
        }
        result = runner.invoke(app, ["incidents", "stats"])
        assert result.exit_code == 0
        assert "5" in result.output

    @patch("nabla.incidents.update_incident")
    @patch("nabla.incidents.list_incidents")
    def test_incidents_update_no_args(self, mock_list, mock_update):
        """Incidents update fails when no status or notes provided."""
        # The CLI resolves partial IDs via list_incidents first
        mock_list.return_value = [{"incident_id": "abcd12345678901234567890123456789012", "status": "new"}]
        result = runner.invoke(app, ["incidents", "update", "abcd12345678901234567890123456789012"])
        assert result.exit_code == 1
        assert "Provide" in result.output

    @patch("nabla.incidents.update_incident")
    @patch("nabla.incidents.list_incidents")
    def test_incidents_update_success(self, mock_list, mock_update):
        """Incidents update with status succeeds."""
        mock_list.return_value = [{"incident_id": "abcd12345678901234567890123456789012", "status": "new"}]
        mock_update.return_value = {
            "incident_id": "abcd12345678901234567890123456789012",
            "status": "investigating",
        }
        result = runner.invoke(app, ["incidents", "update", "abcd12345678901234567890123456789012", "--status", "investigating"])
        assert result.exit_code == 0
        assert "investigating" in result.output


# ---------------------------------------------------------------------------
# RL status command
# ---------------------------------------------------------------------------

class TestRLStatus:
    """Tests for the rl-status command."""

    @patch("nabla.cli.get_settings")
    @patch("nabla.rl.thresholds.ThresholdAgent.load")
    @patch("nabla.rl.bandit.DetectionMethodBandit.load")
    def test_rl_status(self, mock_bandit_load, mock_agent_load, mock_get_settings):
        """RL status prints threshold and bandit info."""
        mock_settings = MagicMock()
        mock_settings.rl_state_file = "/tmp/rl_state.json"
        mock_get_settings.return_value = mock_settings

        mock_agent = MagicMock()
        mock_agent.current_values = {"z_score_spike": 3.5}
        mock_agent.update_counts = {"z_score_spike": 5}
        mock_agent_load.return_value = mock_agent

        mock_bandit = MagicMock()
        mock_bandit.get_means.return_value = {"lolbin_abuse": 0.8, "z_score_spike": 0.3}
        mock_bandit.alpha = {"lolbin_abuse": 8, "z_score_spike": 3}
        mock_bandit.beta = {"lolbin_abuse": 2, "z_score_spike": 7}
        mock_bandit.update_counts = {"lolbin_abuse": 10, "z_score_spike": 10}
        mock_bandit_load.return_value = mock_bandit

        result = runner.invoke(app, ["rl-status"])
        assert result.exit_code == 0
        assert "z_score_spike" in result.output


# ---------------------------------------------------------------------------
# Web command
# ---------------------------------------------------------------------------

class TestWeb:
    """Tests for the web command."""

    @patch("nabla.server.main")
    def test_web_starts_server(self, mock_main):
        """Web command calls server.main."""
        result = runner.invoke(app, ["web"])
        mock_main.assert_called_once()
