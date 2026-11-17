"""Tests for nabla/export.py — export and import learned state."""

import json
import os

import pytest

from nabla.export import (
    EXPORT_VERSION,
    export_state,
    import_state,
    _validate_export,
    _validate_path,
    _merge_dicts,
    _merge_runs,
    _merge_incidents,
    _merge_ingestion_state,
    _merge_jsonl,
    _merge_section,
    _backup_file,
)


# ---------------------------------------------------------------------------
# _validate_export
# ---------------------------------------------------------------------------

class TestValidateExport:
    """Tests for _validate_export."""

    def test_valid_export(self):
        """Valid export passes validation."""
        _validate_export({"version": EXPORT_VERSION, "state": {}})

    def test_missing_version(self):
        """Missing version raises ValueError."""
        with pytest.raises(ValueError, match="missing 'version'"):
            _validate_export({"state": {}})

    def test_wrong_version(self):
        """Wrong version raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported export version"):
            _validate_export({"version": 99, "state": {}})

    def test_missing_state(self):
        """Missing state raises ValueError."""
        with pytest.raises(ValueError, match="missing 'state'"):
            _validate_export({"version": EXPORT_VERSION})

    def test_state_not_dict(self):
        """State must be a dict."""
        with pytest.raises(ValueError, match="'state' must be a dict"):
            _validate_export({"version": EXPORT_VERSION, "state": "not a dict"})


# ---------------------------------------------------------------------------
# _merge_dicts
# ---------------------------------------------------------------------------

class TestMergeDicts:
    """Tests for _merge_dicts."""

    def test_shallow_merge(self):
        """Imported values override existing."""
        result = _merge_dicts({"a": 1, "b": 2}, {"b": 3, "c": 4})
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_deep_merge(self):
        """Nested dicts are merged recursively."""
        existing = {"users": {"alice": {"count": 5}, "bob": {"count": 3}}}
        imported = {"users": {"alice": {"count": 10}, "carol": {"count": 7}}}
        result = _merge_dicts(existing, imported)
        assert result == {"users": {"alice": {"count": 10}, "bob": {"count": 3}, "carol": {"count": 7}}}

    def test_non_dict_existing(self):
        """If existing is not a dict, imported wins."""
        result = _merge_dicts("not a dict", {"a": 1})
        assert result == {"a": 1}

    def test_non_dict_imported(self):
        """If imported is not a dict, imported wins."""
        result = _merge_dicts({"a": 1}, "not a dict")
        assert result == "not a dict"


# ---------------------------------------------------------------------------
# _merge_runs
# ---------------------------------------------------------------------------

class TestMergeRuns:
    """Tests for _merge_runs."""

    def test_deduplication(self):
        """Runs with same run_id are deduplicated."""
        existing = [{"run_id": "a", "success": True}, {"run_id": "b", "success": False}]
        imported = [{"run_id": "b", "success": True}, {"run_id": "c", "success": True}]
        result = _merge_runs(existing, imported)
        assert len(result) == 3
        ids = {r["run_id"] for r in result}
        assert ids == {"a", "b", "c"}
        # Existing 'b' is kept (not overwritten by imported)
        run_b = [r for r in result if r["run_id"] == "b"][0]
        assert run_b["success"] is False

    def test_empty_existing(self):
        """Empty existing list accepts all imported runs."""
        imported = [{"run_id": "a"}, {"run_id": "b"}]
        result = _merge_runs([], imported)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# _merge_ingestion_state
# ---------------------------------------------------------------------------

class TestMergeIngestionState:
    """Tests for _merge_ingestion_state."""

    def test_keep_latest_timestamp(self):
        """Later timestamp wins."""
        existing = {"sumologic": {"last_ingestion": "2026-04-28T10:00:00Z", "total_ingested": 100}}
        imported = {"sumologic": {"last_ingestion": "2026-04-29T10:00:00Z", "total_ingested": 200}}
        result = _merge_ingestion_state(existing, imported)
        assert result["sumologic"]["last_ingestion"] == "2026-04-29T10:00:00Z"

    def test_keep_existing_if_later(self):
        """Existing timestamp wins if later."""
        existing = {"sumologic": {"last_ingestion": "2026-04-30T10:00:00Z", "total_ingested": 300}}
        imported = {"sumologic": {"last_ingestion": "2026-04-28T10:00:00Z", "total_ingested": 200}}
        result = _merge_ingestion_state(existing, imported)
        assert result["sumologic"]["last_ingestion"] == "2026-04-30T10:00:00Z"

    def test_new_connector(self):
        """New connector from import is added."""
        existing = {"sumologic": {"last_ingestion": "2026-04-28T10:00:00Z"}}
        imported = {"splunk": {"last_ingestion": "2026-04-29T10:00:00Z"}}
        result = _merge_ingestion_state(existing, imported)
        assert "splunk" in result
        assert "sumologic" in result


# ---------------------------------------------------------------------------
# _merge_section
# ---------------------------------------------------------------------------

class TestMergeSection:
    """Tests for _merge_section."""

    def test_runs_section(self):
        """Runs section uses list merge."""
        result = _merge_section("runs", [{"run_id": "a"}], [{"run_id": "b"}])
        assert len(result) == 2

    def test_gcn_lof_overwrites(self):
        """GCN-LOF model is always overwritten (can't merge weights)."""
        result = _merge_section("gcn_lof_model", {"old": True}, {"new": True})
        assert result == {"new": True}

    def test_entity_profiles_deep_merge(self):
        """Entity profiles are deep-merged."""
        existing = {"users": {"alice": {"count": 5}}}
        imported = {"users": {"alice": {"count": 10}, "bob": {"count": 3}}}
        result = _merge_section("entity_profiles", existing, imported)
        assert result["users"]["alice"]["count"] == 10
        assert "bob" in result["users"]


# ---------------------------------------------------------------------------
# export_state / import_state integration
# ---------------------------------------------------------------------------

class TestExportImport:
    """Integration tests for export and import round-trip."""

    def test_export_all_files_present(self, tmp_path):
        """Export reads all state files when present."""
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir)

        # Create all state files
        for filename in ["entity_profiles.json", "rl_state.json", "gcn_lof_model.json",
                         "environment_context.json", "watchlists.json", "runs.json",
                         "ingestion_state.json", "system_state.json", "incidents.json"]:
            with open(os.path.join(data_dir, filename), "w") as f:
                json.dump({"test": filename}, f)

        # Create JSONL state files
        for filename in ["siem_logs.jsonl", "baseline_snapshots.jsonl"]:
            with open(os.path.join(data_dir, filename), "w") as f:
                f.write(json.dumps({"log_type": "auth", "count": 1}) + "\n")

        output_path = str(tmp_path / "export.json")
        summary = export_state(data_dir, output_path)

        assert len(summary["exported"]) == 11
        assert len(summary["skipped"]) == 0

        # Verify export file structure
        with open(output_path) as f:
            data = json.load(f)
        assert data["version"] == EXPORT_VERSION
        assert "state" in data
        assert "entity_profiles" in data["state"]

    def test_export_missing_files(self, tmp_path):
        """Export skips missing files gracefully."""
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir)

        # Only create some files
        with open(os.path.join(data_dir, "entity_profiles.json"), "w") as f:
            json.dump({"users": {}}, f)
        with open(os.path.join(data_dir, "rl_state.json"), "w") as f:
            json.dump({"q_tables": {}}, f)

        output_path = str(tmp_path / "export.json")
        summary = export_state(data_dir, output_path)

        assert len(summary["exported"]) == 2
        assert len(summary["skipped"]) == 9

    def test_import_overwrite(self, tmp_path):
        """Import overwrites existing files."""
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir)

        # Create export file
        export_path = str(tmp_path / "export.json")
        export_data = {
            "version": EXPORT_VERSION,
            "state": {
                "entity_profiles": {"users": {"alice": {"count": 10}}},
                "rl_state": {"q_tables": {"z_score": 4.0}},
            },
        }
        with open(export_path, "w") as f:
            json.dump(export_data, f)

        # Create existing files with different content
        with open(os.path.join(data_dir, "entity_profiles.json"), "w") as f:
            json.dump({"users": {"bob": {"count": 5}}}, f)

        summary = import_state(export_path, data_dir, merge=False)

        # Verify overwrite
        with open(os.path.join(data_dir, "entity_profiles.json")) as f:
            profiles = json.load(f)
        assert profiles == {"users": {"alice": {"count": 10}}}

        # Verify backup was created
        assert os.path.exists(os.path.join(data_dir, "entity_profiles.json.bak"))

    def test_import_merge(self, tmp_path):
        """Import merges with existing state."""
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir)

        # Create existing files
        with open(os.path.join(data_dir, "entity_profiles.json"), "w") as f:
            json.dump({"users": {"bob": {"count": 5}}}, f)

        # Create export file
        export_path = str(tmp_path / "export.json")
        export_data = {
            "version": EXPORT_VERSION,
            "state": {
                "entity_profiles": {"users": {"alice": {"count": 10}}},
            },
        }
        with open(export_path, "w") as f:
            json.dump(export_data, f)

        summary = import_state(export_path, data_dir, merge=True)

        # Verify merge
        with open(os.path.join(data_dir, "entity_profiles.json")) as f:
            profiles = json.load(f)
        assert "alice" in profiles["users"]
        assert "bob" in profiles["users"]

    def test_import_missing_file_raises(self, tmp_path):
        """Import raises FileNotFoundError for missing export file."""
        with pytest.raises(FileNotFoundError):
            import_state("/nonexistent/export.json", "/tmp/data")

    def test_import_invalid_version(self, tmp_path):
        """Import rejects wrong version."""
        export_path = str(tmp_path / "export.json")
        with open(export_path, "w") as f:
            json.dump({"version": 99, "state": {}}, f)

        with pytest.raises(ValueError, match="Unsupported export version"):
            import_state(export_path, str(tmp_path / "data"))

    def test_roundtrip(self, tmp_path):
        """Export → import preserves state."""
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir)

        # Create state files with known content
        original_profiles = {"users": {"alice": {"count": 42, "ips": ["1.2.3.4"]}}}
        original_rl = {"q_tables": {"z_score": 3.5}, "bandit": {"alpha": {"lolbin": 10}}}
        with open(os.path.join(data_dir, "entity_profiles.json"), "w") as f:
            json.dump(original_profiles, f)
        with open(os.path.join(data_dir, "rl_state.json"), "w") as f:
            json.dump(original_rl, f)

        # Export
        export_path = str(tmp_path / "export.json")
        export_state(data_dir, export_path)

        # Clear data dir
        os.remove(os.path.join(data_dir, "entity_profiles.json"))
        os.remove(os.path.join(data_dir, "rl_state.json"))

        # Import
        import_state(export_path, data_dir, merge=False)

        # Verify
        with open(os.path.join(data_dir, "entity_profiles.json")) as f:
            assert json.load(f) == original_profiles
        with open(os.path.join(data_dir, "rl_state.json")) as f:
            assert json.load(f) == original_rl

    def test_import_creates_data_dir(self, tmp_path):
        """Import creates data_dir if it doesn't exist."""
        data_dir = str(tmp_path / "new_data")
        export_path = str(tmp_path / "export.json")
        with open(export_path, "w") as f:
            json.dump({"version": EXPORT_VERSION, "state": {"entity_profiles": {"users": {}}}}, f)

        import_state(export_path, data_dir)
        assert os.path.exists(data_dir)
        assert os.path.exists(os.path.join(data_dir, "entity_profiles.json"))

    def test_import_corrupted_json_in_export(self, tmp_path):
        """Import raises on corrupted JSON in export file."""
        export_path = str(tmp_path / "export.json")
        with open(export_path, "w") as f:
            f.write("{invalid json")

        with pytest.raises(json.JSONDecodeError):
            import_state(export_path, str(tmp_path / "data"))

    def test_export_corrupted_state_file_skipped(self, tmp_path):
        """Export skips corrupted state files."""
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir)

        # Create a valid file and a corrupted one
        with open(os.path.join(data_dir, "entity_profiles.json"), "w") as f:
            json.dump({"users": {}}, f)
        with open(os.path.join(data_dir, "rl_state.json"), "w") as f:
            f.write("{invalid json")

        output_path = str(tmp_path / "export.json")
        summary = export_state(data_dir, output_path)

        assert "entity_profiles" in summary["exported"]
        assert "rl_state" in summary["skipped"]

    def test_jsonl_export_import_roundtrip(self, tmp_path):
        """JSONL files export as lists and import back as JSONL lines."""
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir)

        # Create a JSONL file with multiple lines
        jsonl_path = os.path.join(data_dir, "baseline_snapshots.jsonl")
        with open(jsonl_path, "w") as f:
            f.write(json.dumps({"snapshot_type": "baseline", "host_processes": {"H1": ["svchost"]}}) + "\n")
            f.write(json.dumps({"snapshot_type": "baseline", "host_processes": {"H2": ["chrome"]}}) + "\n")

        # Export
        export_path = str(tmp_path / "export.json")
        summary = export_state(data_dir, export_path)
        assert "baseline_snapshots" in summary["exported"]

        # Verify export structure — JSONL becomes a list
        with open(export_path) as f:
            data = json.load(f)
        assert isinstance(data["state"]["baseline_snapshots"], list)
        assert len(data["state"]["baseline_snapshots"]) == 2

        # Import to a new directory
        import_dir = str(tmp_path / "imported")
        os.makedirs(import_dir)
        import_summary = import_state(export_path, import_dir)
        assert "baseline_snapshots" in import_summary["imported"]

        # Verify the imported JSONL file
        imported_path = os.path.join(import_dir, "baseline_snapshots.jsonl")
        assert os.path.exists(imported_path)
        with open(imported_path, "r") as f:
            lines = [l.strip() for l in f if l.strip()]
        assert len(lines) == 2
        data1 = json.loads(lines[0])
        assert data1["snapshot_type"] == "baseline"

    def test_jsonl_merge_deduplicates_by_timestamp(self, tmp_path):
        """JSONL baseline_snapshots merge deduplicates by timestamp."""
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir)

        # Create existing JSONL
        jsonl_path = os.path.join(data_dir, "baseline_snapshots.jsonl")
        with open(jsonl_path, "w") as f:
            f.write(json.dumps({"snapshot_type": "baseline", "timestamp": "2026-01-01T00:00:00Z", "host_processes": {"H1": ["old"]}}) + "\n")
            f.write(json.dumps({"snapshot_type": "baseline", "timestamp": "2026-01-02T00:00:00Z", "host_processes": {"H2": ["proc"]}}) + "\n")

        # Create export with overlapping timestamp
        export_path = str(tmp_path / "export.json")
        export_data = {
            "version": EXPORT_VERSION,
            "state": {
                "baseline_snapshots": [
                    {"snapshot_type": "baseline", "timestamp": "2026-01-01T00:00:00Z", "host_processes": {"H1": ["new"]}},
                    {"snapshot_type": "baseline", "timestamp": "2026-01-03T00:00:00Z", "host_processes": {"H3": ["proc"]}},
                ],
            },
        }
        with open(export_path, "w") as f:
            json.dump(export_data, f)

        # Import with merge
        import_summary = import_state(export_path, data_dir, merge=True)
        assert "baseline_snapshots" in import_summary["imported"]

        # Verify merged file — should have 3 unique timestamps
        with open(jsonl_path, "r") as f:
            lines = [l.strip() for l in f if l.strip()]
        timestamps = set()
        for line in lines:
            data = json.loads(line)
            timestamps.add(data["timestamp"])
        assert len(timestamps) == 3


# ---------------------------------------------------------------------------
# _validate_path — path traversal protection
# ---------------------------------------------------------------------------

class TestValidatePath:
    """Tests for _validate_path path traversal protection."""

    def test_allowed_tmp_path(self):
        """Paths under /tmp are allowed."""
        _validate_path("/tmp/export.json")  # Should not raise

    def test_blocked_etc_path(self):
        """Paths under /etc are rejected."""
        with pytest.raises(ValueError, match="outside allowed directories"):
            _validate_path("/etc/cron.d/malicious")

    def test_blocked_root_path(self):
        """Direct root paths are rejected."""
        with pytest.raises(ValueError, match="outside allowed directories"):
            _validate_path("/root/export.json")

    def test_path_traversal_with_dotdot(self):
        """Path traversal via ../ is caught after resolve."""
        with pytest.raises(ValueError, match="outside allowed directories"):
            _validate_path("/tmp/../../../etc/passwd")

    def test_must_exist_raises_for_missing(self):
        """must_exist=True raises FileNotFoundError for missing files."""
        with pytest.raises(FileNotFoundError, match="File not found"):
            _validate_path("/tmp/this_file_definitely_does_not_exist_12345.json", must_exist=True)

    def test_must_exist_ok_for_existing(self, tmp_path):
        """must_exist=True passes for existing files."""
        f = tmp_path / "exists.json"
        f.write_text("{}")
        _validate_path(str(f), must_exist=True)  # Should not raise


# ---------------------------------------------------------------------------
# _backup_file
# ---------------------------------------------------------------------------

class TestBackupFile:
    """Tests for _backup_file."""

    def test_creates_backup(self, tmp_path):
        """Backup file is created with .bak suffix."""
        original = tmp_path / "state.json"
        original.write_text('{"test": true}')
        result = _backup_file(str(original))
        assert result is not None
        assert result.endswith(".bak")
        assert os.path.exists(result)

    def test_no_backup_for_missing_file(self, tmp_path):
        """Returns None when file doesn't exist."""
        result = _backup_file(str(tmp_path / "nonexistent.json"))
        assert result is None


# ---------------------------------------------------------------------------
# _merge_incidents
# ---------------------------------------------------------------------------

class TestMergeIncidents:
    """Tests for _merge_incidents."""

    def test_deduplication_keeps_newer(self):
        """When same incident_id exists, keep the one with newer updated_at."""
        existing = [{"incident_id": "inc-1", "updated_at": "2026-01-01T00:00:00Z", "status": "new"}]
        imported = [{"incident_id": "inc-1", "updated_at": "2026-01-05T00:00:00Z", "status": "investigating"}]
        result = _merge_incidents(existing, imported)
        assert len(result) == 1
        assert result[0]["status"] == "investigating"

    def test_deduplication_keeps_existing_if_newer(self):
        """When existing is newer, it's kept."""
        existing = [{"incident_id": "inc-1", "updated_at": "2026-01-10T00:00:00Z", "status": "resolved"}]
        imported = [{"incident_id": "inc-1", "updated_at": "2026-01-05T00:00:00Z", "status": "new"}]
        result = _merge_incidents(existing, imported)
        assert len(result) == 1
        assert result[0]["status"] == "resolved"

    def test_new_incidents_added(self):
        """New incident IDs are added."""
        existing = [{"incident_id": "inc-1", "updated_at": "2026-01-01T00:00:00Z"}]
        imported = [{"incident_id": "inc-2", "updated_at": "2026-01-02T00:00:00Z"}]
        result = _merge_incidents(existing, imported)
        assert len(result) == 2
        ids = {i["incident_id"] for i in result}
        assert ids == {"inc-1", "inc-2"}


# ---------------------------------------------------------------------------
# _merge_jsonl
# ---------------------------------------------------------------------------

class TestMergeJsonl:
    """Tests for _merge_jsonl."""

    def test_siem_logs_concatenated(self):
        """siem_logs JSONL are concatenated."""
        existing = [{"log_type": "auth"}]
        imported = [{"log_type": "network"}]
        result = _merge_jsonl("siem_logs", existing, imported)
        assert len(result) == 2

    def test_baseline_snapshots_dedup_by_timestamp(self):
        """baseline_snapshots deduplicates by timestamp."""
        existing = [{"timestamp": "2026-01-01", "data": "old"}]
        imported = [{"timestamp": "2026-01-01", "data": "new"}, {"timestamp": "2026-01-02", "data": "unique"}]
        result = _merge_jsonl("baseline_snapshots", existing, imported)
        timestamps = {r["timestamp"] for r in result}
        assert timestamps == {"2026-01-01", "2026-01-02"}
        # The imported one overwrites the existing one for the same timestamp
        for r in result:
            if r["timestamp"] == "2026-01-01":
                assert r["data"] == "new"


# ---------------------------------------------------------------------------
# _merge_section — system_state and incidents
# ---------------------------------------------------------------------------

class TestMergeSectionSystemState:
    """Tests for _merge_section system_state logic."""

    def test_detection_phase_wins(self):
        """If either is in detection, merged gets detection."""
        existing = {"phase": "baseline", "first_ingestion_at": "2026-01-01T00:00:00Z"}
        imported = {"phase": "detection", "first_ingestion_at": "2026-01-05T00:00:00Z"}
        result = _merge_section("system_state", existing, imported)
        assert result["phase"] == "detection"

    def test_keeps_earlier_first_ingestion(self):
        """Merged keeps the earlier first_ingestion_at."""
        existing = {"phase": "detection", "first_ingestion_at": "2026-01-01T00:00:00Z"}
        imported = {"phase": "detection", "first_ingestion_at": "2026-01-10T00:00:00Z"}
        result = _merge_section("system_state", existing, imported)
        assert result["first_ingestion_at"] == "2026-01-01T00:00:00Z"

    def test_incidents_section_uses_merge_incidents(self):
        """Incidents section deduplicates by incident_id."""
        existing = [{"incident_id": "a", "updated_at": "2026-01-01"}]
        imported = [{"incident_id": "b", "updated_at": "2026-01-02"}]
        result = _merge_section("incidents", existing, imported)
        assert len(result) == 2
