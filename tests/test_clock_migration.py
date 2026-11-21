"""CLOCK-SPEC migration tests (C11 + S-4 + V-3)."""

import json
import os
import tempfile
from pathlib import Path


def _fresh():
    d = Path(tempfile.mkdtemp())
    os.environ["NABLA_DATA_DIR"] = str(d)
    import nabla.config as cfg
    cfg._settings = None
    return d


class TestClockMigration:
    def test_poisoned_clock_repaired(self):
        from nabla.pipeline.clock_migration import run_clock_migration
        d = _fresh()
        (d / "entity_risk_scores.json").write_text(json.dumps(
            {"entities": {"mallory": {"data_clock": "2099-01-01T00:00:00+00:00",
                                      "overall": 5.0}}}))
        s = run_clock_migration(str(d))
        assert s["clocks_repaired"] == 1
        raw = json.loads((d / "entity_risk_scores.json").read_text())
        assert raw["entities"]["mallory"]["data_clock"].startswith("20") and \
            "2099" not in raw["entities"]["mallory"]["data_clock"]

    def test_healthy_clock_untouched(self):
        from nabla.pipeline.clock_migration import run_clock_migration
        d = _fresh()
        good = "2026-08-15T03:00:00+00:00"
        (d / "entity_risk_scores.json").write_text(json.dumps(
            {"entities": {"alice": {"data_clock": good, "overall": 5.0}}}))
        s = run_clock_migration(str(d))
        assert s["clocks_repaired"] == 0
        raw = json.loads((d / "entity_risk_scores.json").read_text())
        assert raw["entities"]["alice"]["data_clock"] == good

    def test_retained_anomaly_dedup(self):
        from nabla.pipeline.clock_migration import run_clock_migration
        d = _fresh()
        dup = {"method": "lolbin", "timestamp": "2026-08-15T03:00:00Z"}
        (d / "entity_profiles.json").write_text(json.dumps(
            {"users": {"alice": {"contributing_anomalies": [dup, dict(dup)],
                                 "closed_hours": ["2026-08-15T03"]}}}))
        s = run_clock_migration(str(d))
        assert s["anomalies_deduped"] == 1
        assert s["registries_reset"] == 1
        raw = json.loads((d / "entity_profiles.json").read_text())
        assert len(raw["users"]["alice"]["contributing_anomalies"]) == 1
        assert "closed_hours" not in raw["users"]["alice"]

    def test_v3_initialization(self):
        from nabla.pipeline.clock_migration import run_clock_migration
        d = _fresh()
        (d / "system_state.json").write_text(json.dumps(
            {"data_newest_ts": "2026-08-15T23:00:00+00:00"}))
        s = run_clock_migration(str(d))
        # round 7: the REAL SIEM kinds seed from the data clock — the
        # v1 "siem" key was a bug (no source is named that)
        assert s["watermarks_initialized"] == 4
        state = json.loads((d / "system_state.json").read_text())
        wm = state["source_watermarks"]
        assert wm["splunk"] == "2026-08-15T23:00:00+00:00"
        assert wm["sumologic"] == "2026-08-15T23:00:00+00:00"
        assert "siem" not in wm
        assert wm["synthetic"] == "" and wm["file"] == ""
        assert state.get("clock_spec_migrated")
        assert state.get("clock_spec_migrated_v2")

    def test_open_hour_carried_into_map(self):
        from nabla.pipeline.clock_migration import run_clock_migration
        d = _fresh()
        (d / "entity_profiles.json").write_text(json.dumps(
            {"users": {"alice": {"open_hour": "2026-08-15T03",
                                 "open_count": 7}}}))
        run_clock_migration(str(d))
        raw = json.loads((d / "entity_profiles.json").read_text())
        # round 7: the accumulator re-homes under the reserved __legacy__
        # source (engine shape: {source|hour: {count, ids, reopen_wm}})
        assert raw["users"]["alice"]["open_hours"] == {
            "__legacy__|2026-08-15T03": {"count": 7, "ids": [],
                                         "reopen_wm": ""}}
        assert "open_hour" not in raw["users"]["alice"]

    def test_idempotent(self):
        from nabla.pipeline.clock_migration import run_clock_migration
        d = _fresh()
        (d / "entity_risk_scores.json").write_text(json.dumps(
            {"entities": {"m": {"data_clock": "2099-01-01T00:00:00+00:00"}}}))
        s1 = run_clock_migration(str(d))
        s2 = run_clock_migration(str(d))
        assert not s2.get("skipped") is False and s2.get("skipped") or s2["clocks_repaired"] == 0
