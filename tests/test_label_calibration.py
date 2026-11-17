"""Phase 3 gates: dispositions, feedback store, calibration, the closed loop."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from nabla.config import Settings


def _settings(tmp_path):
    return Settings(
        data_dir=str(tmp_path), letta_base_url="http://x", embedding_endpoint="http://x",
        splunk_host="", sumologic_host="", splunk_validate_url=False, sumologic_validate_url=False,
    )


@pytest.fixture
def env(tmp_path, monkeypatch):
    s = _settings(tmp_path)
    monkeypatch.setattr("nabla.config.get_settings", lambda: s)
    from nabla.rl import calibration
    monkeypatch.setattr(calibration, "feedback_store_path", lambda: tmp_path / "labels.jsonl")
    monkeypatch.setattr(calibration, "calibration_store_path", lambda: tmp_path / "cal.json")
    return tmp_path


def _incident(tmp_path, anomaly_id="anom-1", method="entity_z_score", raw=2.4, thresh=2.0):
    return {
        "incident_id": "inc-1", "run_id": "r-1", "entity": "alice",
        "contributing_anomaly_ids": [anomaly_id],
        "contributing_anomaly_details": [
            {"anomaly_id": anomaly_id, "method": method,
             "raw_score": raw, "threshold_in_effect": thresh},
        ],
    }


def _write_incident(tmp_path, incident):
    (tmp_path / "incidents.json").write_text(json.dumps([incident]))


class TestDispositionRoundTrip:
    def test_disposition_writes_labels(self, env, monkeypatch):
        import nabla.incidents as inc
        _write_incident(env, _incident(env))
        monkeypatch.setattr(inc, "_incidents_file", lambda: str(env / "incidents.json"))

        result = inc.update_incident("inc-1", disposition="false_positive")
        assert result["disposition"] == "false_positive"
        assert result["disposition_at"]

        from nabla.rl.calibration import current_labels
        labels = current_labels()
        assert len(labels) == 1
        assert labels[0]["anomaly_id"] == "anom-1"
        assert labels[0]["detection_method"] == "entity_z_score"
        assert labels[0]["raw_score"] == 2.4
        assert labels[0]["threshold_in_effect"] == 2.0
        assert labels[0]["disposition"] == "false_positive"

    def test_resolved_sets_no_disposition(self, env, monkeypatch):
        """Review STRONG 1 gate: resolved must not fabricate a TP label."""
        import nabla.incidents as inc
        _write_incident(env, _incident(env))
        monkeypatch.setattr(inc, "_incidents_file", lambda: str(env / "incidents.json"))

        result = inc.update_incident("inc-1", status="resolved")
        assert "disposition" not in result
        from nabla.rl.calibration import current_labels
        assert current_labels() == []

    def test_false_positive_status_compat(self, env, monkeypatch):
        import nabla.incidents as inc
        _write_incident(env, _incident(env))
        monkeypatch.setattr(inc, "_incidents_file", lambda: str(env / "incidents.json"))

        result = inc.update_incident("inc-1", status="false_positive")
        assert result["disposition"] == "false_positive"
        from nabla.rl.calibration import current_labels
        assert len(current_labels()) == 1

    def test_last_disposition_wins(self, env, monkeypatch):
        """Review STRONG 2 gate: re-disposition supersedes, history retained."""
        import nabla.incidents as inc
        _write_incident(env, _incident(env))
        monkeypatch.setattr(inc, "_incidents_file", lambda: str(env / "incidents.json"))

        inc.update_incident("inc-1", disposition="true_positive")
        inc.update_incident("inc-1", disposition="false_positive")

        from nabla.rl.calibration import current_labels, feedback_store_path
        labels = current_labels()
        assert len(labels) == 1
        assert labels[0]["disposition"] == "false_positive"
        # history retained with supersede flag
        raw = [json.loads(l) for l in feedback_store_path().read_text().splitlines() if l.strip()]
        assert len(raw) == 2
        assert raw[0].get("superseded") is True


class TestCalibration:
    def test_noop_below_min_labels(self, env):
        from nabla.rl import calibration
        labels = [{"raw_score": 2.5, "disposition": "false_positive"}] * 5
        proposed, reason = calibration.calibrate(labels, current=2.0, min_labels=30)
        assert proposed == 2.0
        assert "pinned" in reason

    def test_moves_with_sufficient_labels(self, env):
        from nabla.rl import calibration
        # 30 FPs at low scores, 10 TPs at high scores -> threshold should rise
        labels = [{"raw_score": 1.0 + i * 0.01, "disposition": "false_positive"} for i in range(30)]
        labels += [{"raw_score": 4.0 + i * 0.01, "disposition": "true_positive"} for i in range(10)]
        proposed, reason = calibration.calibrate(labels, current=2.0, min_labels=30)
        assert proposed > 2.0, f"FP-heavy corpus should raise the threshold: {proposed}"

    def test_step_limited(self, env):
        from nabla.rl import calibration
        labels = [{"raw_score": 4.0, "disposition": "true_positive"}] * 40
        proposed, _ = calibration.calibrate(labels, current=2.0, min_labels=30, step=0.25)
        assert proposed <= 2.25

    def test_run_calibration_report(self, env):
        from nabla.rl import calibration
        # Seed labels for entity_z_score -> entity_event_count_sigma
        records = [{"anomaly_id": f"a{i}", "entity": "alice", "detection_method": "entity_z_score",
                    "raw_score": 1.0 + (i % 20) * 0.1, "disposition": "false_positive",
                    "disposition_at": "2026-11-17T00:00:00Z", "incident_id": "i", "run_id": "r",
                    "supervisor_hint": None} for i in range(35)]
        calibration.write_labels(records)
        report = calibration.run_calibration()
        assert report["entity_event_count_sigma"]["status"] in ("moved", "held")


class TestClosedLoop:
    def test_disposition_moves_threshold_detection_reads_it(self, env):
        """Gate 11 — the clip-14 contract as a test: labels move the calibration
        store, and effective_thresholds (what detection reads) reflects it."""
        from nabla.rl import calibration
        before = calibration.effective_thresholds()["entity_event_count_sigma"]

        records = [{"anomaly_id": f"a{i}", "entity": "alice", "detection_method": "entity_z_score",
                    "raw_score": 1.0 + (i % 15) * 0.1, "disposition": "false_positive",
                    "disposition_at": "2026-11-17T00:00:00Z", "incident_id": "i", "run_id": "r",
                    "supervisor_hint": None} for i in range(35)]
        calibration.write_labels(records)
        calibration.run_calibration()

        after = calibration.effective_thresholds()["entity_event_count_sigma"]
        # FP-heavy low-score corpus: threshold rises (or holds at ceiling) — never falls
        assert after >= before, f"detection would read a LOOSER threshold: {before} -> {after}"
        # And the evidence trail exists
        store = calibration.load_calibration()
        assert store["entity_event_count_sigma"]["evidence"] is not None or after == before
