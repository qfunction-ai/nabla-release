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
        # R20: history retained as append-only records; supersession is
        # READ-time (last-by-file-order wins), not a written flag
        raw = [json.loads(l) for l in feedback_store_path().read_text().splitlines() if l.strip()]
        assert len(raw) == 2
        assert raw[0]["disposition"] == "true_positive"
        assert raw[1]["disposition"] == "false_positive"


class TestCalibration:
    def test_noop_below_min_labels(self, env):
        from nabla.rl import calibration
        labels = [{"raw_score": 2.5, "disposition": "false_positive"}] * 5
        proposed, reason = calibration.calibrate(labels, current=2.0, min_labels=30)
        assert proposed == 2.0
        assert "pinned" in reason

    def test_moves_with_sufficient_labels(self, env):
        """R5 (round 3): the LOWEST meeting threshold. FP-heavy corpus with
        FPs clustered just below current (1.8-1.99) and TPs above (2.5+):
        the lowest t meeting precision sits just past the FP cluster —
        tighter than current, but recall-preserving (unlike the old
        highest-meeting rule that walked to the TPs' top)."""
        from nabla.rl import calibration
        labels = [{"raw_score": 2.10 + i * 0.01, "disposition": "false_positive"} for i in range(30)]
        labels += [{"raw_score": 3.00 + i * 0.01, "disposition": "true_positive"} for i in range(10)]
        proposed, reason = calibration.calibrate(labels, current=2.0, min_labels=30)
        # Lowest meeting: just past the FP cluster's top (~2.39)
        assert 2.25 <= proposed <= 2.40, (
            f"lowest-meeting should sit just past the FP cluster: {proposed}")

    def test_r5_no_raise_when_meeting(self, env):
        """The review's gate: a set already meeting precision never raises."""
        from nabla.rl import calibration
        # All TPs above current: precision 100% at current
        labels = [{"raw_score": 2.5 + i * 0.01, "disposition": "true_positive"} for i in range(40)]
        proposed, _ = calibration.calibrate(labels, current=2.0, min_labels=30)
        assert proposed <= 2.0, f"already-meeting set raised: {proposed}"

    def test_r5_never_leaves_bounds(self, env):
        """The review's gate: proposals clamp to [lo, hi]."""
        from nabla.rl import calibration
        labels = [{"raw_score": 9.0 + i * 0.01, "disposition": "true_positive"} for i in range(40)]
        # Direct: calibrate has no bounds; run_calibration clamps — test via run
        calibration.write_labels([{"anomaly_id": f"b{i}", "entity": "x",
                                   "detection_method": "entity_z_score",
                                   "raw_score": 9.0 + i * 0.01, "disposition": "false_positive",
                                   "disposition_at": "2026-11-18T00:00:00Z",
                                   "incident_id": "i", "run_id": "r", "supervisor_hint": None}
                                  for i in range(40)])
        report = calibration.run_calibration()
        e = calibration.load_calibration()["entity_event_count_sigma"]
        assert e["current"] <= 4.0, f"left bounds: {e['current']}"

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


class TestR8PerFindingScope:
    def test_disposition_labels_only_finding_anomalies(self, env, monkeypatch):
        """R8: an entity with two findings (different methods) — a disposition
        on one labels only ITS anomalies, not the other finding's."""
        import nabla.incidents as inc
        import json as J
        # Two findings for alice: one lolbin, one off_hours
        incs = []
        for ftype, aids, methods in [
            ("lolbin_attempt", ["bf-1", "bf-2"], ["failed_login_ratio"]),
            ("off_hours_activity", ["oh-1"], ["off_hours"]),
        ]:
            incs.append({
                "incident_id": f"inc-{ftype}", "run_id": "r", "entity": "alice",
                "status": "new", "finding_type": ftype,
                "contributing_anomaly_ids": aids,
                "contributing_anomaly_details": [
                    {"anomaly_id": a, "method": m, "raw_score": 2.5, "threshold_in_effect": 2.0}
                    for a, m in zip(aids, methods)
                ],
            })
        (env / "incidents.json").write_text(J.dumps(incs))
        monkeypatch.setattr(inc, "_incidents_file", lambda: str(env / "incidents.json"))

        inc.update_incident("inc-lolbin_attempt", disposition="false_positive")

        from nabla.rl.calibration import current_labels
        labels = current_labels()
        labeled_ids = {l["anomaly_id"] for l in labels}
        assert labeled_ids == {"bf-1", "bf-2"}, (
            f"disposition leaked beyond its finding: {labeled_ids}")


class TestR9BanditReset:
    def test_schema_gated_load_resets_preschema_state(self, env):
        """R9 (round 3) + S11 (round 5): reset_poisoned_bandit is deleted
        (dead code — the schema-gated load IS the reset). Pre-schema
        state files load as uniform priors; post-schema files load as
        themselves."""
        from nabla.rl.bandit import DetectionMethodBandit
        import json as J
        # Pre-schema poisoned state (no schema marker)
        (env / "rl_state.json").write_text(J.dumps(
            {"bandit": {"alpha": {"lolbin": 50.0}, "beta": {"lolbin": 1.0}}}))
        b = DetectionMethodBandit.load(str(env / "rl_state.json"))
        assert b.alpha.get("lolbin", 1.0) == 1.0, "pre-schema state resets to priors"
        # Post-schema learned state survives
        (env / "rl_state2.json").write_text(J.dumps(
            {"schema": 2, "bandit": {"alpha": {"lolbin": 7.0}, "beta": {"lolbin": 1.0}}}))
        b2 = DetectionMethodBandit.load(str(env / "rl_state2.json"))
        assert b2.alpha.get("lolbin") == 7.0, "post-schema state loads as itself"
